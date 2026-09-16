"""``java-bridge validate``: the javac build gate for reagent candidates.

Strategy (primary): decompile the ORIGINAL class with CFR, replace the target
method with the candidate body, and compile the result against the original
classpath. Success means the candidate type-checks against the real
signatures of every referenced class.

Strategy (fallback): a stub class generated from javap metadata (all fields,
other methods stubbed) with the candidate spliced in — used when the CFR
output does not compile for reasons unrelated to the candidate.

Also verifies the method descriptor (signature) is preserved in the compiled
output.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from .config import BridgeConfig
from .decompile import DecompileError, _param_type_from_source, decompile_class, method_at
from .index import Index
from .jvm import parse_descriptor
from .javap import run_javap

CANDIDATE_METHOD_RE = re.compile(
    r"^[ \t]*"
    r"((?:(?:public|protected|private|static|final|synchronized|abstract|default|native|strictfp)[ \t]+)*)"
    r"((?:@[^\n]*\n[ \t]*)*)"
    r"((?:[\w$]+(?:\s*<[^;{]*>)?(?:\s*\[\s*\])*\s+)?)"
    r"([\w$]+)[ \t]*\(([^)]*)\)[ \t]*(?:throws [^{;]+)?\{",
    re.M,
)


def _match_brace(text: str, open_idx: int) -> int | None:
    """Index of the brace matching text[open_idx] (string/char/comment aware)."""
    depth = 0
    i = open_idx
    n = len(text)
    in_str = in_chr = in_line = in_block = False
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            if ch == "\n":
                in_line = False
        elif in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                i += 1
        elif in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        elif in_chr:
            if ch == "\\":
                i += 1
            elif ch == "'":
                in_chr = False
        else:
            if ch == "/" and nxt == "/":
                in_line = True
                i += 1
            elif ch == "/" and nxt == "*":
                in_block = True
                i += 1
            elif ch == '"':
                in_str = True
            elif ch == "'":
                in_chr = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return None


def extract_candidate_method(text: str, method_name: str | None = None) -> tuple[int, int, str] | None:
    """Extract one method from candidate text. Returns (start, end, source)."""
    starts = []
    for m in CANDIDATE_METHOD_RE.finditer(text):
        name = m.group(4)
        if method_name and name != method_name:
            continue
        starts.append((m.start(), m.end()))
    if not starts:
        return None
    start, hdr_end = starts[0]
    # Walk back over annotation lines.
    line_start = text.rfind("\n", 0, start) + 1
    s = line_start
    while s > 0:
        prev = text.rfind("\n", 0, s - 1) + 1
        prev_line = text[prev:s].strip()
        if prev_line.startswith("@"):
            s = prev
        else:
            break
    close = _match_brace(text, hdr_end - 1)
    if close is None:
        return None
    return (s, close + 1, text[s : close + 1].rstrip() + "\n")


def _signature_params(candidate_src: str) -> list[str]:
    m = CANDIDATE_METHOD_RE.match(candidate_src.lstrip("\n"))
    if not m:
        return []
    return split_params(m.group(5))


def _infer_target(idx: Index, candidate_file: Path, candidate_src: str,
                  explicit: str | None) -> tuple[object, str]:
    """Resolve the index method the candidate is for. Returns (method, name)."""
    from .decompile import _param_type_from_source

    if explicit:
        m = idx.resolve(explicit)
        return m, m.name
    sig = CANDIDATE_METHOD_RE.search(candidate_src)
    cand_name = sig.group(4) if sig else None
    if cand_name is None:
        raise ValueError("cannot find a method declaration in the candidate file")
    stem = candidate_file.stem
    # reagent names isolated candidates {safe_class}_{safe_func}(.cpp/.java);
    # the class part of the stem identifies the target class exactly.
    matches = []
    for m in idx.methods:
        if m.name != cand_name:
            continue
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", m.class_name)
        if stem == f"{safe}_{cand_name}":
            matches.append(m)
    if not matches:
        matches = [m for m in idx.methods if m.name == cand_name]
    if not matches:
        raise ValueError(f"no method named {cand_name!r} in the target")
    if len(matches) > 1:
        from .jvm import java_type_key, split_params

        got = []
        if sig:
            got = [java_type_key(_param_type_from_source(p)) for p in
                   split_params(sig.group(5))]
        narrowed = []
        for m in matches:
            want = [java_type_key(p) for p in parse_descriptor(m.descriptor)[0]]
            if got == want:
                narrowed.append(m)
        if len(narrowed) == 1:
            return narrowed[0], cand_name
        descs = ", ".join(sorted(m.class_name + m.descriptor for m in matches))
        raise ValueError(f"ambiguous candidate target ({descs}); pass --method")
    return matches[0], cand_name


def _stub_source(idx: Index, cls_name: str, skip_method: str, candidate_src: str) -> str:
    cls = idx.classes[cls_name]
    if cls.is_enum:
        raise RuntimeError("stub-class fallback is not supported for enums")
    header = ""
    for ln in cls.raw.splitlines():
        if "class" in ln or "interface" in ln or "enum" in ln:
            header = ln.strip()
            break
    header = header.rstrip(" {").rstrip("{").strip()
    impl = re.search(r"\bimplements\b(.+)$", header)
    lines = []
    pkg = cls_name.rsplit(".", 1)[0] if "." in cls_name else ""
    if pkg:
        lines.append(f"package {pkg};")
        lines.append("")
    kind = cls.kind if cls.kind in ("class", "interface", "record") else "class"
    decl = f"{kind} {cls_name.rsplit('.', 1)[-1]}"
    if cls.extends and cls.kind != "interface":
        decl += f" extends {cls.extends}"
    if impl:
        decl += f" implements {impl.group(1).strip()}"
    lines.append(decl + " {")
    for f in cls.fields:
        if cls.is_enum and f.type == cls_name:
            continue  # enum constants need bodies
        # generics in the signature attribute keep descriptor-style '$' for
        # inner classes; Java source needs the dot form. `final` is dropped:
        # the stub has no initializers (the real class assigns in <clinit>).
        fmods = " ".join(m for m in f.modifiers.split() if m != "final")
        lines.append(f"  {fmods} {f.type.replace('$', '.')} {f.name};")
    # The stub shadows the real class file, so nested classes it references
    # must be declared. Empty placeholders are enough for signature
    # type-checking (stub bodies never run).
    for other_name in sorted(idx.classes):
        if other_name.startswith(cls_name + "$"):
            other = idx.classes[other_name]
            simple = other_name.rsplit("$", 1)[-1]
            if simple.isdigit():
                continue  # anonymous class; not a usable type name
            if other.kind == "interface":
                lines.append(f"  static interface {simple} {{}}")
            elif other.is_enum:
                lines.append(f"  static enum {simple} {{ PLACEHOLDER }}")
            else:
                lines.append(f"  static class {simple} {{}}")
    for m in cls.methods:
        if m.name == "<clinit>":
            continue
        if m.name == skip_method:
            lines.append("  " + candidate_src.strip() + "")
            continue
        try:
            params, ret = parse_descriptor(m.descriptor)
        except ValueError:
            params, ret = [], "void"
        # Descriptor internal names use '$' for inner classes; Java source
        # requires the dot form (Climate$Sampler -> Climate.Sampler).
        params = [t.replace("$", ".") for t in params]
        ret = ret.replace("$", ".")
        params_src = ", ".join(f"{t} p{i}" for i, t in enumerate(params))
        name = cls_name.rsplit(".", 1)[-1] if m.name == "<init>" else m.name
        if "abstract" in m.modifiers or (cls.is_interface and "default" not in m.modifiers):
            lines.append(f"  {m.modifiers} {ret} {name}({params_src});")
        elif ret == "void" or m.name == "<init>":
            ret_out = ret if m.name != "<init>" else ""
            lines.append(
                "  "
                + " ".join(p for p in (m.modifiers, ret_out, f"{name}({params_src}) {{ }}") if p)
            )
        else:
            lines.append(
                f"  {m.modifiers} {ret} {name}({params_src}) {{ throw new UnsupportedOperationException(); }}"
            )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _javac(cfg: BridgeConfig, source: str, class_name: str, workdir: Path) -> tuple[bool, str, Path | None]:
    pkg = class_name.rsplit(".", 1)[0]
    src_dir = workdir / "src"
    dst_dir = workdir / "out"
    src_dir.mkdir(parents=True, exist_ok=True)
    dst_dir.mkdir(parents=True, exist_ok=True)
    if pkg:
        (src_dir / pkg).mkdir(parents=True, exist_ok=True)
        src_file = src_dir / pkg / f"{class_name.rsplit('.', 1)[-1]}.java"
    else:
        src_file = src_dir / f"{class_name.rsplit('.', 1)[-1]}.java"
    src_file.write_text(source, encoding="utf-8")
    cp = cfg.classpath_arg()
    cmd = [cfg.javac, "-d", str(dst_dir)]
    if cp:
        cmd += ["-cp", cp]
    cmd.append(str(src_file))
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=cfg.timeout_s, check=False)
    compiled = dst_dir / (class_name.replace(".", "/") + ".class")
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip(), (compiled if compiled.is_file() else None)


def _descriptor_of(compiled: Path, class_name: str, method_name: str, cfg: BridgeConfig) -> str | None:
    """Read the descriptor of the compiled method (javap -s on the output)."""
    try:
        text = run_javap(cfg, class_name=class_name, cp=compiled.parent.as_posix())
    except RuntimeError:
        return None
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.endswith(");") and re.search(rf"\b{re.escape(method_name)}\s*\(", s):
            for j in range(i + 1, min(i + 3, len(lines))):
                if lines[j].strip().startswith("descriptor:"):
                    return lines[j].strip().split(":", 1)[1].strip()
    return None


def validate(cfg: BridgeConfig, idx: Index, candidate_file: Path,
             explicit: str | None = None) -> int:
    text = candidate_file.read_text(encoding="utf-8", errors="replace")
    try:
        m, _name = _infer_target(idx, candidate_file, text, explicit)
    except (KeyError, ValueError) as exc:
        print(f"FAIL: cannot identify target method: {exc}")
        return 1

    extracted = extract_candidate_method(text)
    if extracted is None:
        print(f"FAIL: no complete method (with body) found in {candidate_file}")
        return 1
    candidate_src = extracted[2]

    print(f"target: {m.class_name}::{m.name} {m.descriptor}")
    workdir = Path(tempfile.mkdtemp(prefix="java-bridge-validate-"))

    # Primary: CFR original source with the target method replaced.
    compiled_path: Path | None = None
    detail = ""
    try:
        src = decompile_class(cfg, idx, m.class_name)
        loc = method_at(src, m.class_name, m.name, m.descriptor)
        if loc is None:
            raise DecompileError("target method not found in CFR output")
        replaced = src[: loc[0]] + candidate_src + "\n" + src[loc[1]:]
        ok, output, compiled_path = _javac(cfg, replaced, m.class_name, workdir)
        detail = output
        if not ok:
            primary_output = output
            raise DecompileError("CFR path failed")
    except (DecompileError, RuntimeError) as exc:
        primary_err = str(exc)
        # Fallback: stub class from javap metadata.
        try:
            stub = _stub_source(idx, m.class_name, m.name, candidate_src)
            ok, output, compiled_path = _javac(cfg, stub, m.class_name, workdir)
            detail = output
            if ok:
                print("note: compiled via stub-class fallback "
                      f"(CFR path failed: {primary_err[:200]})")
            else:
                print(f"FAIL: javac rejected the candidate (tried CFR and stub-class strategies):")
                print(output[-3000:])
                return 1
        except Exception as exc2:  # noqa: BLE001
            print(f"FAIL: validation could not run (CFR: {primary_err[:200]}; stub: {exc2})")
            return 1

    # Descriptor preservation check.
    if compiled_path is not None:
        desc = _descriptor_of(compiled_path, m.class_name, m.name, cfg)
        if desc is not None and desc != m.descriptor:
            print(f"FAIL: signature changed: original {m.descriptor}, candidate {desc}")
            return 1
    print(f"PASS: candidate compiles against the original classpath; descriptor {m.descriptor} preserved")
    return 0
