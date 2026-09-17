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

import os
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
    r"((?:[\w$.]+(?:\s*<[^;{]*>)?(?:\s*\[\s*\])*\s+)?)"
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
            elif ch == "\n":
                in_str = False  # resync: a string never spans a newline
        elif in_chr:
            if ch == "\\":
                i += 1
            elif ch == "'":
                in_chr = False
            elif ch == "\n":
                in_chr = False  # resync: same, for char literals
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
    target_cls = None
    for m in idx.methods:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", m.class_name)
        if stem == f"{safe}_{cand_name}" or stem.startswith(f"{safe}_"):
            target_cls = m.class_name
            break
    simple = target_cls.rsplit(".", 1)[-1] if target_cls else None
    inner = simple.rsplit("$", 1)[-1] if simple else None
    # Java constructor syntax declares the class name; the index calls it
    # <init>.
    lookups = [cand_name]
    if simple and cand_name in (simple, inner):
        lookups.append("<init>")
    if target_cls:
        matches = [m for m in idx.methods
                   if m.name in lookups and m.class_name == target_cls]
    else:
        matches = [m for m in idx.methods if m.name in lookups]
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
            return narrowed[0], narrowed[0].name
        descs = ", ".join(sorted(m.class_name + m.descriptor for m in matches))
        raise ValueError(f"ambiguous candidate target ({descs}); pass --method")
    return matches[0], matches[0].name


_SIMPLE_TYPE_RE = re.compile(r"\b([A-Z][A-Za-z0-9_$]*)\b")
_FQN_RE = re.compile(r"\b([A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)+)\b")
_CP_SIMPLE_CACHE: dict[tuple, dict[str, set[str]]] = {}


def _classpath_simple_names(classpath: str) -> dict[str, set[str]]:
    """Map simple class name -> {FQN, ...} over the whole classpath."""
    key = (classpath,)
    if key in _CP_SIMPLE_CACHE:
        return _CP_SIMPLE_CACHE[key]
    out: dict[str, set[str]] = {}

    def add(fqn: str) -> None:
        simple = fqn.rsplit(".", 1)[-1]
        if simple and not simple.startswith("_"):
            out.setdefault(simple, set()).add(fqn)

    for entry in filter(None, classpath.split(os.pathsep)):
        if entry.endswith(".jar"):
            try:
                import zipfile

                with zipfile.ZipFile(entry) as zf:
                    for n in zf.namelist():
                        if n.endswith(".class") and "/" not in n[:1]:
                            add(n[:-6].replace("/", "."))
            except OSError:
                continue
        elif os.path.isdir(entry):
            for dirpath, _dirs, files in os.walk(entry):
                for fn in files:
                    if fn.endswith(".class"):
                        rel = os.path.relpath(os.path.join(dirpath, fn), entry)
                        add(rel[:-6].replace(os.sep, "."))
    _CP_SIMPLE_CACHE[key] = out
    return out


def _simple_of(fqn: str) -> str:
    """Import-relevant simple name: Outer$Inner counts as Inner."""
    return fqn.rsplit(".", 1)[-1].rsplit("$", 1)[-1]


def _stub_imports(idx: Index, cls_name: str, source_text: str,
                  classpath: str,
                  extra_class: str | None = None) -> list[str]:
    """import lines for the simple names the stub references.

    Resolution priority: the target class's own bytecode references
    (its real dependencies), then the mod index, then the full
    classpath. Within a pool, JDK (java.*/javax.*) types beat
    third-party look-alikes (javaslang/IntelliJ libraries on the MC
    classpath shadow java.util names; JDK types are also not on the
    explicit classpath at all, so without this rule they are invisible).
    Names in java.lang or the stub's own package never need imports.
    """
    own_fqns: dict[str, set[str]] = {}
    cls = idx.classes.get(cls_name)
    raw = (cls.raw if cls is not None else "") or ""
    if extra_class is not None:
        ec = idx.classes.get(extra_class)
        if ec is not None:
            raw += "\n" + (ec.raw or "")
    if cls is not None:
        # javap comments use internal (slash) names:
        #   // Method java/util/Arrays.fill:([II)V
        #   // Field dev/streamsreflowing/X.y:I
        #   // class dev/streamsreflowing/core/Climate$Sampler
        for tok in re.findall(
                r"//\s+(?:Method|InterfaceMethod|Field|InvokeDynamic)\s+([\w/$]+)",
                raw) + re.findall(r"//\s+class\s+([\w/$]+)", raw):
            fqn = tok.split(".", 1)[0].split("(", 1)[0].replace("/", ".")
            # same-class references print without the class name
            # ('// Field OFF:L...;') — a bare identifier is a member name,
            # not an FQN. Bare class refs ('// class X') are same-package
            # and need no import either, so skip all bare tokens.
            if "/" not in tok and "." not in tok:
                continue
            own_fqns.setdefault(_simple_of(fqn), set()).add(fqn)
        # dot-form scan on the de-commented raw: inside '//' comments the
        # 'Class.FIELD' suffix of a slash path would match as a fake FQN
        # (BlockTags.LEAVES) and poison the pool.
        for fqn in _FQN_RE.findall(re.sub(r"//.*$", "", raw, flags=re.M)):
            own_fqns.setdefault(_simple_of(fqn), set()).add(fqn)
    mod_fqns: dict[str, set[str]] = {}
    for c in idx.classes:
        simple = c.rsplit(".", 1)[-1]
        mod_fqns.setdefault(simple, set()).add(c)
    cp = _classpath_simple_names(classpath)
    own_pkg = cls_name.rsplit(".", 1)[0] if "." in cls_name else ""
    own_simple = cls_name.rsplit(".", 1)[-1]
    # a class in the stub's own package cannot be imported (Java has no
    # same-package imports); an external jar class with the same simple
    # name (javax.inject.Provider vs the stub's nested Provider) would
    # shadow the stub member. Such names must simply be skipped.
    # simple names the stub itself defines (its nested classes/fields in
    # the same package): an external class with the same simple name
    # (javax.inject.Provider vs the stub's nested Provider) would shadow
    # the stub member and cannot be imported around — skip it.
    stub_simples = {own_simple}
    for fqn_set in mod_fqns.values():
        for c in fqn_set:
            if "." in c and c.rsplit(".", 1)[0] == own_pkg:
                stub_simples.add(_simple_of(c))
    def usable(c: str) -> bool:
        return (not c.startswith("java.lang.") and c != cls_name
                and _simple_of(c) != own_simple
                and _simple_of(c) not in stub_simples
                and "$" not in c)

    def pick(pool: set[str], verified: bool) -> str | None:
        jdk = {c for c in pool if c.startswith(("java.", "javax."))}
        if len(jdk) == 1:
            return next(iter(jdk))
        if len(pool) == 1:
            return next(iter(pool))
        # ambiguous: only trust the bytecode-verified pool; the
        # classpath pool alone may pick a wrong look-alike (bouncycastle
        # Layer for Minecraft's Layer)
        return next(iter(pool)) if verified else None

    # @Override lines name the member, not a type
    source_text = re.sub(r"@\w+[^\n]*", "", source_text)
    imports: dict[str, str] = {}
    for name in _SIMPLE_TYPE_RE.findall(source_text):
        # Single uppercase letters and CONSTANT_STYLE names are this
        # codebase's variable/constant fields, not type names.
        if len(name) == 1 or ("_" in name and name == name.upper()):
            continue
        # qualified only (Outer.Inner occurrences): the simple name is a
        # member of an imported outer type, not a type itself
        if name in imports:
            continue
        total = len(re.findall(r"(?<![\w$])" + re.escape(name) + r"\b", source_text))
        qualified = len(re.findall(r"\." + re.escape(name) + r"\b", source_text))
        if total and total == qualified:
            continue
        # Priority: the class's own dependencies (its bytecode) — the
        # classpath alone is ambiguous (e.g. six `Path` classes).
        own_c = {c for c in own_fqns.get(name, set()) if usable(c)}
        # ALL_CAPS identifiers without underscores (OFF, ON, MAX) are
        # constants; only keep them as types when the class's own
        # bytecode references exactly one type of that name (UUID).
        if (name == name.upper() and len(name) > 1 and "_" not in name
                and len(own_c) != 1):
            continue
        if own_c:
            chosen = pick(own_c, verified=True)
            if chosen:
                imports[name] = chosen
                continue
        cands = {c for c in (mod_fqns.get(name, set()) | cp.get(name, set()))
                 if usable(c)}
        chosen = pick(cands, verified=False)
        if chosen:
            imports[name] = chosen
    return sorted(f"import {fqn};" for fqn in imports.values())


def _bridge_method_descriptors(cls: object) -> set[str]:
    """Descriptors that look like synthetic bridges: same name as another
    method of the class whose parameter types match after replacing class
    types by Object (the javap -p output lacks the ACC_BRIDGE flag)."""
    by_name: dict[str, list[str]] = {}
    for m in cls.methods:
        if m.name in ("<clinit>", "<init>"):
            continue
        try:
            params, _ = parse_descriptor(m.descriptor)
        except ValueError:
            params = []
        by_name.setdefault(m.name, []).append(tuple(
            p.replace("$", ".") for p in params))
    out: set[str] = set()
    for name, groups in by_name.items():
        if len(groups) < 2:
            continue
        for i, a in enumerate(groups):
            for j, b in enumerate(groups):
                if i == j:
                    continue
                if len(a) != len(b):
                    continue
                if all(x == y or (x == "java.lang.Object" and y != "java.lang.Object")
                       for x, y in zip(a, b)):
                    out.add(next(m.descriptor for m in cls.methods
                                 if m.name == name
                                 and tuple(p.replace("$", ".") for p in parse_descriptor(m.descriptor)[0]) == a))
                    break
    # bytecode-based: a synthetic bridge's whole body is
    # (loads + optional checkcasts) + one self-invoke + return.
    load_ops = re.compile(
        r"^(aload|aload_[0-9]|iload|iload_[0-9]|lload|lload_[0-9]|fload|"
        r"fload_[0-9]|dload|dload_[0-9]|getstatic)$")
    for m in cls.methods:
        if m.name in ("<init>", "<clinit>") or not m.lines:
            continue
        lines = m.lines
        if len(lines) > 30:
            continue
        if lines[-1].opcode != "areturn" and not re.match(r"^(i|l|f|d)return$", lines[-1].opcode):
            continue
        invokes = [l for l in lines if l.opcode.startswith("invoke")]
        if len(invokes) != 1:
            continue
        inv = invokes[0]
        if not re.search(rf"\b{re.escape(m.name)}[:(]", inv.comment or ""):
            continue
        ok = True
        for l in lines:
            if l is inv or l is lines[-1]:
                continue
            if l.opcode == "checkcast":
                continue
            if not load_ops.match(l.opcode):
                ok = False
                break
        if ok:
            out.add(m.descriptor)
    return out


def _stub_source(idx: Index, cls_name: str, skip_method: str | tuple[str, str],
                  candidate_src: str, classpath: str,
                  super_args: list[str] | dict[str, list[str]] | None = None,
                  nested_target: str | None = None) -> str:
    """Full stub compilation unit for a candidate.

    nested_target: the target class is a nested class (cls_name is the
    OUTER); its stub is inlined as a real nested class so that private
    access between outer and inner is checked as in the source tree.
    """
    body = _stub_body_lines(idx, cls_name, skip_method, candidate_src,
                            classpath, super_args, nested_target)
    imports = _stub_imports(idx, cls_name, "\n".join(body), classpath,
                            extra_class=nested_target)
    pkg = cls_name.rsplit(".", 1)[0] if "." in cls_name else ""
    lines: list[str] = []
    if pkg:
        lines.append(f"package {pkg};")
        lines.append("")
    lines += imports
    if imports:
        lines.append("")
    lines += body
    return "\n".join(lines) + "\n"


def _stub_body_lines(idx: Index, cls_name: str,
                     skip_method: str | tuple[str, str],
                     candidate_src: str, classpath: str,
                     super_args: list[str] | dict[str, list[str]] | None = None,
                     nested_target: str | None = None) -> list[str]:
    # super_args: when the real (stubbed) constructors must call a
    # superclass ctor that has no no-arg overload, the args to use
    # (None = emit plain '{}' bodies, the common case); a dict maps
    # class_name -> args for per-class control (nested targets)
    if isinstance(super_args, dict):
        my_super_args = super_args.get(cls_name)
    else:
        my_super_args = super_args
    # skip may be (name, descriptor): plain-name skip would replace EVERY
    # overload of the same name (e.g. all <init>s of a class with two
    # constructors), inserting the candidate multiple times.
    if isinstance(skip_method, tuple):
        skip_name, skip_desc = skip_method
    else:
        skip_name, skip_desc = skip_method, None
    cls = idx.classes[cls_name]
    # A record canonical constructor may not contain an explicit
    # super(...) invocation (the Record.<init> call is implicit in
    # source, present in bytecode). The decompiler shows it; strip it.
    if cls.extends in ("java.lang.Record", "Record") and skip_name == "<init>":
        candidate_src = re.sub(
            r"\s*super\([^)]*\)\s*;", "", candidate_src, count=1)
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
    # javap prints records as plain classes extending java.lang.Record
    is_record = cls.extends in ("java.lang.Record", "Record")
    kind = "record" if is_record else (
        cls.kind if cls.kind in ("class", "interface", "record") else "class")
    simple = cls_name.rsplit(".", 1)[-1]
    if "$" in simple:
        inner = simple.rsplit("$", 1)[-1]
        simple = inner if not inner.isdigit() else f"__Anon{inner}"
    decl = f"{kind} {simple}"
    comp_names: list[str] = []
    comp_types: list[str] = []
    if is_record:
        # Components are the canonical constructor's parameters, named
        # after the implicit accessor methods (accessors are the only
        # surviving component names in bytecode). Fields are NOT
        # components (records may have plain static fields too).
        def _nparams(d: str) -> int:
            try:
                return len(parse_descriptor(d)[0])
            except ValueError:
                return -1
        object_methods = {"toString", "hashCode", "equals", "wait",
                          "notify", "notifyAll", "getClass"}
        comp_names = [m.name for m in cls.methods
                      if m.name not in object_methods
                      and m.name != "<init>" and _nparams(m.descriptor) == 0
                      and not any(mod in m.modifiers.split()
                                   for mod in ("static", "abstract"))]
        canonical = [m for m in cls.methods
                     if m.name == "<init>" and _nparams(m.descriptor) == len(comp_names)]
        if len(canonical) == 1 and _nparams(canonical[0].descriptor) > 0:
            comp_types = [p.replace("$", ".")
                          for p in parse_descriptor(canonical[0].descriptor)[0]]
            comps = ", ".join(f"{comp_types[i]} {comp_names[i]}"
                              for i in range(len(comp_names)))
        else:
            comps = ", ".join(f"java.lang.Object {c}" for c in comp_names)
        decl += f"({comps})"
    elif cls.extends and cls.kind != "interface":
        decl += " extends " + cls.extends.replace("$", ".")
    if impl:
        decl += " implements " + impl.group(1).strip().replace("$", ".")
    body: list[str] = []
    body.append(decl + " {")
    accessor_names = set(comp_names) if is_record else set()
    for f in cls.fields:
        if is_record and f.name in accessor_names:
            continue  # components already in the header
        if cls.is_enum and f.type == cls_name:
            continue  # enum constants need bodies
        # generics in the signature attribute keep descriptor-style '$' for
        # inner classes; Java source needs the dot form. `final` is dropped:
        # the stub has no initializers (the real class assigns in <clinit>).
        fmods = " ".join(m for m in f.modifiers.split() if m != "final")
        body.append(f"  {fmods} {f.type.replace('$', '.')} {f.name};")
    # The stub shadows the real class file, so nested classes it references
    # must be declared. Empty placeholders are enough for signature
    # type-checking (stub bodies never run).
    for other_name in sorted(idx.classes):
        if other_name.startswith(cls_name + "$"):
            other = idx.classes[other_name]
            other_simple = other_name.rsplit("$", 1)[-1]
            if other_name == nested_target:
                # inline the target's stub as a real nested class so
                # private access outer<->inner checks as in the source
                # tree; anonymous targets get an __AnonN stand-in name.
                inner_lines = _stub_body_lines(
                    idx, other_name, skip_method, candidate_src, classpath,
                    super_args, nested_target=None)
                body.extend("  " + ln for ln in inner_lines)
                continue
            if other_simple.isdigit() or re.match(r"^\d", other_simple):
                continue  # anonymous class; not a usable type name
            # Full stub: candidates may call nested ctors/methods.
            inner_lines = _stub_body_lines(
                idx, other_name, None, "", classpath, None,
                nested_target=None)
            # A genuine inner class (non-static) ctor takes the enclosing
            # instance as first param; all others are static nested.
            takes_outer = False
            for om in other.methods:
                if om.name != "<init>":
                    continue
                try:
                    op = parse_descriptor(om.descriptor)[0]
                except ValueError:
                    op = []
                if op and op[0].replace("$", ".") == cls_name:
                    takes_outer = True
            if not takes_outer:
                first = inner_lines[0]
                kw = first.lstrip().split(" ", 1)[0]
                if kw in ("class", "interface", "enum", "record"):
                    inner_lines[0] = first.replace(kw, f"static {kw}", 1)
            body.extend("  " + ln for ln in inner_lines)
    # final instance fields must be assigned in every ctor stub
    final_assigns = " ".join(
        f"{f.name} = {_default_for_source_type(f.type.replace('$', '.'))};"
        for f in cls.fields
        if "final" in f.modifiers.split()
        and "static" not in f.modifiers.split()
        and f.name not in accessor_names)
    bridges = _bridge_method_descriptors(cls)
    record_accessors = set()
    if is_record:
        # implicit accessors: a zero-arg, non-static method whose name
        # matches a component is declared by the record header itself
        for c in comp_names:
            for m in cls.methods:
                if m.name != c or "static" in m.modifiers.split():
                    continue
                try:
                    if parse_descriptor(m.descriptor)[0]:
                        continue
                except ValueError:
                    continue
                record_accessors.add(m.descriptor)
    for m in cls.methods:
        if m.name == "<clinit>":
            continue
        is_skip = (m.name == skip_name
                   and (skip_desc is None or m.descriptor == skip_desc))
        if is_skip:
            body.append("  " + candidate_src.strip() + "")
            continue
        if m.descriptor in bridges:
            # synthetic bridge (same name, Object-widened params): the real
            # class carries ACC_BRIDGE, a stub method cannot
            continue
        if m.descriptor in record_accessors:
            continue  # record header declares it implicitly
        try:
            params, ret = parse_descriptor(m.descriptor)
        except ValueError:
            params, ret = [], "void"
        # Descriptor internal names use '$' for inner classes; Java source
        # requires the dot form (Climate$Sampler -> Climate.Sampler).
        params = [t.replace("$", ".") for t in params]
        ret = ret.replace("$", ".")
        if (m.name == "<init>" and is_record
                and len(params) == len(comp_names)):
            params_src = ", ".join(f"{params[i]} {comp_names[i]}"
                                   for i in range(len(params)))
        else:
            params_src = ", ".join(f"{t} p{i}" for i, t in enumerate(params))
        name = simple if m.name == "<init>" else m.name
        # ctors never take visibility modifiers in source
        mods = " ".join(mm for mm in m.modifiers.split()
                        if mm not in ("public", "protected", "private"))
        if m.name == "<init>":
            m.modifiers = mods
        if "abstract" in m.modifiers or (cls.is_interface and "default" not in m.modifiers):
            body.append(f"  {m.modifiers} {ret} {name}({params_src});")
        elif ret == "void" or m.name == "<init>":
            ret_out = ret if m.name != "<init>" else ""
            if m.name == "<init>" and is_record and len(params) == len(comp_names):
                # record components are implicitly final: the canonical
                # ctor must assign every component
                assigns = " ".join(f"this.{comp_names[i]} = {comp_names[i]};"
                                   for i in range(len(comp_names)))
                body.append(f"  {mods} {name}({params_src}) {{ {assigns} }}")
                continue
            if m.name == "<init>":
                ctor_parts = []
                if is_record and len(params) != len(comp_names) and comp_names:
                    # non-canonical record ctor must chain to the
                    # canonical one: own params + defaults for the rest
                    chained = [f"p{i}" for i in range(len(params))]
                    while len(chained) < len(comp_names):
                        chained.append(
                            _default_for_source_type(comp_types[len(chained)])
                            if len(comp_types) > len(chained) else "null")
                    ctor_parts.append("this(" + ", ".join(chained) + ");")
                if my_super_args is not None:
                    ctor_parts.append("super(" + ", ".join(my_super_args) + ");")
                if final_assigns:
                    ctor_parts.append(final_assigns)
                ctor_body = " ".join(ctor_parts)
                body.append(
                    "  "
                    + " ".join(p for p in (m.modifiers, ret_out, f"{name}({params_src}) {{ {ctor_body} }}") if p)
                )
            else:
                body.append(
                    "  "
                    + " ".join(p for p in (m.modifiers, ret_out, f"{name}({params_src}) {{ }}") if p)
                )
        else:
            body.append(
                f"  {m.modifiers} {ret} {name}({params_src}) {{ throw new UnsupportedOperationException(); }}"
            )
    body.append("}")
    return body


_PRIMITIVE_DEFAULTS = {
    "I": "0", "S": "0", "B": "0", "C": "'\\0'", "J": "0L",
    "F": "0.0f", "D": "0.0d", "Z": "false",
}


def _default_for_source_type(t: str) -> str:
    base = t.replace(" ", "").split("<")[0]
    if base.endswith("[]"):
        return "new " + _default_for_source_type(base[:-2]) + "[]"
    if base == "int" or base == "short" or base == "byte":
        return "0"
    if base == "char":
        return "'\\0'"
    if base == "long":
        return "0L"
    if base == "float":
        return "0.0f"
    if base == "double":
        return "0.0d"
    if base == "boolean":
        return "false"
    return "null"


def _parent_ctor_defaults(extends: str, classpath: str) -> list[str] | None:
    """Default-arg list for the superclass's constructor (super(...) call).

    Returns None when the parent has a no-arg ctor (no call needed).
    Uses the parent's first public constructor, javap'd from the classpath.
    """
    if not extends:
        return []
    extends = extends.split("<")[0].strip()  # drop generic type args
    cmd = ["javap", "-p", "-cp", classpath, extends]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            return None
    except (OSError, subprocess.TimeoutExpired):
        return None
    import re as _re
    ctors = []
    for ln in proc.stdout.splitlines():
        if " extends " in ln:
            continue
        if re.search(rf"\b{_re.escape(extends.rsplit('.', 1)[-1])}\s*\(", ln) and ";" not in ln.split("(")[0]:
            pass
        m = _re.search(r"\)\s*\{?\s*$", ln)
        if f".{extends.rsplit('.', 1)[-1]}(" in ln or ln.strip().startswith((extends.rsplit('.', 1)[-1] + "(")):
            ctors.append(ln.strip().rstrip(";"))
    if not ctors:
        return None
    # no-arg parent ctor: nothing to call
    for c in ctors:
        if c.index("(") and c[c.index("(") + 1:c.index(")")] == "":
            return []

    def _ref_count(c: str) -> int:
        p = c[c.index("(") + 1:c.rindex(")")]
        return sum(1 for x in p.split(",")
                   if x.strip() and not any(x.strip().startswith(s)
                                            for s in ("int", "long", "float",
                                                      "double", "boolean",
                                                      "char", "short", "byte")))
    pick = min(ctors, key=_ref_count)
    params_src = pick[pick.index("(") + 1:pick.rindex(")")]
    if not params_src.strip():
        return []
    from .jvm import split_params
    out = []
    for p in split_params(params_src):
        p = p.strip()
        if not p:
            continue
        # javap -p prints bare types (no parameter names)
        out.append(_default_for_source_type(p))
    return out


def _javac(cfg: BridgeConfig, source: str, class_name: str, workdir: Path,
           outer_class: str | None = None) -> tuple[bool, str, Path | None]:
    unit = outer_class or class_name  # compilation unit = outer class
    pkg = unit.rsplit(".", 1)[0]
    src_dir = workdir / "src"
    dst_dir = workdir / "out"
    src_dir.mkdir(parents=True, exist_ok=True)
    dst_dir.mkdir(parents=True, exist_ok=True)
    if pkg:
        (src_dir / pkg).mkdir(parents=True, exist_ok=True)
        src_file = src_dir / pkg / f"{unit.rsplit('.', 1)[-1]}.java"
    else:
        src_file = src_dir / f"{unit.rsplit('.', 1)[-1]}.java"
    src_file.write_text(source, encoding="utf-8")
    cp = cfg.classpath_arg()
    cmd = [cfg.javac, "-d", str(dst_dir)]
    if cp:
        cmd += ["-cp", cp]
    cmd.append(str(src_file))
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=cfg.timeout_s, check=False)
    # nested classes compile to Outer$Inner.class in the outer's package dir
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
            nested = "$" in m.class_name
            outer_name = m.class_name.rsplit("$", 1)[0] if nested else None

            def build_stub(super_args=None):
                if nested:
                    if super_args is not None:
                        super_args = {outer_name: super_args}
                    return _stub_source(idx, outer_name, (m.name, m.descriptor),
                                        candidate_src, cfg.classpath_arg(),
                                        super_args=super_args,
                                        nested_target=m.class_name)
                return _stub_source(idx, m.class_name, (m.name, m.descriptor),
                                    candidate_src, cfg.classpath_arg(),
                                    super_args=super_args)

            def compile(stub):
                if nested:
                    return _javac(cfg, stub, m.class_name, workdir,
                                  outer_class=outer_name)
                return _javac(cfg, stub, m.class_name, workdir)

            ok, output, compiled_path = compile(build_stub())
            detail = output
            if not ok and ("cannot be applied" in output
                           or "cannot find symbol" in output
                           or "no suitable constructor" in output):
                # stubbed ctors may need to call a superclass ctor that
                # has no no-arg overload
                defaults = _parent_ctor_defaults(
                    idx.classes[outer_name if nested else m.class_name].extends,
                    cfg.classpath_arg())
                if defaults is not None:
                    ok, output, compiled_path = compile(
                        build_stub(super_args=defaults))
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
