"""Java decompilation via CFR (single-JAR decompiler, BSD-licensed).

The decompiler jar is downloaded to the cache dir on first use (or taken from
``cfr_jar`` in the config). Whole classes are decompiled once and cached;
per-method output is extracted from the class source by matching the method
name against the descriptor's parameter types.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from .config import BridgeConfig
from .index import Index
from .jvm import java_type_key, split_params, parse_descriptor

CFR_TIMEOUT_S = 300


class DecompileError(RuntimeError):
    pass


def ensure_decompiler(cfg: BridgeConfig) -> Path:
    """Return the path to the decompiler jar, downloading it if necessary."""
    if cfg.cfr_jar:
        p = Path(cfg.cfr_jar).expanduser()
        if p.is_file():
            return p
        raise DecompileError(f"configured decompiler jar missing: {p}")
    cache = cfg.cache_path / "decompiler"
    cache.mkdir(parents=True, exist_ok=True)
    jar = cache / "cfr-0.152.jar"
    if jar.is_file() and jar.stat().st_size > 100_000:
        return jar
    tmp = cache / "cfr-0.152.jar.part"
    try:
        with urllib.request.urlopen(cfg.cfr_url, timeout=120) as resp:
            tmp.write_bytes(resp.read())
        tmp.rename(jar)
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        raise DecompileError(
            f"could not download CFR from {cfg.cfr_url}: {exc}. "
            "Set cfr_jar in java-bridge.yaml to a local copy."
        ) from exc
    return jar


def class_file_for(cfg: BridgeConfig, class_name: str) -> tuple[str, bool]:
    """Return (path-or-jar, is_jar) for a class; extracts jar members to cache."""
    t = Path(cfg.target).expanduser()
    if t.is_file() and t.suffix == ".jar":
        extracted = cfg.cache_path / "extracted" / (class_name.replace("$", "__") + ".class")
        if not extracted.is_file():
            extracted.parent.mkdir(parents=True, exist_ok=True)
            entry = class_name.replace(".", "/") + ".class"
            with zipfile.ZipFile(t) as zf:
                if entry not in zf.namelist():
                    raise DecompileError(f"{class_name} not found in {t.name}")
                extracted.write_bytes(zf.read(entry))
        return str(extracted), False
    if t.is_file() and t.suffix == ".class":
        return str(t), False
    if t.is_dir():
        return str(t / (class_name.replace(".", "/") + ".class")), False
    raise DecompileError(f"unsupported target for decompile: {cfg.target}")


def decompile_class(cfg: BridgeConfig, idx: Index, class_name: str) -> str:
    """Decompile one class with CFR (cached in the index cache dir)."""
    cache = cfg.cache_path / "decompiled" / idx.fingerprint[:32]
    cache.mkdir(parents=True, exist_ok=True)
    out_file = cache / (class_name.replace("$", "__") + ".java")
    if out_file.is_file():
        return out_file.read_text(encoding="utf-8")

    class_file, _is_jar = class_file_for(cfg, class_name)
    if not Path(class_file).is_file():
        raise DecompileError(f"class file not found: {class_file}")
    jar = ensure_decompiler(cfg)
    tmpdir = tempfile.mkdtemp(prefix="java-bridge-cfr-")
    try:
        cmd = [
            cfg.java, "-jar", str(jar), class_file,
            "--outputdir", tmpdir,
            "--silent", "true",
            "--comments", "false",
        ]
        cp = cfg.classpath_arg()
        if cp:
            cmd += ["--extraclasspath", cp]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=CFR_TIMEOUT_S, check=False)
        produced = list(Path(tmpdir).rglob(f"{class_name.rsplit('.', 1)[-1]}.java"))
        if not produced:
            raise DecompileError(
                f"CFR produced no output for {class_name}: "
                f"{(proc.stderr or proc.stdout).strip()[:500]}"
            )
        src = produced[0].read_text(encoding="utf-8", errors="replace")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    out_file.write_text(src, encoding="utf-8")
    return src


def _param_type_from_source(param: str) -> str:
    """Extract the type from a Java parameter declaration like ``int a`` or
    ``List<String> x`` (array brackets are preserved)."""
    p = param.strip()
    p = re.sub(r"^(?:@\w+(?:\([^)]*\))?\s+)+", "", p)  # drop annotations
    m = re.match(r"^(.*?)([A-Za-z_$][\w$]*)\s*$", p)
    if m and m.group(2):
        return m.group(1).strip()
    return p


def method_at(class_source: str, class_name: str, name: str, descriptor: str) -> tuple[int, int, str] | None:
    """Locate a method in decompiled class source.

    Returns (start, end, source) where the slice is the full method
    (modifiers through closing brace). ``name`` may be ``<init>``.
    """
    try:
        expected_params, _ret = parse_descriptor(descriptor)
    except ValueError:
        expected_params = None
    simple = class_name.rsplit(".", 1)[-1]
    target_name = simple if name == "<init>" else name

    header_re = re.compile(
        r"(?m)^[ \t]*"
        r"(?P<mods>(?:(?:public|protected|private|static|final|synchronized|abstract|default|native|strictfp)[ \t]+)*)"
        r"(?P<anns>(?:@[^\n]*\n[ \t]*)*)"
        r"(?P<type>(?:[\w$]+(?:\s*<[^;{]*>)?(?:\s*\[\s*\])*\s+)?)"
        + r"(?<!\.)"
        + re.escape(target_name)
        + r"[ \t]*\((?P<params>[^)]*)\)[ \t]*(?:throws [^{;]+)?[;{]"
    )
    best: tuple[int, int, str] | None = None
    for m in header_re.finditer(class_source):
        params_src = split_params(m.group("params"))
        if expected_params is not None and len(params_src) != len(expected_params):
            continue
        if expected_params is not None:
            got = [java_type_key(_param_type_from_source(p)) for p in params_src]
            want = [java_type_key(p) for p in expected_params]
            if got != want:
                continue
        # Ensure this is a declaration: the regex consumed the final '{' or
        # ';'; it must be the last character of the match.
        last = class_source[m.end() - 1]
        if last not in ("{", ";"):
            continue
        # Walk back over annotation lines already consumed by the regex, and
        # forward to the matching brace.
        start = m.start()
        if last == "{":
            depth = 0
            i = m.end() - 1
            while i < len(class_source):
                ch = class_source[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return (start, i + 1, class_source[start : i + 1])
                i += 1
            return None
        end = m.end()
        if best is None:
            best = (start, end, class_source[start:end])
    return best


def extract_method(cfg: BridgeConfig, idx: Index, method) -> str:
    """Return the decompiled source of one method (raises DecompileError)."""
    src = decompile_class(cfg, idx, method.class_name)
    found = method_at(src, method.class_name, method.name, method.descriptor)
    if found is None:
        raise DecompileError(
            f"CFR output for {method.class_name} does not contain {method.name}{method.descriptor}"
        )
    return found[2].rstrip() + "\n"
