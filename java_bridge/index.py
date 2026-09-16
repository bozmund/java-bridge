"""Method inventory: enumerate classes/methods of a target, build the xref
graph, strings, and fields. The index is cached as JSON and invalidated by a
content fingerprint of the target.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .addr import method_address, normalize
from .config import BridgeConfig
from .javap import (
    ClassInfo,
    FieldInfo,
    MethodInfo,
    parse_javap,
    parse_reference,
    extract_string,
    run_javap,
)

SYNTHETIC_NAME_RE = re.compile(r"^(lambda\$|access\$|\$values|writeReplace|readResolve)")


def list_class_files(target: str) -> list[tuple[str, str]]:
    """Return (class_name, class_file_or_None) pairs for a target.

    - jar: names come from the zip listing; the class file is the jar itself
      (javap -cp jar) and None is returned as the file.
    - directory: walked for .class files; the package is derived from the
      relative path.
    - single .class file: one entry; the name is unknown until javap runs
      (class_file is set and the name is a placeholder to be replaced).
    """
    p = Path(target).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"target not found: {target}")
    if p.is_file() and p.suffix == ".jar":
        out = []
        with zipfile.ZipFile(p) as zf:
            for name in zf.namelist():
                if name.endswith(".class") and not name.endswith(
                    ("module-info.class", "package-info.class")
                ):
                    out.append((name[:-6].replace("/", "."), target))
        return out
    if p.is_file() and p.suffix == ".class":
        return [("<unknown>", str(p))]
    if p.is_dir():
        out = []
        for root, _dirs, files in os.walk(p):
            for f in sorted(files):
                if f.endswith(".class"):
                    full = Path(root) / f
                    rel = full.relative_to(p)
                    out.append((str(rel.with_suffix("")).replace(os.sep, "."), str(full)))
        return out
    raise ValueError(f"unsupported target type: {target}")


def _fingerprint(target: str) -> str:
    h = hashlib.sha256()
    p = Path(target).expanduser()
    if p.is_file():
        if p.suffix == ".jar":
            with zipfile.ZipFile(p) as zf:
                for info in sorted(zf.infolist(), key=lambda i: i.filename):
                    if info.filename.endswith(".class"):
                        h.update(info.filename.encode())
                        h.update(b"%d" % info.file_size)
        else:
            h.update(p.name.encode())
            h.update(b"%d" % p.stat().st_size)
    else:
        entries = []
        for root, _dirs, files in os.walk(p):
            for f in files:
                if f.endswith(".class"):
                    full = Path(root) / f
                    st = full.stat()
                    entries.append((str(full.relative_to(p)), st.st_size, st.st_mtime_ns))
        for rel, size, mtime in sorted(entries):
            h.update(f"{rel}:{size}:{mtime // 1000}".encode())
    return h.hexdigest()


@dataclass
class Index:
    target: str
    fingerprint: str
    classes: dict[str, ClassInfo]
    methods: list[MethodInfo]
    xrefs_to: dict[str, list[dict]]
    xrefs_from: dict[str, list[dict]]
    strings: dict[str, list[dict]]

    # -- lookup ---------------------------------------------------------------

    @property
    def by_addr(self) -> dict[str, MethodInfo]:
        return {normalize(m.address): m for m in self.methods}

    def method(self, class_name: str, name: str, descriptor: str) -> MethodInfo | None:
        for m in self.methods:
            if m.class_name == class_name and m.name == name and m.descriptor == descriptor:
                return m
        return None

    def resolve(self, target: str) -> MethodInfo:
        """Resolve an address, ``Class::method``, ``Class.method`` or bare name."""
        t = str(target).strip()
        by = self.by_addr
        if t.lower().startswith("0x") or re.fullmatch(r"[0-9a-fA-F]{8,16}", t):
            key = normalize(t)
            if key in by:
                return by[key]
            raise KeyError(f"unknown address {t}")
        if "::" in t:
            cls, _, name = t.partition("::")
        elif "#" in t:
            cls, _, name = t.partition("#")
        elif "." in t:
            cls, _, name = t.rpartition(".")
        else:
            cls, name = "", t
        cls = cls.strip()
        name = name.strip() or cls
        matches: list[MethodInfo] = []
        for m in self.methods:
            if cls and m.class_name != cls and not m.class_name.endswith("." + cls):
                continue
            if m.name != name:
                continue
            matches.append(m)
        if not matches:
            raise KeyError(f"cannot resolve method target {t!r}")
        if len(matches) > 1:
            descs = ", ".join(sorted(m.descriptor for m in matches))
            raise KeyError(
                f"ambiguous method {t!r} (overloads: {descs}); use an address instead"
            )
        return matches[0]

    def class_methods(self, class_filter: str | None, include_synthetic: bool = False) -> list[MethodInfo]:
        out = []
        for m in self.methods:
            c = self.classes.get(m.class_name)
            if c is not None and c.is_interface:
                continue  # no bytecode to reverse
            if not include_synthetic:
                if m.name == "<clinit>":
                    continue
                if SYNTHETIC_NAME_RE.match(m.name):
                    continue
                if c is not None and c.is_enum and m.name in ("values", "valueOf", "$values"):
                    continue
                if m.name == "<init>" and c is not None and c.is_enum:
                    continue  # synthetic (String, int) ctor
            if class_filter:
                f = class_filter.lower()
                if f not in m.class_name.lower() and f not in m.name.lower():
                    continue
            out.append(m)
        return out


# -- build --------------------------------------------------------------------


def _build(cfg: BridgeConfig) -> Index:
    classes: dict[str, ClassInfo] = {}
    methods: list[MethodInfo] = []
    for class_name, class_file in list_class_files(cfg.target):
        try:
            if class_file and class_file.endswith(".class"):
                text = run_javap(cfg, class_name=None, class_file=class_file)
            else:
                text = run_javap(cfg, class_name=class_name)
        except RuntimeError as exc:
            print(f"warning: skipping {class_name}: {exc}", flush=True)
            continue
        info = parse_javap(text)
        if info is None:
            continue
        if class_name == "<unknown>":
            class_name = info.class_name
            # re-key methods/fields to the discovered name
            for m in info.methods:
                m.class_name = info.class_name
            for f in info.fields:
                f.class_name = info.class_name
        classes[info.class_name] = info
        for m in info.methods:
            m.address = method_address(info.class_name, m.name, m.descriptor)
            methods.append(m)

    # xrefs
    xrefs_to: dict[str, list[dict]] = {}
    xrefs_from: dict[str, list[dict]] = {}
    strings: dict[str, list[dict]] = {}
    by_key: dict[tuple[str, str, str], MethodInfo] = {
        (m.class_name, m.name, m.descriptor): m for m in methods
    }
    for m in methods:
        for instr in m.lines:
            ref = parse_reference(instr.comment, m.class_name)
            if ref is not None and ref["kind"] == "method":
                entry = {
                    "class": ref["class"],
                    "name": ref["name"],
                    "desc": ref["desc"],
                    "opcode": instr.opcode,
                    "external": False,
                    "addr": "",
                }
                target = by_key.get((ref["class"], ref["name"], ref["desc"]))
                if target is not None:
                    entry["addr"] = target.address
                else:
                    entry["external"] = True
                xrefs_from.setdefault(m.address, []).append(entry)
                if target is not None:
                    xrefs_to.setdefault(target.address, []).append(
                        {
                            "addr": m.address,
                            "class": m.class_name,
                            "name": m.name,
                            "desc": m.descriptor,
                            "opcode": instr.opcode,
                        }
                    )
            s = extract_string(instr.comment)
            if s is not None:
                strings.setdefault(m.class_name, []).append(
                    {"addr": m.address, "method": m.name, "value": s}
                )

    return Index(
        target=cfg.target,
        fingerprint=_fingerprint(cfg.target),
        classes=classes,
        methods=methods,
        xrefs_to=xrefs_to,
        xrefs_from=xrefs_from,
        strings=strings,
    )


# -- persistence ----------------------------------------------------------------


def _cache_file(cfg: BridgeConfig, fingerprint: str) -> Path:
    d = cfg.cache_path / "index"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{fingerprint[:32]}.json"


def _serialize(idx: Index) -> dict:
    return {
        "schema_version": 1,
        "target": idx.target,
        "fingerprint": idx.fingerprint,
        "classes": {
            name: {
                "kind": c.kind,
                "extends": c.extends,
                "fields": [
                    {"name": f.name, "type": f.type, "modifiers": f.modifiers,
                     "descriptor": f.descriptor, "const_value": f.const_value}
                    for f in c.fields
                ],
                "raw": c.raw,
            }
            for name, c in idx.classes.items()
        },
        "methods": [
            {
                "class_name": m.class_name,
                "name": m.name,
                "descriptor": m.descriptor,
                "modifiers": m.modifiers,
                "address": m.address,
                "lines": [
                    {"offset": i.offset, "opcode": i.opcode,
                     "comment": i.comment, "targets": i.targets, "raw": i.raw}
                    for i in m.lines
                ],
            }
            for m in idx.methods
        ],
        "xrefs_to": idx.xrefs_to,
        "xrefs_from": idx.xrefs_from,
        "strings": idx.strings,
    }


def _deserialize(data: dict) -> Index:
    from .javap import Instr

    classes: dict[str, ClassInfo] = {}
    for name, c in data["classes"].items():
        classes[name] = ClassInfo(
            class_name=name,
            kind=c.get("kind", "class"),
            extends=c.get("extends", ""),
            fields=[
                FieldInfo(
                    name=f["name"], type=f["type"], modifiers=f.get("modifiers", ""),
                    descriptor=f.get("descriptor", ""), const_value=f.get("const_value", ""),
                )
                for f in c.get("fields", [])
            ],
            raw=c.get("raw", ""),
        )
    methods: list[MethodInfo] = []
    for m in data["methods"]:
        methods.append(
            MethodInfo(
                class_name=m["class_name"],
                name=m["name"],
                descriptor=m["descriptor"],
                modifiers=m.get("modifiers", ""),
                lines=[
                    Instr(
                        offset=i["offset"], opcode=i["opcode"],
                        comment=i.get("comment", ""), targets=i.get("targets", []),
                        raw=i.get("raw", f"{i['offset']}: {i['opcode']}"),
                    )
                    for i in m.get("lines", [])
                ],
                address=m["address"],
            )
        )
    return Index(
        target=data["target"],
        fingerprint=data["fingerprint"],
        classes=classes,
        methods=methods,
        xrefs_to=data.get("xrefs_to", {}),
        xrefs_from=data.get("xrefs_from", {}),
        strings=data.get("strings", {}),
    )


def load(cfg: BridgeConfig, force: bool = False) -> Index:
    """Load the index from cache or rebuild it.

    The cache file is written atomically (tmp + rename) so concurrent
    readers always see a complete file — a torn read mid-write used to
    cause JSONDecodeError -> rebuild -> write cascades when several
    java-bridge processes ran in parallel.
    """
    fp = _fingerprint(cfg.target)
    cf = _cache_file(cfg, fp)
    if not force and cf.exists():
        try:
            idx = _deserialize(json.loads(cf.read_text(encoding="utf-8")))
            if idx.fingerprint == fp:
                return idx
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            pass
    idx = _build(cfg)
    tmp = cf.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(_serialize(idx)), encoding="utf-8")
    tmp.replace(cf)
    return idx
