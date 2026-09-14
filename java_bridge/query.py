"""Query commands: stdout formats compatible with reagent's GhidraBridgeBackend.

Output contracts (matched against re_agent.backend.ghidra_bridge parsers):
- function lists:  ``0xADDR  Class::method  (N callers)``
- decompile:       ``// Known as:`` / ``// Signature:`` comment lines,
                   ``Callers: N | Callees: M`` line, then the method source
- xrefs:           ``0xADDR  Class::method`` per line
- pcode / cfg:     JSON (``{"data": [...]}``) — reagent json.loads the content
- context / vtable / global / strings: free-form text (AnalysisArtifact blobs)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .config import BridgeConfig
from .decompile import DecompileError, decompile_class, extract_method
from .index import Index, load
from .javap import BRANCH_OPS, INVOKE_OPS, RETURN_OPS, SWITCH_OPS, extract_string
from .jvm import parse_descriptor


def _fail(msg: str) -> int:
    print(f"error: {msg}", flush=True)
    return 1


def _caller_count(idx: Index, addr: str) -> int:
    return len(idx.xrefs_to.get(addr, []))


def _callee_count(idx: Index, m) -> int:
    return len(idx.xrefs_from.get(m.address, []))


def _func_line(idx: Index, m, show_callers: bool = True) -> str:
    callers = _caller_count(idx, m.address)
    tail = f"  ({callers} callers)" if show_callers else ""
    return f"{m.address}  {m.class_name}::{m.name}{tail}"


# -- list-shaped commands -------------------------------------------------------


def cmd_search(idx: Index, pattern: str) -> int:
    pat = pattern.lower()
    found = [
        m for m in idx.methods
        if pat in m.class_name.lower() or pat in m.name.lower()
    ]
    for m in found:
        print(_func_line(idx, m))
    return 0


def cmd_list(idx: Index, _pattern: str | None) -> int:
    for m in idx.methods:
        print(_func_line(idx, m))
    return 0


def cmd_unimplemented(idx: Index, cfg: BridgeConfig, pattern: str | None) -> int:
    for m in idx.class_methods(pattern):
        print(_func_line(idx, m))
    return 0


def cmd_remaining(idx: Index, cfg: BridgeConfig, pattern: str | None) -> int:
    return cmd_unimplemented(idx, cfg, pattern)


# -- decompile ------------------------------------------------------------------


def _method_signature(idx: Index, m) -> str:
    try:
        params, ret = parse_descriptor(m.descriptor)
    except ValueError:
        return f"{m.name}{m.descriptor}"
    return f"{ret} {m.name}({', '.join(params)})"


def cmd_decompile(idx: Index, cfg: BridgeConfig, target: str) -> int:
    try:
        m = idx.resolve(target)
    except KeyError as exc:
        return _fail(str(exc))
    try:
        code = extract_method(cfg, idx, m)
    except (DecompileError, RuntimeError) as exc:
        # Fall back to bytecode so the agent still gets structural evidence.
        code = f"// NOTE: decompiler unavailable ({str(exc)[:300]}); bytecode follows\n" + _asm_text(m)
    print(f"// Known as: {m.class_name}::{m.name}")
    print(f"// Signature: {_method_signature(idx, m)}")
    print(f"// Class: {m.class_name}")
    print(f"Callers: {_caller_count(idx, m.address)} | Callees: {_callee_count(idx, m)}")
    print(code)
    return 0


def _asm_text(m) -> str:
    out = [f"{m.class_name}::{m.name}{m.descriptor}"]
    for i in m.lines:
        out.append(f"  {i.raw}")
    for t in _switch_extra(m):
        out.append(f"  {t}")
    return "\n".join(out)


def _switch_extra(m) -> list[str]:
    extra = []
    for i in m.lines:
        if i.opcode in SWITCH_OPS and i.targets:
            extra.append(f"  {i.offset:>5}: {i.opcode} targets: {i.targets}")
    return extra


def cmd_asm(idx: Index, cfg: BridgeConfig, target: str) -> int:
    try:
        m = idx.resolve(target)
    except KeyError as exc:
        return _fail(str(exc))
    print(_asm_text(m))
    return 0


# -- xrefs ----------------------------------------------------------------------


def cmd_xrefs_to(idx: Index, cfg: BridgeConfig, target: str) -> int:
    try:
        m = idx.resolve(target)
    except KeyError as exc:
        return _fail(str(exc))
    refs = idx.xrefs_to.get(m.address, [])
    if not refs:
        print("// no internal callers")
    for r in refs:
        print(f"{r['addr']}  {r['class']}::{r['name']}")
    return 0


def cmd_xrefs_from(idx: Index, cfg: BridgeConfig, target: str) -> int:
    try:
        m = idx.resolve(target)
    except KeyError as exc:
        return _fail(str(exc))
    refs = idx.xrefs_from.get(m.address, [])
    if not refs:
        print("// no outgoing calls")
    seen: set[tuple[str, str, str]] = set()
    for r in refs:
        key = (r["class"], r["name"], r["desc"])
        if key in seen:
            continue
        seen.add(key)
        if r["external"]:
            print(f"// external: {r['class']}::{r['name']} {r['desc']}")
        else:
            print(f"{r['addr']}  {r['class']}::{r['name']}")
    return 0


# -- struct / enum / vtable / global ---------------------------------------------


def _find_class(idx: Index, target: str):
    """Find a class by name, tolerating $ <-> . inner-class separators."""
    if target in idx.classes:
        return idx.classes[target]
    candidates = {target, target.replace("$", "."), target.replace(".", "$")}
    for name in idx.classes:
        variants = {name, name.replace("$", "."), name.replace(".", "$")}
        if variants & candidates or name.endswith("." + target) or name.replace("$", ".").endswith("." + target):
            return idx.classes[name]
    return None


def cmd_struct(idx: Index, cfg: BridgeConfig, target: str) -> int:
    """``source-struct``: fields of a class (slot numbers, not byte offsets)."""
    cls = _find_class(idx, target)
    if cls is None:
        return _fail(f"no class matching {target!r}")
    print(f"// Java class {cls.class_name} (slot indices, not byte offsets)")
    print(f"Size: 0x{len(cls.fields):x} ({len(cls.fields)})")
    for i, f in enumerate(cls.fields, start=1):
        print(f"  +0x{i:x}  {f.type}  {f.name}")
    return 0


def cmd_enum(idx: Index, cfg: BridgeConfig, target: str) -> int:
    """``source-enum``: enum constants with their ordinals."""
    cls = _find_class(idx, target)
    if cls is None or not cls.is_enum:
        return _fail(f"no enum matching {target!r}")
    for i, name in enumerate(cls.enum_constants):
        print(f"{name} = {i}")
    return 0


def cmd_vtable(idx: Index, cfg: BridgeConfig, target: str) -> int:
    """Virtual (dispatchable) methods of a class."""
    cls = _find_class(idx, target)
    if cls is None:
        return _fail(f"no class matching {target!r}")
    print(f"// virtual (non-final instance) methods of {cls.class_name}")
    for m in cls.methods:
        if "static" in m.modifiers or m.name == "<clinit>":
            continue
        if cls.is_interface and "default" not in m.modifiers and "abstract" not in m.modifiers:
            continue
        kind = "abstract" if "abstract" in m.modifiers or (cls.is_interface and "default" not in m.modifiers) else "concrete"
        if "final" in m.modifiers and kind == "concrete":
            continue
        print(f"{m.address}  {m.class_name}::{m.name}  ({kind})")
    return 0


def cmd_global(idx: Index, cfg: BridgeConfig, target: str) -> int:
    """``global``: a static field (``Class.FIELD`` or ``Class.field``)."""
    parts = target.rsplit(".", 1)
    if len(parts) != 2:
        return _fail(f"expected Class.FIELD, got {target!r}")
    cls_name, field_name = parts
    cls = _find_class(idx, cls_name)
    if cls is None:
        return _fail(f"no class matching {cls_name!r}")
    for f in cls.fields:
        if f.name == field_name:
            print(f"// static field {cls.class_name}.{f.name}")
            print(f"// modifiers: {f.modifiers or 'static'}")
            print(f"// type: {f.type}")
            print(f"// descriptor: {f.descriptor}")
            if f.const_value:
                print(f"// ConstantValue: {f.const_value}")
            return 0
    return _fail(f"no field {field_name!r} in {cls.class_name}")


# -- strings / context ------------------------------------------------------------


def cmd_strings(idx: Index, cfg: BridgeConfig, pattern: str) -> int:
    pat = pattern.lower()
    for class_name in sorted(idx.strings):
        for s in idx.strings[class_name]:
            if pat in s["value"].lower():
                where = f"{s['addr']}  {class_name}  \" {s['value']} \" (in {s['method']})"
                print(where)
    return 0


def cmd_context(idx: Index, cfg: BridgeConfig, target: str) -> int:
    """Full class context: decompiled class + fields + method signatures."""
    try:
        m = idx.resolve(target)
    except KeyError as exc:
        return _fail(str(exc))
    cls = idx.classes.get(m.class_name)
    print(f"// class {m.class_name}" + (f" extends {cls.extends}" if cls and cls.extends else ""))
    if cls:
        print("// fields:")
        for f in cls.fields:
            print(f"//   {f.modifiers} {f.type} {f.name};")
        print("// methods:")
        for om in cls.methods:
            try:
                params, ret = parse_descriptor(om.descriptor)
            except ValueError:
                params, ret = [], "?"
            print(f"//   {om.modifiers} {ret} {om.name}({', '.join(params)});")
    try:
        print(decompile_class(cfg, idx, m.class_name))
    except (DecompileError, RuntimeError) as exc:
        print(f"// decompiler unavailable: {exc}")
    return 0


# -- pcode / cfg (JSON) -----------------------------------------------------------


def _branch_target(i) -> str:
    """Bytecode branch target: a switch target or the trailing offset in raw."""
    if i.targets:
        return f"{i.opcode} {i.targets}"
    tm = re.search(r"(\d+)\s*$", i.raw or "")
    return tm.group(1) if tm else ""


def _pcode_items(m) -> list[dict]:
    items = []
    for i in m.lines:
        if i.opcode in INVOKE_OPS and i.opcode != "invokedynamic":
            items.append({"opcode": "CALL", "target": i.comment})
        elif i.opcode in RETURN_OPS:
            items.append({"opcode": "RETURN"})
        elif i.opcode in BRANCH_OPS:
            items.append({"opcode": "BRANCH", "target": _branch_target(i)})
        elif i.opcode in SWITCH_OPS:
            items.append({"opcode": "BRANCH", "target": _branch_target(i)})
        elif i.opcode == "invokedynamic":
            items.append({"opcode": "INVOKE_DYNAMIC", "target": i.comment})
        else:
            items.append({"opcode": i.opcode.upper()})
    return items


def _cfg_blocks(m) -> list[dict]:
    """Derive basic blocks from branch targets (bytecode offsets)."""
    ins = m.lines
    if not ins:
        return []
    targets: set[int] = set()
    fallthrough_points: set[int] = set()
    ends: set[int] = set()
    for k, i in enumerate(ins):
        nxt = ins[k + 1] if k + 1 < len(ins) else None
        if i.opcode in SWITCH_OPS:
            targets.update(i.targets)
            if nxt is not None:
                fallthrough_points.add(nxt.offset)  # code after the switch
        elif i.opcode in BRANCH_OPS:
            tm = re.search(r"(\d+)\s*$", i.raw or "")
            if tm:
                targets.add(int(tm.group(1)))
            if nxt is not None and i.opcode != "goto":
                fallthrough_points.add(nxt.offset)
        elif i.opcode in RETURN_OPS:
            ends.add(i.offset)
    leaders = {ins[0].offset} | targets | fallthrough_points
    leaders = {o for o in leaders if any(i.offset == o for i in ins)}
    blocks: list[list] = []
    cur: list = []
    for i in ins:
        if i.offset in leaders:
            if cur:
                blocks.append(cur)
            cur = [i]
        else:
            cur.append(i)
    if cur:
        blocks.append(cur)

    offset_to_block = {b[0].offset: bi for bi, b in enumerate(blocks)}
    out = []
    for bi, b in enumerate(blocks):
        last = b[-1]
        outs: set[int] = set()
        if last.opcode in SWITCH_OPS:
            for t in last.targets:
                if t in offset_to_block:
                    outs.add(offset_to_block[t])
            if bi + 1 < len(blocks):
                outs.add(bi + 1)  # fallthrough after the switch
        elif last.opcode in BRANCH_OPS:
            tm = re.search(r"(\d+)\s*$", last.raw or "")
            if tm and int(tm.group(1)) in offset_to_block:
                outs.add(offset_to_block[int(tm.group(1))])
            if last.opcode != "goto" and bi + 1 < len(blocks):
                outs.add(bi + 1)
        elif last.opcode not in RETURN_OPS:
            if bi + 1 < len(blocks):
                outs.add(bi + 1)
        out.append({"index": bi, "out": sorted(outs)})
    return out


def cmd_pcode(idx: Index, cfg: BridgeConfig, target: str) -> int:
    try:
        m = idx.resolve(target)
    except KeyError as exc:
        return _fail(str(exc))
    print(json.dumps({"schema_version": 1, "data": _pcode_items(m)}))
    return 0


def cmd_cfg(idx: Index, cfg: BridgeConfig, target: str) -> int:
    try:
        m = idx.resolve(target)
    except KeyError as exc:
        return _fail(str(exc))
    print(json.dumps({"schema_version": 1, "data": _cfg_blocks(m)}))
    return 0


# -- info --------------------------------------------------------------------------


def cmd_info(idx: Index, cfg: BridgeConfig) -> int:
    n_classes = len(idx.classes)
    n_methods = len(idx.methods)
    n_xrefs = sum(len(v) for v in idx.xrefs_from.values())
    n_strings = sum(len(v) for v in idx.strings.values())
    print(f"target:        {cfg.target}")
    print(f"fingerprint:   {idx.fingerprint}")
    print(f"classes:       {n_classes}")
    print(f"methods:       {n_methods}")
    print(f"xref edges:    {n_xrefs}")
    print(f"string constants: {n_strings}")
    print("address scheme: 0x + sha256(class#name+descriptor)[:16]")
    return 0
