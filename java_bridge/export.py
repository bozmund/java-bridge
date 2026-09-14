"""``java-bridge export``: write Ghidra-JSON-schema-1 export records.

This makes the ``ghidra-json`` reagent backend type usable without any CLI
shelling: ``backend.type: ghidra-json`` + ``backend.export_dir: <dir>``.
"""

from __future__ import annotations

import json
from pathlib import Path

from .config import BridgeConfig
from .decompile import DecompileError, decompile_class
from .index import Index
from .jvm import parse_descriptor
from .query import _cfg_blocks, _pcode_items
from .addr import normalize


def _assembly_lines(m) -> list[str]:
    return [i.raw for i in m.lines]


def export_all(cfg: BridgeConfig, idx: Index, out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)

    index: dict[str, dict] = {}
    for m in idx.methods:
        index[normalize(m.address)] = {"name": f"{m.class_name}::{m.name}"}
    (out_dir / "_index.json").write_text(
        json.dumps({"schema_version": 1, **index}, indent=1), encoding="utf-8"
    )

    name_map = {k: {"full_name": v["name"]} for k, v in index.items()}
    (out_dir / "address_map.json").write_text(
        json.dumps({"schema_version": 1, **name_map}, indent=1), encoding="utf-8"
    )

    structs: dict[str, dict] = {}
    for name, cls in idx.classes.items():
        structs[name] = {
            "size_dec": len(cls.fields),
            "fields": [
                {"field": f.name, "offset_dec": i, "type": f.type, "size": 0}
                for i, f in enumerate(cls.fields, start=1)
            ],
        }
    (out_dir / "_source_structs.json").write_text(
        json.dumps({"schema_version": 1, "structs": structs}, indent=1), encoding="utf-8"
    )

    decompiled_cache: dict[str, str | None] = {}
    for m in idx.methods:
        cls_src = decompiled_cache.get(m.class_name)
        if m.class_name not in decompiled_cache:
            try:
                cls_src = decompile_class(cfg, idx, m.class_name)
            except (DecompileError, RuntimeError):
                cls_src = None
            decompiled_cache[m.class_name] = cls_src
        code = ""
        if cls_src:
            try:
                from .decompile import method_at

                loc = method_at(cls_src, m.class_name, m.name, m.descriptor)
                code = loc[2].strip() if loc else ""
            except Exception:  # noqa: BLE001
                code = ""
        if not code:
            code = "\n".join(
                f"// {i.offset}: {i.opcode} {i.comment}".strip() for i in m.lines
            )
        try:
            params, ret = parse_descriptor(m.descriptor)
            signature = f"{ret} {m.name}({', '.join(params)})"
        except ValueError:
            signature = m.descriptor
        record = {
            "schema_version": 1,
            "address": m.address,
            "name": f"{m.class_name}::{m.name}",
            "signature": signature,
            "decompiled": code,
            "callers": [
                {"addr": r["addr"], "name": f"{r['class']}::{r['name']}", "ref_type": "CALL"}
                for r in idx.xrefs_to.get(m.address, [])
            ],
            "callees": [
                {"addr": r["addr"] or f"ext:{r['class']}::{r['name']}",
                 "name": f"{r['class']}::{r['name']}", "ref_type": "CALL"}
                for r in idx.xrefs_from.get(m.address, [])
            ],
            "gaps": [],
            "data_refs": [
                {"addr": r["addr"] or "", "name": f"{r['class']}.{r['name']}", "kind": "field"}
                for r in []  # field refs are not tracked per-method in v1
            ],
            "strings": [s["value"] for s in idx.strings.get(m.class_name, []) if s["method"] == m.name],
            "cfg": _cfg_blocks(m),
            "pcode": _pcode_items(m),
            "assembly": _assembly_lines(m),
        }
        (out_dir / f"{normalize(m.address)}.json").write_text(
            json.dumps(record, indent=1), encoding="utf-8"
        )
    print(f"exported {len(idx.methods)} methods to {out_dir}")
    print(f"ghidra-json backend config: export_dir: {out_dir}, address_map: {out_dir / 'address_map.json'}")
    return 0
