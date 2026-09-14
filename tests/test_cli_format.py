"""CLI output must round-trip through reagent's own parsers (GhidraBridgeBackend).

Skipped when reagent is not installed in the environment.
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from java_bridge.config import BridgeConfig
from java_bridge.index import load

from test_index import DEMO

re_agent = pytest.importorskip("re_agent")
gb = pytest.importorskip("re_agent.backend.ghidra_bridge")


def _cli(tmp_cache: Path, *args: str) -> str:
    cfg_file = tmp_cache / "cfg.yaml"
    cfg_file.write_text(
        f"target: {DEMO / 'classes'}\ncache_dir: {tmp_cache / 'cache'}\n"
    )
    exe = sys.executable
    proc = subprocess.run(
        [exe, "-m", "java_bridge", "--config", str(cfg_file), *args],
        capture_output=True, text=True, cwd=str(DEMO),
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _addr(out: str) -> str:
    return out.splitlines()[0].split()[0]


def test_search_parses(tmp_path):
    out = _cli(tmp_path, "search", "Geometry")
    entries = gb.GhidraBridgeBackend._parse_function_list(out)
    assert entries
    assert all(e.class_name == "com.example.demo.Geometry" for e in entries)
    assert all(re.fullmatch(r"0x[0-9a-f]{16}", e.address) for e in entries)


def test_decompile_parses(tmp_path):
    out = _cli(tmp_path, "search", "distanceTo")
    addr = _addr(out)
    deco = _cli(tmp_path, "decompile", addr)
    known = re.search(r"^// Known as:\s*(.+)$", deco, re.M)
    cc = re.search(r"Callers:\s*(\d+)\s*\|\s*Callees:\s*(\d+)", deco)
    sig = re.search(r"^// Signature:\s*(.+)$", deco, re.M)
    assert known and "Geometry::distanceTo" in known.group(1)
    assert cc
    assert sig
    # the decompiled body must include a real method (not just the NOTE line)
    body = deco.split("Callees", 1)[1]
    assert "Math.sqrt" in body


def test_xrefs_parse(tmp_path):
    out = _cli(tmp_path, "search", "distanceTo")
    addr = _addr(out)
    raw = _cli(tmp_path, "xrefs-to", addr)
    refs = gb.GhidraBridgeBackend._parse_xrefs(raw)
    assert refs, "distanceTo should have internal callers"
    assert any("ScoreKeeper" in r.name for r in refs)


def test_pcode_and_cfg_are_json(tmp_path):
    out = _cli(tmp_path, "search", "rankOf")
    addr = _addr(out)
    pcode = json.loads(_cli(tmp_path, "pcode", addr))
    cfg = json.loads(_cli(tmp_path, "cfg", addr))
    assert pcode["data"]
    assert any(item["opcode"] == "BRANCH" for item in pcode["data"])
    blocks = cfg["data"]
    assert blocks
    branching = [b for b in blocks if len(set(b["out"])) > 1]
    assert branching, "rankOf has two comparisons -> at least one branching block"


def test_enum_and_struct(tmp_path):
    enum = _cli(tmp_path, "source-enum", "com.example.demo.ScoreKeeper.Rank")
    vals = re.findall(r"^(\w+)\s*=\s*(\d+)$", enum, re.M)
    assert [v[0] for v in vals] == ["BRONZE", "SILVER", "GOLD"]
    st = _cli(tmp_path, "source-struct", "com.example.demo.Geometry")
    fields = re.findall(r"(?m)^\s*\+0x[0-9a-f]+\s+(\S+)\s+(\S+)\s*$", st)
    assert ("double", "x") in fields and ("double", "y") in fields


def test_subcommand_probe_contract(tmp_path):
    """reagent probes <cli> <subcmd> --help and <cli> <subcmd> __probe__;
    failures must not look like 'unknown command'."""
    cfg_file = tmp_path / "cfg.yaml"
    cfg_file.write_text(f"target: {DEMO / 'classes'}\ncache_dir: {tmp_path / 'c'}\n")
    exe = sys.executable
    p = subprocess.run(
        [exe, "-m", "java_bridge", "--config", str(cfg_file), "decompile", "__probe__"],
        capture_output=True, text=True, cwd=str(DEMO),
    )
    assert p.returncode != 0
    low = p.stderr.lower()
    for pat in ("unknown command", "unrecognized command", "invalid choice",
                "no such sub-command", "not a command"):
        assert pat not in low


def test_export_consumable_by_json_backend(tmp_path):
    re_agent_exports = pytest.importorskip("re_agent.backend.exports")
    out = _cli(tmp_path, "export", "all", "--dir", str(tmp_path / "exp"))
    exp = tmp_path / "exp"
    assert (exp / "_index.json").is_file()
    backend = re_agent_exports.GhidraExportsBackend(str(exp), str(exp / "address_map.json"))
    index = json.loads((exp / "_index.json").read_text())
    first_addr = next(k for k in index if k != "schema_version")
    result = backend.decompile("0x" + first_addr)
    assert result.decompiled.strip()
