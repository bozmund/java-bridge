"""Index construction and resolution against the bundled demo classes.

Skipped when a JDK is not available on the host.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from java_bridge.config import BridgeConfig
from java_bridge.index import load

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "examples" / "demo"


@pytest.fixture(scope="module")
def demo_classes() -> Path:
    classes = DEMO / "classes"
    if not list(classes.glob("**/*.class")):
        proc = subprocess.run(
            ["javac", "-d", str(classes), *[str(p) for p in sorted((DEMO / "src").rglob("*.java"))]],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            pytest.skip(f"javac failed: {proc.stderr}")
    return classes


@pytest.fixture()
def idx(demo_classes, tmp_path):
    cfg = BridgeConfig(target=str(demo_classes), cache_dir=str(tmp_path / "cache"))
    return load(cfg)


def test_inventory(idx):
    assert len(idx.classes) == 4
    names = {(m.class_name, m.name) for m in idx.methods}
    assert ("com.example.demo.Geometry", "distanceTo") in names
    assert ("com.example.demo.ScoreKeeper", "<init>") in names
    assert ("com.example.demo.ScoreKeeper$Rank", "<init>") in names


def test_enum_kind_detected(idx):
    rank = idx.classes["com.example.demo.ScoreKeeper$Rank"]
    assert rank.is_enum
    assert rank.enum_constants == ["BRONZE", "SILVER", "GOLD"]


def test_xrefs(idx):
    by_key = {(m.class_name, m.name): m for m in idx.methods}
    rankof = by_key[("com.example.demo.ScoreKeeper", "rankOf")]
    callers = {c["class"] + "::" + c["name"] for c in idx.xrefs_to[rankof.address]}
    assert "com.example.demo.ScoreKeeper::rankMultiplier" in callers
    dist = by_key[("com.example.demo.Geometry", "distanceTo")]
    refs = idx.xrefs_from[dist.address]
    internal = [r for r in refs if not r["external"]]
    assert not internal  # distanceTo only calls java.lang.Math
    assert any(r["external"] and r["class"] == "java.lang.Math" and r["name"] == "sqrt" for r in refs)


def test_strings(idx):
    strings = [s["value"] for s in idx.strings.get("com.example.demo.Inventory", [])]
    assert "empty item" in strings


def test_resolve_variants(idx):
    m1 = idx.resolve("com.example.demo.Geometry::distanceTo")
    m2 = idx.resolve("com.example.demo.Geometry.distanceTo")
    m3 = idx.resolve("com.example.demo.Geometry#distanceTo")
    m4 = idx.resolve("distanceTo")
    m5 = idx.resolve(m1.address)
    assert m1.address == m2.address == m3.address == m4.address == m5.address


def test_resolve_ambiguous(idx):
    # no overloads in the demo, so add a pair manually
    from java_bridge.javap import MethodInfo

    a = MethodInfo("c.A", "f", "(I)V", "")
    b = MethodInfo("c.A", "f", "(J)V", "")
    idx.methods.extend([a, b])
    try:
        with pytest.raises(KeyError, match="ambiguous"):
            idx.resolve("c.A::f")
    finally:
        idx.methods.pop()
        idx.methods.pop()


def test_class_methods_filters_synthetics(idx):
    names = {m.name for m in idx.class_methods("ScoreKeeper$Rank")}
    assert "values" not in names
    assert "valueOf" not in names
    assert "<init>" not in names  # synthetic enum ctor


def test_descriptor_fields(idx):
    g = idx.classes["com.example.demo.Geometry"]
    fields = {f.name: f.type for f in g.fields}
    assert fields == {"x": "double", "y": "double"}
