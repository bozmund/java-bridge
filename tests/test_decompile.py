"""CFR decompilation and per-method extraction (needs JDK + network for the
CFR jar on first use; skipped otherwise)."""

import pytest

from java_bridge.config import BridgeConfig
from java_bridge.decompile import DecompileError, decompile_class, extract_method, method_at
from java_bridge.index import load

from test_index import DEMO


@pytest.fixture(scope="module")
def demo_classes():
    classes = DEMO / "classes"
    if not list(classes.glob("**/*.class")):
        pytest.skip("demo classes not compiled (run: javac -d classes examples/demo/src/**/*.java)")
    return classes


@pytest.fixture()
def ctx(demo_classes, tmp_path):
    cfg = BridgeConfig(target=str(demo_classes), cache_dir=str(tmp_path / "cache"))
    idx = load(cfg)
    yield cfg, idx
    # keep downloaded CFR jar from being refetched by later tests:
    # nothing to clean (tmp cache)


def test_decompile_class(ctx):
    cfg, idx = ctx
    src = decompile_class(cfg, idx, "com.example.demo.Geometry")
    assert "public class Geometry" in src
    assert "distanceTo" in src


def test_extract_method(ctx):
    cfg, idx = ctx
    m = idx.method("com.example.demo.Geometry", "distanceTo", "(Lcom/example/demo/Geometry;)D")
    assert m is not None
    code = extract_method(cfg, idx, m)
    assert "Math.sqrt" in code
    assert "distanceTo" in code


def test_method_at_ctor_not_in_cfr_output(ctx):
    # CFR 0.152 omits default no-arg constructors; method_at must report
    # None (not raise), letting callers fall back to bytecode.
    cfg, idx = ctx
    src = decompile_class(cfg, idx, "com.example.demo.ScoreKeeper")
    m = idx.method("com.example.demo.ScoreKeeper", "<init>", "()V")
    assert m is not None
    if "public ScoreKeeper() {" not in src:
        assert method_at(src, m.class_name, m.name, m.descriptor) is None


def test_extract_method_missing_raises(ctx):
    cfg, idx = ctx
    m = idx.method("com.example.demo.ScoreKeeper", "<init>", "()V")
    src = decompile_class(cfg, idx, "com.example.demo.ScoreKeeper")
    if "public ScoreKeeper() {" not in src:
        with pytest.raises(DecompileError):
            extract_method(cfg, idx, m)
