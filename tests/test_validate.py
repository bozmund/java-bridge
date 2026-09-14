"""``java-bridge validate``: correct candidates pass, broken ones fail.

Needs JDK + CFR. Candidate files are named like reagent names isolated
candidates ({safe_class}_{safe_func}) so target inference is exercised.
"""

import re
from pathlib import Path

import pytest

from java_bridge.config import BridgeConfig
from java_bridge.index import load
from java_bridge.validate import validate

from test_index import DEMO


def _method_source(java_file: Path, name: str) -> str:
    """Extract a method's source from the original demo source file."""
    text = java_file.read_text()
    m = re.search(
        r"(?m)^([ \t]*(?:(?:public|private|protected|static|final)[ \t]+)*"
        r"[^;{=]*?\b" + re.escape(name) + r"\s*\([^)]*\)\s*(?:throws [^{;]+)?)\{",
        text,
    )
    assert m, f"method {name} not found in {java_file}"
    start = m.start()
    depth = 0
    i = text.index("{", m.end() - 1)
    while True:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1


@pytest.fixture()
def ctx(tmp_path):
    classes = DEMO / "classes"
    if not list(classes.glob("**/*.class")):
        pytest.skip("demo classes not compiled")
    cfg = BridgeConfig(target=str(classes), cache_dir=str(tmp_path / "cache"))
    idx = load(cfg)
    return cfg, idx


def test_validate_correct_candidate(ctx, tmp_path):
    cfg, idx = ctx
    src = _method_source(DEMO / "src/com/example/demo/ScoreKeeper.java", "rankOf")
    cand = tmp_path / "com_example_demo_ScoreKeeper_rankOf.cpp"
    cand.write_text(src + "\n")
    assert validate(cfg, idx, cand) == 0


def test_validate_candidate_with_explicit_method(ctx, tmp_path):
    cfg, idx = ctx
    src = _method_source(DEMO / "src/com/example/demo/Geometry.java", "dot")
    cand = tmp_path / "candidate.cpp"  # unhelpful name -> explicit method
    cand.write_text(src + "\n")
    assert validate(cfg, idx, cand, explicit="com.example.demo.Geometry::dot") == 0


def test_validate_rejects_broken_candidate(ctx, tmp_path):
    cfg, idx = ctx
    broken = """
public com.example.demo.ScoreKeeper$Rank rankOf() {
    return com.example.demo.ScoreKeeper$Rank.valueOf("GOLD").hashCode();
}
"""
    cand = tmp_path / "com_example_demo_ScoreKeeper_rankOf.cpp"
    cand.write_text(broken)
    assert validate(cfg, idx, cand) == 1


def test_validate_no_method_in_file(ctx, tmp_path):
    cfg, idx = ctx
    cand = tmp_path / "com_example_demo_ScoreKeeper_rankOf.cpp"
    cand.write_text("int notJava = 3;\n")
    assert validate(cfg, idx, cand) == 1
