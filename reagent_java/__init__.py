"""``reagent-java``: run reagent with Java-specific prompt and extraction.

This is a thin launcher around ``re_agent.cli.main`` that, before dispatch,
points the reverser/checker agents at the Java prompt templates shipped with
java-bridge and teaches the code extractor about ```java fences. No reagent
source files are modified.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


def _apply_java_overrides() -> Path:
    import java_bridge
    import re_agent.agents.checker as checker
    import re_agent.agents.reverser as reverser

    prompts = Path(
        os.environ.get("JAVA_BRIDGE_PROMPTS")
        or (Path(java_bridge.__file__).parent / "prompts")
    )
    if not (prompts / "reverser_system.md").is_file():
        raise RuntimeError(f"prompt templates not found under {prompts}")
    reverser.PROMPTS_DIR = prompts
    checker.PROMPTS_DIR = prompts
    reverser.CODE_BLOCK_RE = re.compile(r"```(?:cpp|c\+\+|java)?\s*\n(.*?)```", re.S)
    return prompts


def main(argv: list[str] | None = None) -> int:
    prompts = _apply_java_overrides()
    if os.environ.get("JAVA_BRIDGE_VERBOSE"):
        print(f"reagent-java: using Java prompts from {prompts}", file=sys.stderr)
    from re_agent.cli.main import main as reagent_main

    return reagent_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
