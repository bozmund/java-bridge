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
    if os.environ.get("JAVA_BRIDGE_NO_THINKING"):
        _disable_thinking()

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


def _disable_thinking() -> None:
    """Patch the OpenAI-compatible provider to send llama.cpp's
    ``chat_template_kwargs.enable_thinking=false``.

    Qwen3.8-family models think by default (the template's enable_thinking
    defaults to true); for large batches of mechanical naming tasks that
    burns most of the token budget on unreturned reasoning with no quality
    gain. llama-swap / llama.cpp accept the flag in the request body; the
    OpenAI client forwards it via ``extra_body``. Note: reagent's
    ``OpenAIProvider.send`` does not forward ``extra_body`` to ``create``,
    so the interception happens on the client's ``create`` itself.
    No reagent source files are modified.
    """
    from re_agent.llm.openai_compat import OpenAIProvider

    original_send = OpenAIProvider.send

    def send(self, messages, **kwargs):  # type: ignore[no-untyped-def]
        orig_create = self._client.chat.completions.create

        def create_with_no_thinking(**kw):  # type: ignore[no-untyped-def]
            extra = dict(kw.pop("extra_body", None) or {})
            ctk = dict(extra.get("chat_template_kwargs") or {})
            ctk.setdefault("enable_thinking", False)
            extra["chat_template_kwargs"] = ctk
            kw["extra_body"] = extra
            return orig_create(**kw)

        self._client.chat.completions.create = create_with_no_thinking
        return original_send(self, messages, **kwargs)

    OpenAIProvider.send = send  # type: ignore[method-assign]


def main(argv: list[str] | None = None) -> int:
    prompts = _apply_java_overrides()
    if os.environ.get("JAVA_BRIDGE_VERBOSE"):
        print(f"reagent-java: using Java prompts from {prompts}", file=sys.stderr)
    from re_agent.cli.main import main as reagent_main

    return reagent_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
