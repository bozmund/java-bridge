"""Configuration for java-bridge (java-bridge.yaml).

Lookup order: --config flag > $JAVA_BRIDGE_CONFIG > ./java-bridge.yaml >
~/.config/java-bridge/java-bridge.yaml.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CFR_URL = "https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar"


@dataclass
class BridgeConfig:
    target: str = ""                      # .jar, .class file, or directory of classes
    classpath: list[str] = field(default_factory=list)  # extra jars/dirs
    java: str = "java"
    javac: str = "javac"
    javap: str = "javap"
    decompiler: str = "cfr"
    cfr_jar: str = ""                     # explicit jar path (default: auto-download to cache)
    cfr_url: str = DEFAULT_CFR_URL
    cache_dir: str = str(Path.home() / ".cache" / "java-bridge")
    timeout_s: int = 120

    @property
    def cache_path(self) -> Path:
        return Path(self.cache_dir).expanduser()

    def classpath_arg(self) -> str:
        parts = [p for p in self.classpath if p]
        if self.target and (Path(self.target).is_dir() or self.target.endswith(".jar")):
            parts.insert(0, self.target)
        return os.pathsep.join(parts)


def find_config(explicit: str | None = None) -> Path | None:
    candidates = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    env = os.environ.get("JAVA_BRIDGE_CONFIG")
    if env:
        candidates.append(Path(env).expanduser())
    candidates.append(Path.cwd() / "java-bridge.yaml")
    candidates.append(Path.home() / ".config" / "java-bridge" / "java-bridge.yaml")
    for c in candidates:
        if c.is_file():
            return c
    return None


def load_config(explicit: str | None = None) -> BridgeConfig:
    path = find_config(explicit)
    if path is None:
        return BridgeConfig()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    known = {f for f in BridgeConfig.__dataclass_fields__}  # type: ignore[attr-defined]
    kwargs = {k: v for k, v in raw.items() if k in known}
    return BridgeConfig(**kwargs)
