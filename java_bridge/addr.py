"""Deterministic synthetic addresses for Java methods.

reagent keys all state (session, hooks, reports, candidate overlays) on
``0x``-prefixed hex strings. Java methods have no such addresses, so
java-bridge derives one from the fully-qualified method identity:

    addr = "0x" + sha256(f"{class}#{name}{descriptor}")[:16 hex chars]

Properties:
- deterministic across machines and runs (stable session state),
- distinct per overload (the descriptor is part of the identity),
- 16 hex digits, compatible with re_agent.utils.address.normalize_address.

The mapping is reversible in practice only via the index (``java-bridge
info`` / ``search`` / ``list`` print ``addr  class::method`` lines), which is
the same situation as mangled C++ names in the native tool.
"""

from __future__ import annotations

import hashlib

ADDR_LEN = 16


def method_address(class_name: str, name: str, descriptor: str) -> str:
    """Return the synthetic ``0x`` address for a fully-qualified method."""
    ident = f"{class_name}#{name}{descriptor}"
    return "0x" + hashlib.sha256(ident.encode("utf-8")).hexdigest()[:ADDR_LEN]


def normalize(addr: str) -> str:
    """Normalize an address to lowercase 16 hex digits (no prefix)."""
    a = str(addr).strip().lower()
    if a.startswith("0x"):
        a = a[2:]
    return a.zfill(ADDR_LEN)
