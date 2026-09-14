"""Small JVM descriptor/type helpers (no external dependencies)."""

from __future__ import annotations

PRIMITIVE_TYPES: dict[str, str] = {
    "B": "byte",
    "C": "char",
    "D": "double",
    "F": "float",
    "I": "int",
    "J": "long",
    "S": "short",
    "Z": "boolean",
    "V": "void",
}


def parse_type(desc: str) -> str:
    """Parse one descriptor type token into a Java type name.

    ``I`` -> ``int``, ``Ljava/lang/String;`` -> ``java.lang.String``,
    ``[D`` -> ``double[]``, ``[[I`` -> ``int[][]``.
    """
    arrays = 0
    while desc.startswith("["):
        arrays += 1
        desc = desc[1:]
    if desc.startswith("L") and desc.endswith(";"):
        base = desc[1:-1].replace("/", ".")
    else:
        base = PRIMITIVE_TYPES.get(desc, f"unknown<{desc}>")
    return base + "[]" * arrays


def parse_descriptor(desc: str) -> tuple[list[str], str]:
    """Parse a method descriptor into (parameter types, return type).

    ``(ILjava/lang/String;[D)V`` -> (["int", "java.lang.String", "double[]"], "void")
    """
    if not (isinstance(desc, str) and desc.startswith("(")):
        raise ValueError(f"not a method descriptor: {desc!r}")
    close = desc.find(")")
    if close < 0 or close + 1 >= len(desc):
        raise ValueError(f"not a method descriptor: {desc!r}")
    inner = desc[1:close]
    ret = desc[close + 1 :]
    params: list[str] = []
    i = 0
    while i < len(inner):
        start = i
        while inner[i] == "[":
            i += 1
        if inner[i] == "L":
            i = inner.index(";", i) + 1
        else:
            i += 1
        params.append(parse_type(inner[start:i]))
    return params, parse_type(ret)


def java_type_key(type_name: str) -> str:
    """Normalize a Java type name for comparison against descriptor types.

    Keeps the last dot segment plus the array brackets:
    ``java.lang.String`` -> ``String``, ``int[][]`` -> ``int[][]``,
    ``List<String>`` (generics stripped) -> ``List``.
    """
    t = type_name.strip()
    if "<" in t:  # drop generic parameters
        t = t[: t.index("<")]
    return t.rsplit(".", 1)[-1]
