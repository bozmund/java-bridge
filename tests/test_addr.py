"""Deterministic address scheme: stable, unique per overload, reagent-compatible."""

from java_bridge.addr import ADDR_LEN, method_address, normalize


def test_deterministic():
    a = method_address("com.foo.Bar", "baz", "(I)V")
    assert a == method_address("com.foo.Bar", "baz", "(I)V")
    assert a.startswith("0x")
    assert len(a) == 2 + ADDR_LEN


def test_overloads_differ():
    a = method_address("com.foo.Bar", "baz", "(I)V")
    b = method_address("com.foo.Bar", "baz", "(Ljava/lang/String;)V")
    assert a != b


def test_different_classes_differ():
    assert method_address("com.foo.Bar", "baz", "(I)V") != method_address(
        "com.foo.Baz", "baz", "(I)V"
    )


def test_reagent_normalize_compatible():
    from re_agent.utils.address import normalize_address

    a = method_address("com.foo.Bar", "baz", "(I)V")
    # reagent pads to at least 8; our 16-hex-digit addresses pass through
    assert normalize_address(a) == a[2:]


def test_normalize_roundtrip():
    a = method_address("com.foo.Bar", "baz", "(I)V")
    assert normalize(a) == a[2:]
    assert normalize(a[2:]) == a[2:]
    assert normalize(a.upper()) == a[2:]
