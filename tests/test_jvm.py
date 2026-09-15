"""JVM descriptor parsing."""

import pytest

from java_bridge.jvm import java_type_key, parse_descriptor, parse_type


def test_parse_type():
    assert parse_type("I") == "int"
    assert parse_type("Ljava/lang/String;") == "java.lang.String"
    assert parse_type("[D") == "double[]"
    assert parse_type("[[I") == "int[][]"
    assert parse_type("[Lcom/x/Foo;") == "com.x.Foo[]"


def test_parse_descriptor():
    params, ret = parse_descriptor("(ILjava/lang/String;[D)V")
    assert params == ["int", "java.lang.String", "double[]"]
    assert ret == "void"


def test_parse_descriptor_object_return():
    params, ret = parse_descriptor("()Lcom/example/demo/ScoreKeeper$Rank;")
    assert params == []
    assert ret == "com.example.demo.ScoreKeeper$Rank"


def test_parse_descriptor_empty_params():
    params, ret = parse_descriptor("()V")
    assert params == []
    assert ret == "void"


def test_bad_descriptors():
    with pytest.raises(ValueError):
        parse_descriptor("not-a-descriptor")
    with pytest.raises(ValueError):
        parse_descriptor("(II")  # missing close


def test_java_type_key():
    assert java_type_key("java.lang.String") == "String"
    assert java_type_key("int[][]") == "int[][]"
    assert java_type_key("java.util.List<java.lang.String>") == "List"


def test_java_type_key_inner_class():
    # descriptors write inner classes with '$' while source uses '.';
    # both must normalize to the same key (method_at relies on this)
    assert java_type_key("net.minecraft.world.level.biome.Climate$Sampler") == "Sampler"
    assert java_type_key("Climate.Sampler") == "Sampler"
    desc_params, _ = parse_descriptor(
        "(Lnet/minecraft/world/level/biome/Climate$Sampler;I)Z"
    )
    assert [java_type_key(p) for p in desc_params] == [
        java_type_key("Climate.Sampler"),
        "int",
    ]
