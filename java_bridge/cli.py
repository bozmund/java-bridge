"""java-bridge CLI dispatcher (ghidra-bridge protocol).

Usage:
    java-bridge <command> [args...]

Commands:
    init <target>                 Write a java-bridge.yaml config
    export [all] [--dir DIR]      Export Ghidra-JSON-schema-1 records
    decompile <addr|name>         Decompile one method (CFR)
    asm <addr|name>               Bytecode listing for one method
    search <pattern>              Search class/method names
    xrefs-to <addr|name>          Who calls this method?
    xrefs-from <addr|name>        What does this method call?
    source-struct <class>         Fields of a class (slot indices)
    source-enum <enum>            Enum constants with ordinals
    vtable <class>                Virtual (dispatchable) methods
    global <Class.FIELD>          Static field info
    strings <pattern>             Search string constants
    context <addr|name>           Whole-class decompilation + metadata
    pcode <addr|name>             Normalized bytecode (JSON)
    cfg <addr|name>               Basic-block graph (JSON)
    unimplemented [filter]        Reversible methods (synthetics excluded)
    remaining [filter]            Same as unimplemented
    validate <file> [--method M]  javac build gate for a candidate method
    info                          Target statistics
    list                          List all methods

Targets are synthetic addresses (0x + sha256(class#name+descriptor)[:16]),
``Class::method`` / ``Class.method`` / ``Class#method``, or bare names.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from .config import BridgeConfig, find_config, load_config
from .index import load as load_index


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="java-bridge",
        description="RE backend for Dryxio/reagent: Java classes to decompiled evidence",
    )
    p.add_argument("--config", help="Path to java-bridge.yaml")
    sub = p.add_subparsers(dest="command")

    pi = sub.add_parser("init", help="Write a java-bridge.yaml config")
    pi.add_argument("target", help="Jar, .class file, or class directory")
    pi.add_argument("--classpath", nargs="*", default=[], help="Extra classpath entries")
    pi.add_argument("--out", default="java-bridge.yaml")

    pe = sub.add_parser("export", help="Export Ghidra-JSON records")
    pe.add_argument("type", nargs="?", default="all")
    pe.add_argument("--dir", default="", help="Output directory (default: cache/exports)")

    for cmd in ["decompile", "asm", "search", "xrefs-to", "xrefs-from",
                "source-struct", "source-enum", "vtable", "global",
                "strings", "context", "pcode", "cfg"]:
        c = sub.add_parser(cmd, help=f"{cmd} <target>")
        c.add_argument("target")

    for cmd in ["unimplemented", "remaining"]:
        c = sub.add_parser(cmd, help=f"{cmd} [filter]")
        c.add_argument("filter", nargs="?", default=None)

    pv = sub.add_parser("validate", help="javac build gate for a candidate method")
    pv.add_argument("file")
    pv.add_argument("--method", default=None, help='e.g. "com.foo.Bar::add"')

    sub.add_parser("info")
    sub.add_parser("list")
    return p


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser()
    if not target.exists():
        print(f"error: target not found: {target}")
        return 1
    cfg = BridgeConfig(target=str(target), classpath=list(args.classpath))
    out = Path(args.out)
    if out.exists():
        print(f"error: {out} already exists")
        return 1
    out.write_text(
        yaml.safe_dump(cfg.__dict__, sort_keys=False), encoding="utf-8"
    )
    print(f"wrote {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if not args.command:
        _build_parser().print_help()
        return 1

    if args.command == "init":
        return cmd_init(args)

    cfg = load_config(args.config)
    if not cfg.target:
        print("error: no target configured (run: java-bridge init <jar-or-dir>)")
        return 1

    from . import query

    try:
        idx = load_index(cfg)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", flush=True)
        return 1

    if args.command == "info":
        return query.cmd_info(idx, cfg)
    if args.command == "list":
        return query.cmd_list(idx, None)
    if args.command == "unimplemented":
        return query.cmd_unimplemented(idx, cfg, args.filter)
    if args.command == "remaining":
        return query.cmd_remaining(idx, cfg, args.filter)
    if args.command == "export":
        from .export import export_all

        out_dir = Path(args.dir).expanduser() if args.dir else cfg.cache_path / "exports" / idx.fingerprint[:32]
        return export_all(cfg, idx, out_dir)
    if args.command == "validate":
        from .validate import validate

        return validate(cfg, idx, Path(args.file).expanduser(), args.method)

    return {
        "decompile": lambda: query.cmd_decompile(idx, cfg, args.target),
        "asm": lambda: query.cmd_asm(idx, cfg, args.target),
        "search": lambda: query.cmd_search(idx, args.target),
        "xrefs-to": lambda: query.cmd_xrefs_to(idx, cfg, args.target),
        "xrefs-from": lambda: query.cmd_xrefs_from(idx, cfg, args.target),
        "source-struct": lambda: query.cmd_struct(idx, cfg, args.target),
        "source-enum": lambda: query.cmd_enum(idx, cfg, args.target),
        "vtable": lambda: query.cmd_vtable(idx, cfg, args.target),
        "global": lambda: query.cmd_global(idx, cfg, args.target),
        "strings": lambda: query.cmd_strings(idx, cfg, args.target),
        "context": lambda: query.cmd_context(idx, cfg, args.target),
        "pcode": lambda: query.cmd_pcode(idx, cfg, args.target),
        "cfg": lambda: query.cmd_cfg(idx, cfg, args.target),
    }[args.command]()


if __name__ == "__main__":
    sys.exit(main())
