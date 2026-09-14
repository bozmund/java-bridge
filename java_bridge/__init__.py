"""java-bridge: a Ghidra-bridge-protocol RE backend for Dryxio/reagent.

Targets compiled Java classes (.class files, .jar archives, class directories)
and exposes the same query surface reagent expects from a decompiler backend:
decompile, asm (bytecode), xrefs, strings, structs (fields), enums, vtables
(virtual methods), globals (statics), context, pcode (normalized bytecode),
and cfg (basic blocks derived from branch targets).

Java methods have no addresses, so each method gets a deterministic synthetic
address derived from ``class#name+descriptor`` (see :mod:`java_bridge.addr`).
"""

__version__ = "0.1.0"
