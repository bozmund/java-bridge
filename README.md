# java-bridge

A **Ghidra-bridge-protocol reverse-engineering backend for Java**, built for
[Dryxio/reagent](https://github.com/Dryxio/reagent). Point reagent at a
`.jar`, a `.class` file, or a directory of classes and it reconstructs Java
methods from bytecode + decompilation with the same agentic workflow it uses
for native binaries: evidence gathering, reverser → checker loop, objective
structural verification, and a **real `javac` build gate**.

```
reagent (LLM loop, verification, reports)     ← unchanged
        │  REBackend / ghidra-bridge CLI protocol
        ▼
java-bridge                                   ← this project
  ├─ javap  → method inventory, bytecode, xrefs, strings, fields
  ├─ CFR    → decompilation (whole class, cached; per-method extraction)
  ├─ index  → deterministic synthetic addresses, xref graph (JSON cache)
  ├─ export → Ghidra-JSON-schema-1 records (enables reagent's ghidra-json backend)
  └─ validate → javac build gate for candidate methods
```

## Why a synthetic address?

reagent keys every piece of state (session, reports, candidate overlays,
parity hooks) on `0x…` hex addresses. Java methods don't have addresses, so
java-bridge derives one from the fully-qualified identity:

```
addr = 0x + sha256("com.foo.Bar#add(int)").hexdigest()[:16]
```

Deterministic across runs/machines, unique per overload. `search`/`list`/
`info` always print the `addr  Class::method` mapping.

## Evidence mapping (reagent tool → java-bridge)

| reagent tool      | java-bridge subcommand | what it returns |
|-------------------|------------------------|-----------------|
| decompile         | `decompile`            | CFR source of the method (+ `// Known as:` / `// Signature:` / `Callers: N \| Callees: M` header lines reagent parses) |
| asm               | `asm`                  | `javap -c` bytecode listing |
| pcode             | `pcode`                | normalized bytecode as JSON (`CALL` for `invoke*`, `RETURN`, `BRANCH`…) — feeds reagent's objective verifier |
| cfg               | `cfg`                  | basic-block graph as JSON, derived from real branch/switch targets |
| xrefs_from / to   | `xrefs-from` / `-to`   | caller/callee graph (external calls marked `// external:`) |
| struct            | `source-struct`        | class fields (slot indices, not byte offsets) |
| enum              | `source-enum`          | enum constants with ordinals |
| vtable            | `vtable`               | virtual (dispatchable) methods |
| global            | `global`               | static field type/`ConstantValue` |
| strings           | `strings`              | string constants with the method that loads them |
| context           | `context`              | whole-class decompilation + fields + method signatures |
| unimplemented/remaining | same            | reversible methods (synthetics, enum boilerplate and interface methods excluded) |

## Install

Requirements: Python ≥ 3.10, a JDK (for `javac`/`javap`; anything recent —
developed and tested on OpenJDK 25), and — for reagent integration —
reagent itself. The CFR decompiler jar (~2.5 MB, BSD-licensed) is downloaded
on first use to `~/.cache/java-bridge/decompiler/` (or pin `cfr_jar:` in the
config).

```sh
cd java-bridge
uv venv .venv
uv pip install -e '.[dev]'            # includes auto-re-agent from PyPI… or:
uv pip install -e /path/to/Dryxio/reagent   # from a local clone
.venv/bin/python -m pytest tests      # 34 tests; needs the JDK
```

## Quick start (standalone)

```sh
cd examples/demo && javac -d classes src/com/example/demo/*.java
java-bridge init classes                     # writes java-bridge.yaml
java-bridge info
java-bridge search ScoreKeeper
ADDR=$(java-bridge search rankOf | awk '{print $1}')
java-bridge decompile $ADDR
java-bridge xrefs-to $ADDR
java-bridge pcode $ADDR
java-bridge cfg $ADDR
java-bridge source-enum com.example.demo.ScoreKeeper.Rank
```

## Wiring into reagent

Two equivalent backend types work — CLI (default, no pre-export) or JSON
(after `java-bridge export all`):

```yaml
# reagent.yaml — CLI backend (run reagent from the dir holding java-bridge.yaml)
backend:
  type: ghidra-bridge
  cli_path: java-bridge
  timeout_s: 180

validation:
  enabled: true
  require_build: true
  trust_configured_commands: true
  build_commands:
    - "java-bridge validate {candidate_file}"

parity:
  enabled: false            # the parity engine is C-oriented; see Limitations
```

or:

```sh
java-bridge export all --dir exports
```

```yaml
backend:
  type: ghidra-json
  export_dir: exports
  address_map: exports/address_map.json
```

Run reagent through the **`reagent-java`** launcher, which swaps in the
Java prompt templates and teaches the code extractor about ```java fences —
no reagent source is modified:

```sh
reagent-java --config reagent.yaml reverse --address $ADDR
reagent-java --config reagent.yaml reverse --class com.example.demo.ScoreKeeper
reagent-java --config reagent.yaml doctor
```

`reagent-java` also sets `JAVA_BRIDGE_PROMPTS`-respectable overrides:
point `JAVA_BRIDGE_PROMPTS` at a directory of modified templates to tweak
behavior without code changes.

### The build gate

`java-bridge validate {candidate_file}` is the Java analogue of reagent's
C++ build gate. It infers the target method from the candidate filename
(`com_example_demo_ScoreKeeper_rankOf.cpp` — reagent's naming convention)
or signature, then:

1. decompiles the **original** class with CFR,
2. splices the candidate method in place of the original,
3. compiles with `javac` against the original classpath,
4. re-reads the compiled class and verifies the method descriptor is
   unchanged.

Pass = the candidate type-checks against the real signatures of everything
it touches. If the CFR output itself is broken (CFR happens to fail on
some constructs), a stub-class fallback (fields from `javap`, other methods
stubbed) is attempted.

## Limitations / known issues

- **CFR 0.152 omits default no-arg constructors** (field initializers are
  hoisted to the field declarations). For those, `decompile` falls back to
  the bytecode listing (marked with a `// NOTE:` line) and `validate` uses
  the stub-class path.
- The **parity engine** (reagent's 11-signal C++-oriented engine, clang
  indexing, x86 FP signals) is disabled for Java (`parity.enabled: false`).
  The objective verifier, checker loop, and build gate all work; parity for
  Java is a follow-up.
- `invokedynamic` (lambdas, string concatenation) is reported as
  `INVOKE_DYNAMIC`, not counted as a `CALL` in the pcode evidence.
- Interface methods, enum boilerplate (`values`/`valueOf`/synthetic ctor),
  `lambda$`/`access$` synthetics and `<clinit>` are excluded from
  `unimplemented`/`remaining` (there is no bytecode to reverse, or it is
  compiler-generated).
- The stub-class fallback for `validate` is not supported for enums.
- Records: decompilation works; their compiler-generated `equals`/`hashCode`
  are reversible but usually pointless (they are in the inventory).

## Layout

```
java_bridge/            the CLI backend (protocol-compatible with ghidra-bridge)
  addr.py               synthetic address scheme
  javap.py              javap wrappers + bytecode/reference parsers
  index.py              method inventory, xref graph, JSON cache
  decompile.py          CFR integration, per-method extraction
  query.py              reagent-protocol output formats
  validate.py           javac build gate
  export.py             Ghidra-JSON-schema-1 exports
  prompts/              Java reverser/checker/fix templates (same $vars as reagent)
reagent_java/           the reagent-java launcher (prompt + fence overrides)
examples/demo/          3-class demo + ready-made reagent.yaml
tests/                  34 tests incl. round-trips through reagent's own parsers
```

## License

MIT. Delegates to CFR (BSD-3) and the JDK's `javap`/`javac`.
