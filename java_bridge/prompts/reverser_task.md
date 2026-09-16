Reverse the following method into clean Java.

**Target:** ${class_name}::${function_name} at ${address}

**Decompilation (derived evidence; may contain decompiler errors):**
```
${decompiled}
```

**Cross-references (calls from this method):**
${xrefs}

**Class fields:**
${structs}

**Whole-class context (other methods visible as signatures/decompiled):**
${source_context}

**Structured reverse-engineering evidence:**
${investigation_context}

**Project-specific rules:**
${project_rules}

Requirements:
1. Match every branch and call from the decompilation/bytecode
2. Map decompiler placeholder names (v0, param_1, ...) to the real field/parameter names where the evidence identifies them
3. **Rename every decompiler-style local variable** (single letters with numeric suffixes: `l`, `l2`, `n`, `n3`, `d`, `d2`, `b`, `s`, `ob`, ...) to a short, meaningful camelCase name derived from how the variable is used in the code (e.g. `l` accumulated from `System.nanoTime()` deltas -> `elapsedNanos`, a loop bound counter -> `sampleCount`). This is always safe: local names have no observable effect. Do NOT leave any such placeholder names in the output. Keep parameters as given unless they are placeholder-style too, in which case rename them the same way (parameter renames are cosmetic and safe).
4. Preserve exact expression/operand order
5. Do not change the method signature (name, parameter types, return type); do not add helpers or import statements
8. If the target is a Java **record** constructor: the canonical constructor (the one whose parameters are exactly the record components) must NOT call super() or this(); other (non-canonical) constructors must begin with `this(...)` delegating to the canonical constructor with the correct argument values — reproduce that delegation exactly from the bytecode evidence (an invokespecial of the record's own <init> is a this(...) call in source, not super()).
6. Output the complete method implementation in a single ``` code block
7. End with: REVERSED_FUNCTION: ${class_name}::${function_name} (${address})
