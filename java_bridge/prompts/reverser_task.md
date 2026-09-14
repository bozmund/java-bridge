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
3. Preserve exact expression/operand order
4. Do not change the method signature; do not add helpers or import statements
5. Output the complete method implementation in a single ``` code block
6. End with: REVERSED_FUNCTION: ${class_name}::${function_name} (${address})
