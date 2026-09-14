"""Thin wrappers around ``javap`` with parsers for its text output.

Parses the output of ``javap -p -s -c`` (private members, descriptors,
bytecode). JDK 9+ output formats are handled, including the braced
``lookupswitch``/``tableswitch`` blocks and constant-pool reference
comments (``// Method owner.name:desc``).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

from .config import BridgeConfig

CLASS_HEADER_RE = re.compile(
    r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|final|abstract|strictfp|non-sealed|sealed)\s+)*"
    r"(?:class|interface|enum|@interface|record)\s+([\w.$]+)"
)
BC_LINE_RE = re.compile(r"^\s+(\d+): (\w+)(.*)$")
REF_STRING_RE = re.compile(r"String\s+(.*)$")
REF_CLASS_RE = re.compile(r"class\s+([\w/$\[\];.]+)")
INVOKE_OPS = {
    "invokevirtual",
    "invokestatic",
    "invokespecial",
    "invokeinterface",
    "invokedynamic",
}
RETURN_OPS = {"return", "ireturn", "lreturn", "freturn", "dreturn", "areturn"}
BRANCH_OPS = {
    "iflt", "ifle", "ifgt", "ifge", "iflt", "if_icmpeq", "if_icmpne", "if_icmplt",
    "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "ifnull", "ifnonnull", "goto",
}
SWITCH_OPS = {"tableswitch", "lookupswitch"}


@dataclass
class Instr:
    """One bytecode instruction (switch bodies are folded into ``targets``)."""

    offset: int
    opcode: str
    comment: str = ""
    targets: list[int] = field(default_factory=list)  # branch/switch targets
    raw: str = ""  # original javap line (offset + opcode + operands + comment)


@dataclass
class MethodInfo:
    class_name: str
    name: str  # <init> / <clinit> kept verbatim
    descriptor: str  # e.g. (ILjava/lang/String;)V
    modifiers: str
    lines: list[Instr] = field(default_factory=list)
    address: str = ""


@dataclass
class FieldInfo:
    class_name: str
    name: str
    type: str  # Java-style type from javap, e.g. java.lang.String, int[]
    modifiers: str
    descriptor: str = ""
    const_value: str = ""


@dataclass
class ClassInfo:
    class_name: str
    kind: str = "class"  # class | interface | enum | record
    extends: str = ""
    methods: list[MethodInfo] = field(default_factory=list)
    fields: list[FieldInfo] = field(default_factory=list)
    raw: str = ""

    @property
    def is_interface(self) -> bool:
        return self.kind == "interface"

    @property
    def is_enum(self) -> bool:
        return self.kind == "enum"

    @property
    def enum_constants(self) -> list[str]:
        return [f.name for f in self.fields
                if "static" in f.modifiers and f.type == self.class_name]


def run_javap(cfg: BridgeConfig, class_name: str | None, class_file: str | None = None,
              cp: str = "") -> str:
    """Run ``javap -p -s -c`` and return stdout. Raises RuntimeError on failure."""
    cmd = [cfg.javap, "-p", "-s", "-c"]
    cp_arg = cp or cfg.classpath_arg()
    if cp_arg:
        cmd += ["-cp", cp_arg]
    cmd.append(class_file or class_name or "")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=cfg.timeout_s, check=False
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"javap not found: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"javap timed out for {class_name or class_file}") from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"javap failed ({class_name or class_file}): {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout


def _parse_switch_body(lines: list[str], i: int) -> tuple[list[int], int]:
    """Parse a braced lookupswitch/tableswitch body starting at ``lines[i]``.

    Returns (targets, index_after_block). Tolerates both the JDK 9+ braced
    layout and the legacy parenthesized layout.
    """
    targets: list[int] = []
    n = len(lines)
    i += 1
    while i < n:
        s = lines[i].strip()
        if s in ("}", ")") or s.endswith("}") or s.endswith(")"):
            return targets, i + 1
        dm = re.match(r"^default:\s*(\d+)$", s)          # JDK 9+ braced layout
        if dm:
            targets.append(int(dm.group(1)))
            i += 1
            continue
        km = re.match(r"^(-?\d+|\d+ to \d+):\s*(\d+)$", s)  # key or range line
        if km:
            targets.append(int(km.group(2)))
            i += 1
            continue
        lm = re.match(r"^\d+:\s*(default\s+\d+|\d+\s*:\s*\d+)$", s)  # legacy layout
        if lm:
            targets.append(int(lm.group(1).replace(":", " ").split()[-1]))
            i += 1
            continue
        i += 1
    return targets, i


def parse_javap(text: str) -> ClassInfo | None:
    """Parse ``javap -p -s -c`` output into a ClassInfo."""
    hm = None
    header_line = ""
    for line in text.splitlines():
        hm = CLASS_HEADER_RE.match(line)
        if hm:
            header_line = line
            break
    if hm is None:
        return None
    class_name = hm.group(1)
    kind = "class"
    for k in ("interface", "enum", "@interface", "record"):
        if re.search(rf"\b{k}\b", hm.group(0)):
            kind = k
            break
    em = re.search(r"\bextends\s+([\w.$\[\]<>,\s]+?)(?:\s+implements|\s*\{)", header_line)
    extends = em.group(1).strip() if em else ""
    if kind == "class" and extends.startswith("java.lang.Enum"):
        kind = "enum"  # javap prints enums as plain classes extending java.lang.Enum
    info = ClassInfo(class_name=class_name, kind=kind, extends=extends, raw=text)

    lines = text.splitlines()
    cur: MethodInfo | None = None
    field_pending: FieldInfo | None = None
    in_code = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        if cur is not None and in_code and stripped and indent > 2:
            if stripped == "Code:":
                i += 1
                continue
            bm = BC_LINE_RE.match(line)
            if bm:
                offset, opcode, rest = int(bm.group(1)), bm.group(2), bm.group(3)
                comment = rest.split("//", 1)[1].strip() if "//" in rest else ""
                if opcode in SWITCH_OPS:
                    targets, i = _parse_switch_body(lines, i)
                    cur.lines.append(Instr(offset, opcode, comment, targets, line.strip()))
                    continue
                cur.lines.append(Instr(offset, opcode, comment, [], line.strip()))
                i += 1
                continue
            # switch body lines are consumed by _parse_switch_body; anything
            # else unexpected inside code is ignored.
            i += 1
            continue

        # Member level (indent 2) or pre-code lines.
        if stripped == "Code:":
            in_code = cur is not None
            i += 1
            continue

        if indent <= 2:
            in_code = False

        if indent == 2 and stripped:
            if stripped == "static {};":
                cur = MethodInfo(class_name, "<clinit>", "()V", "static")
                info.methods.append(cur)
                field_pending = None
            elif stripped.endswith(");") and "(" in stripped:
                cur = _parse_method_header(class_name, stripped)
                info.methods.append(cur)
                field_pending = None
            elif stripped.endswith(";") and not stripped.endswith("());"):
                fm = re.match(r"^((?:(?:public|protected|private|static|final|transient|volatile|synchronized)\s+)*)((?:[\w$.]+<[^;]+>|[\w$.]+(?:\[\s*\])*)\s+)([\w$]+)\s*;$", stripped)
                if fm:
                    field_pending = FieldInfo(class_name, fm.group(3), fm.group(2).strip(), fm.group(1).strip())
                    info.fields.append(field_pending)
                    cur = None
                else:
                    cur = None
            else:
                cur = None

        if stripped.startswith("descriptor:") and cur is not None:
            cur.descriptor = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("descriptor:") and field_pending is not None:
            field_pending.descriptor = stripped.split(":", 1)[1].strip()
            field_pending = None

        i += 1

    return info


def _parse_method_header(class_name: str, stripped: str) -> MethodInfo:
    """Parse a member header line like ``public int add(int, int);``."""
    body = stripped[:-2]  # drop ');'
    open_idx = body.rindex("(")
    head = body[:open_idx]
    mods_m = re.match(
        r"((?:(?:public|protected|private|static|final|synchronized|native|abstract|default|strictfp)\s+)*)",
        head,
    )
    modifiers = mods_m.group(1).strip() if mods_m else ""
    head_core = head[mods_m.end():] if mods_m else head
    nm = re.search(r"([\w$]+)$", head_core)
    name = nm.group(1) if nm else "?"
    ret_part = head_core[: nm.start() if nm else 0].strip()
    if "$" in class_name:
        top, _, inner = class_name.partition("$")
        simple = top.rsplit(".", 1)[-1] + "$" + inner
    else:
        simple = class_name.rsplit(".", 1)[-1]
    # A ctor header has no return type: head_core is either empty (package-
    # private) or just the package (no space before the name).
    is_ctor = (" " not in head_core) and name in (simple, class_name)
    return MethodInfo(class_name, "<init>" if is_ctor else name, "", modifiers)


def parse_reference(comment: str, current_class: str) -> dict | None:
    """Parse a javap reference comment into a structured ref.

    Returns {"kind": "method"|"field", "class": ..., "name": ..., "desc": ...}
    or None. Comment shapes handled:

        Method owner.name:desc          (fully qualified)
        Method "owner".name:desc        (quoted owner, e.g. array classes)
        Method name:desc                (same-class; owner omitted)
        Method "<init>":desc            (same-class constructor)
        InterfaceMethod owner.name:desc
        Field owner.name:desc / Field name:desc
    """
    if not comment:
        return None
    kind = None
    rest = comment
    for prefix, k in (("InterfaceMethod ", "method"), ("Method ", "method"),
                      ("Field ", "field")):
        if rest.startswith(prefix):
            kind = k
            rest = rest[len(prefix):]
            break
    if kind is None or ":" not in rest:
        return None
    owner_name, desc = rest.rsplit(":", 1)
    if "." in owner_name:
        owner, name = owner_name.rsplit(".", 1)
    else:
        owner, name = "", owner_name
    owner = owner.strip().strip('"')
    name = name.strip().strip('"')
    if not owner:
        owner = current_class
    return {"kind": kind, "class": owner.replace("/", "."), "name": name,
            "desc": desc.strip()}


def extract_string(comment: str) -> str | None:
    """Return the literal if the comment is an ``ldc`` string, else None."""
    if not comment.startswith("String "):
        return None
    return REF_STRING_RE.search(comment).group(1).strip() if REF_STRING_RE.search(comment) else comment[len("String "):]


def referenced_class(comment: str) -> str | None:
    m = REF_CLASS_RE.search(comment)
    return m.group(1).replace("/", ".") if m and "InvokeDynamic" not in comment else None
