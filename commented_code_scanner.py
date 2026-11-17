#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Commented Code & Secrets Scanner  (standalone, rule-based, no AI, no network)
=============================================================================

What it does
------------
* Asks for a project folder (GUI) and walks it (handles 1M+ lines of code).
* Language-aware comment extraction for Java, JSP, HTML, JS/TS, Ruby, Python
  (+ optional Kotlin/Scala/Groovy, PHP, C/C++/C#/Go, CSS, SQL, XML, YAML,
  .properties, Shell).  String-aware, so "http://..." inside a string is not
  mistaken for a comment.
* Finds COMMENTED-OUT CODE using a heuristic scoring engine (syntax signals,
  prose penalties) plus a real Python `ast` parse check for Python comments.
* Flags every comment that contains an ID / password / token / key / PII as
  HIGH.  Uses pattern rules, name analysis (dbPassword, api_key ...),
  placeholder filtering, entropy checks and checksum validation
  (Luhn for cards, Verhoeff for Aadhaar, mod-97 for IBAN).
* Writes an Excel report: Summary, High Risk, All Findings, File-wise,
  Package-wise (+ Skipped files).  Secret values are MASKED by default.

Requirements:  Python 3.8+  and  `pip install openpyxl`   (tkinter ships with Python)
Run GUI:       python commented_code_scanner.py
Run headless:  python commented_code_scanner.py --cli <project_path> -o report.xlsx
Make an .exe:  pip install pyinstaller
               pyinstaller --onefile --windowed commented_code_scanner.py
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import io
import math
import multiprocessing
import os
import platform
import queue
import re
import subprocess
import sys
import textwrap
import threading
import time
import tokenize
import traceback
from collections import Counter, defaultdict
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from datetime import datetime

try:  # GUI is optional (CLI mode works without it)
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except Exception:  # pragma: no cover
    tk = None

APP_NAME = "Commented Code & Secrets Scanner"
VERSION = "1.0"

# ----------------------------------------------------------------------------
# Language configuration
# ----------------------------------------------------------------------------
# ext -> (display language, comment-syntax family)
EXT_MAP = {
    "java": ("Java", "c"), "kt": ("Kotlin", "c"), "kts": ("Kotlin", "c"),
    "scala": ("Scala", "c"), "groovy": ("Groovy", "c"), "gradle": ("Groovy", "c"),
    "js": ("JavaScript", "c"), "jsx": ("JavaScript", "c"), "mjs": ("JavaScript", "c"),
    "ts": ("TypeScript", "c"), "tsx": ("TypeScript", "c"),
    "c": ("C", "c"), "h": ("C", "c"), "cpp": ("C++", "c"), "cc": ("C++", "c"),
    "hpp": ("C++", "c"), "cs": ("C#", "c"), "go": ("Go", "c"), "swift": ("Swift", "c"),
    "php": ("PHP", "php"),
    "jsp": ("JSP", "jsp"), "jspf": ("JSP", "jsp"), "jspx": ("JSP", "jsp"), "tag": ("JSP", "jsp"),
    "html": ("HTML", "html"), "htm": ("HTML", "html"), "xhtml": ("HTML", "html"),
    "vm": ("HTML", "html"), "ftl": ("HTML", "html"),
    "xml": ("XML", "xml"),
    "css": ("CSS", "css"),
    "py": ("Python", "python"),
    "rb": ("Ruby", "ruby"), "rake": ("Ruby", "ruby"),
    "sql": ("SQL", "sql"),
    "sh": ("Shell", "hash"), "yml": ("YAML", "hash"), "yaml": ("YAML", "hash"),
    "properties": ("Properties", "props"),
}

# GUI groups: name -> (extensions, enabled by default)
EXT_GROUPS = {
    "Java": (["java"], True),
    "JSP": (["jsp", "jspf", "jspx", "tag"], True),
    "HTML": (["html", "htm", "xhtml"], True),
    "JavaScript / TypeScript": (["js", "jsx", "mjs", "ts", "tsx"], True),
    "Ruby": (["rb", "rake"], True),
    "Python": (["py"], True),
    "Kotlin / Scala / Groovy": (["kt", "kts", "scala", "groovy", "gradle"], False),
    "PHP": (["php"], False),
    "C / C++ / C# / Go": (["c", "h", "cpp", "cc", "hpp", "cs", "go"], False),
    "XML / .properties / YAML": (["xml", "properties", "yml", "yaml"], False),
    "SQL": (["sql"], False),
    "CSS": (["css"], False),
    "Shell": (["sh"], False),
}

DEFAULT_EXCLUDE_DIRS = (".git,.svn,.hg,node_modules,target,build,dist,out,__pycache__,"
                        ".idea,.vscode,.gradle,.mvn,venv,.venv,bower_components")
DEFAULT_EXCLUDE_FILES = "*.min.js,*.min.css,*-min.js"

# ----------------------------------------------------------------------------
# Comment extraction
# ----------------------------------------------------------------------------
# Every regex matches strings (skipped) and comments in a single pass, so a
# "//" or "#" inside a string literal is never reported as a comment.
C_RX = re.compile(r'''
    (?P<lc>//[^\n]*)
  | (?P<bc>/\*.*?(?:\*/|\Z))
  | (?P<str>"""[\s\S]*?"""|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)
''', re.S | re.X)
PHP_RX = re.compile(r'''
    (?P<lc>(?://|\#(?!\[))[^\n]*)
  | (?P<bc>/\*.*?(?:\*/|\Z))
  | (?P<str>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')
''', re.S | re.X)
CSS_RX = re.compile(r'''
    (?P<bc>/\*.*?(?:\*/|\Z))
  | (?P<str>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')
''', re.S | re.X)
SQL_RX = re.compile(r'''
    (?P<lc>--[^\n]*)
  | (?P<bc>/\*.*?(?:\*/|\Z))
  | (?P<str>'(?:''|[^'])*')
''', re.S | re.X)
RUBY_RX = re.compile(r'''
    (?P<bc>^=begin\b.*?^=end\b[^\n]*)
  | (?P<lc>\#[^\n]*)
  | (?P<str>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
''', re.S | re.M | re.X)
HASH_RX = re.compile(r'''
    (?P<lc>(?:^|(?<=[ \t]))\#[^\n]*)
  | (?P<str>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')
''', re.M | re.X)
PROPS_RX = re.compile(r'(?P<lc>^[ \t]*[#!][^\n]*)', re.M)

HTML_CMT = re.compile(r'<%--.*?--%>|<!--.*?-->', re.S)
SCRIPT_RX = re.compile(r'(<script\b[^>]*>)(.*?)(</script\s*>)', re.S | re.I)
STYLE_RX = re.compile(r'(<style\b[^>]*>)(.*?)(</style\s*>)', re.S | re.I)
SCRIPTLET_RX = re.compile(r'<%(?![-@])(.*?)%>', re.S)

_LINE_MARK = re.compile(r'^(?:/{2,}|#+|-{2,}|!+)\s?')


def _clean_block(g):
    body = g[2:]
    if body.endswith("*/"):
        body = body[:-2]
    lines = body.split("\n")
    out = [lines[0].lstrip("*").strip()]
    for ln in lines[1:]:
        out.append(re.sub(r"^\s*\*(?!/)\s?", "", ln).rstrip())
    return "\n".join(out).strip("\n")


def scan_tokens(text, rx, base_line=0):
    """Return [(start_line, end_line, kind, inline, text)] (1-based lines)."""
    out, pos, line = [], 0, base_line
    for m in rx.finditer(text):
        k = m.lastgroup
        if k == "str":
            continue
        s = m.start()
        line += text.count("\n", pos, s)
        pos = s
        g = m.group()
        ls = text.rfind("\n", 0, s) + 1
        inline = bool(text[ls:s].strip())
        if k == "lc":
            out.append((line + 1, line + 1, "line", inline, _LINE_MARK.sub("", g).rstrip()))
        else:
            n = g.count("\n")
            if g.startswith("=begin"):
                kind, txt = "block", "\n".join(g.split("\n")[1:-1])
            else:
                kind = "doc" if g.startswith("/**") and not g.startswith("/**/") else "block"
                txt = _clean_block(g)
            out.append((line + 1, line + 1 + n, kind, inline, txt))
    return out


def scan_markup(text, family):
    out, pos, line = [], 0, 0
    for m in HTML_CMT.finditer(text):
        g = m.group()
        s = m.start()
        line += text.count("\n", pos, s)
        pos = s
        if g.startswith("<%--"):
            body, kind = g[4:-4], "jsp"
        else:
            body, kind = g[4:-3], "markup"
            b = body.strip()
            if b.startswith(("[if", "<![endif")) or b.endswith("<!"):
                continue  # IE conditional comments are not code
        ls = text.rfind("\n", 0, s) + 1
        inline = bool(text[ls:s].strip())
        out.append((line + 1, line + 1 + g.count("\n"), kind, inline, body.strip("\n")))

    def blank(m):
        return re.sub(r"[^\n]", " ", m.group())

    masked = HTML_CMT.sub(blank, text)
    if family in ("html", "jsp"):
        for rx, crx in ((SCRIPT_RX, C_RX), (STYLE_RX, CSS_RX)):
            for m in rx.finditer(masked):
                seg = m.group(2)
                if "/" in seg:
                    out += scan_tokens(seg, crx, masked.count("\n", 0, m.start(2)))
            masked = rx.sub(blank, masked)
    if family == "jsp":
        for m in SCRIPTLET_RX.finditer(masked):
            seg = m.group(1)
            if "/" in seg:
                out += scan_tokens(seg, C_RX, masked.count("\n", 0, m.start(1)))
    return out


def scan_python(text):
    out = []
    try:
        for t in tokenize.generate_tokens(io.StringIO(text).readline):
            if t.type == tokenize.COMMENT:
                row, col = t.start
                out.append((row, row, "line", bool(t.line[:col].strip()),
                            re.sub(r"^#+ ?", "", t.string).rstrip()))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return scan_tokens(text, HASH_RX)  # Python 2 / broken file: regex fallback
    # bare string statements that are not docstrings = often "commented out" code
    try:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if not isinstance(body, list):
                continue
            is_doc_owner = isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            for i, st in enumerate(body):
                if (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant)
                        and isinstance(st.value.value, str) and not (i == 0 and is_doc_owner)):
                    out.append((st.lineno, getattr(st, "end_lineno", st.lineno), "string", False,
                                textwrap.dedent(st.value.value)))
    except Exception:
        pass
    return out


def merge_line_comments(items):
    items.sort(key=lambda x: (x[0], x[1]))
    out = []
    for it in items:
        if out and it[2] == "line" and not it[3]:
            p = out[-1]
            if p[2] == "line" and not p[3] and it[0] == p[1] + 1:
                out[-1] = (p[0], it[0], "line", False, p[4] + "\n" + it[4])
                continue
        out.append(it)
    return out


def extract_comments(text, family):
    if family == "c":
        items = scan_tokens(text, C_RX)
    elif family == "php":
        items = scan_tokens(text, PHP_RX)
    elif family == "css":
        items = scan_tokens(text, CSS_RX)
    elif family == "sql":
        items = scan_tokens(text, SQL_RX)
    elif family in ("html", "jsp", "xml"):
        items = scan_markup(text, family)
    elif family == "python":
        items = scan_python(text)
    elif family == "ruby":
        items = scan_tokens(text, RUBY_RX)
    elif family == "props":
        items = scan_tokens(text, PROPS_RX)
    else:
        items = scan_tokens(text, HASH_RX)
    return merge_line_comments(items)


# ----------------------------------------------------------------------------
# "Is this commented-out code?"  -- heuristic scoring engine
# ----------------------------------------------------------------------------
SEP_RX = re.compile(r"^[\-=*#~_/\\+.\s]{3,}$")
ASSIGN_RX = re.compile(r"^\s*(?:[A-Za-z_][\w<>\[\],.\s]*\s+)?[A-Za-z_$@][\w.\[\]$\"']*\s*(?:[-+*/%|&^]|\|\||&&)?=(?!=)\s*\S")
CALL_END_RX = re.compile(r"[\w$]\([^()]*\)?\s*[;{]?\s*$")
METHOD_CALL_RX = re.compile(r"[\w)\]]\.[A-Za-z_]\w*\(")
OPS_RX = re.compile(r"==|!=|&&|\|\||=>|->|<=|>=|\+\+|--|::|\+=|-=")
KW_START_RX = re.compile(r"^\s*(?:if|else|elif|for|foreach|while|do|switch|case|try|catch|except|finally|return|throw|"
                         r"import|from\s+\S+\s+import|package|def|class|interface|function|public|private|protected|"
                         r"static|final|var|let|const|require|include|using|puts|print|echo|System\.out|console\.|"
                         r"log\.|logger\.|end|begin|unless|elsif|rescue|self\.|this\.)\b")
SYMS_RX = re.compile(r"[;{}()=<>\[\]]")
PY_BLOCK_RX = re.compile(r"^\s*(?:def|class|if|elif|else|for|while|try|except|finally|with)\b.*:\s*$")
TAG_RX = re.compile(r"^\s*</?[A-Za-z][\w:\-]*(?:\s[^>]*)?/?>")
ANNOT_RX = re.compile(r"^\s*@[A-Z]\w+(?:\(.*\))?\s*$")
DEF_RX = re.compile(r"^\s*(?:def|class|module|function|func|fun)\s+[\w.:]+")
STMT_RX = re.compile(r"^\s*(?:puts|print|echo|return|raise|throw|yield)\s+\S")
PROSE_RX = re.compile(r"^[A-Z][a-z']+(?:\s+[\w',()\-/]+){3,}[.:!?]?$")
STOP_RX = re.compile(r"\b(?:the|is|are|this|that|which|should|will|because|please|note|used|when|then|also|"
                     r"we|you|it|be|to|of|and|or|not|for|with|from|has|have|was|if)\b", re.I)
LICENSE_RX = re.compile(r"(?i)copyright|\(c\)\s*\d{4}|licen[cs]e[sd]?\b.*\b(?:under|apache|mit|gpl|bsd)|"
                        r"all rights reserved|spdx-license|permission is hereby granted|without warranty")
DIRECTIVE_RX = re.compile(r"(?i)^\s*(?:noinspection|eslint|prettier-ignore|noqa|pylint:|type:\s*ignore|pragma\b|"
                          r"@formatter|checkstyle|nosonar|nosec|istanbul|jshint|jslint|global\s+\w|-\*-|coding[:=]|"
                          r"!/|<editor-fold|</editor-fold|region\b|endregion\b|sourceMappingURL|@ts-|@suppress|"
                          r"suppresswarnings|fmt:|nolint|lint:|rubocop:|frozen_string_literal|encoding:|vim:|mode:)")
MARKER_RX = re.compile(r"(?i)^\s*(?:todo|fixme|hack|xxx|bug|note|optimi[sz]e|review|temp)\b")


def line_score(s, markup):
    s = s.strip()
    if not s or SEP_RX.match(s):
        return None
    sc = 0.0
    if s.endswith(";") or s.endswith("{") or s.endswith("}"):
        sc += 2
    elif s in (")", ");", "]", "},", "),", "})", "});", "end"):
        sc += 2
    if PY_BLOCK_RX.match(s):
        sc += 2
    if ASSIGN_RX.match(s):
        sc += 1.5
    if CALL_END_RX.search(s):
        sc += 2
    elif METHOD_CALL_RX.search(s):
        sc += 1.5
    if OPS_RX.search(s):
        sc += 1
    if KW_START_RX.match(s):
        sc += 1.5 if SYMS_RX.search(s) else 0.3
    if DEF_RX.match(s):
        sc += 2
    if STMT_RX.match(s) and SYMS_RX.search(s) or re.match(r"^\s*(?:puts|print|echo|raise|throw)\s+[\w\"'\[{(:@$]", s) and not PROSE_RX.match(s) and len(s.split()) <= 3:
        sc += 1.5
    if TAG_RX.match(s):
        sc += 3 if markup else 1.2
    if ANNOT_RX.match(s):
        sc += 2
    words = s.split()
    if len(words) >= 4 and not SYMS_RX.search(s):
        sc -= 2
    elif PROSE_RX.match(s):
        sc -= 2.5
    if len(STOP_RX.findall(s)) >= 3:
        sc -= 2
    return sc


def py_parses(text):
    try:
        tree = ast.parse(textwrap.dedent(text))
    except Exception:
        return False
    for n in tree.body:
        if isinstance(n, ast.Expr) and isinstance(n.value, (ast.Name, ast.Constant, ast.Attribute)):
            continue
        if isinstance(n, ast.AnnAssign) and n.value is None:
            continue
        return True
    return False


def classify(text, family, kind):
    """-> (category, confidence %, reason)"""
    st = text.strip()
    if not st:
        return "Empty", 0, ""
    is_py = family == "python"
    if is_py and py_parses(text):
        return "Commented Code", 95, "Parses as valid Python"
    if LICENSE_RX.search(st[:500]):
        return "License", 0, ""
    if DIRECTIVE_RX.match(st):
        return "Directive", 0, ""
    if kind == "doc":
        return "Documentation", 0, ""
    markup = family in ("html", "jsp", "xml") or kind in ("markup", "jsp")
    scores = [x for x in (line_score(l, markup) for l in text.split("\n")) if x is not None]
    n = len(scores)
    if n == 0:
        return "Plain Comment", 0, ""
    strong = sum(1 for x in scores if x >= 2)
    weak = sum(1 for x in scores if 1 <= x < 2)
    ratio = (strong + 0.5 * weak) / n
    conf = int(min(99, ratio * 100))
    if n == 1:
        if scores[0] >= 3:
            return "Commented Code", max(conf, 80), "Strong code syntax"
        if scores[0] >= 2:
            return "Possible Code", 60, "Some code syntax"
    else:
        if ratio >= 0.5 and strong >= 1:
            return "Commented Code", conf, f"{strong} of {n} lines look like code"
        if ratio >= 0.3 and (strong + weak) >= 1:
            return "Possible Code", conf, f"{strong + weak} of {n} lines look like code"
    if MARKER_RX.match(st):
        return "Marker", 0, ""
    return "Plain Comment", 0, ""


# ----------------------------------------------------------------------------
# Sensitive-data detection (rule based)
# ----------------------------------------------------------------------------
PREFILTER = re.compile(r"(?i)pass|pwd|secret|token|key|auth|bearer|cred|user|login|uid|empid|@|\d{9,}|"
                       r"\d{4}[ -]\d{4}|BEGIN|AKIA|ASIA|eyJ|://|ssn|aadh|dob|birth|card|cvv|cvc|iban|mobile|"
                       r"phone|jdbc|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[A-Z]{5}\d{4}|account|passport")


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def luhn_ok(num):
    t, alt = 0, False
    for ch in reversed(num):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        t += d
        alt = not alt
    return t % 10 == 0


_VD = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
       [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
       [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
       [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VP = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
       [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
       [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_ok(num):
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VD[c][_VP[i % 8][int(ch)]]
    return c == 0


def iban_ok(v):
    v = re.sub(r"\s", "", v)
    if not 15 <= len(v) <= 34:
        return False
    r = v[4:] + v[:4]
    return int("".join(str(int(c, 36)) for c in r)) % 97 == 1


def _digits(v):
    return re.sub(r"\D", "", v)


def _line_of(text, s):
    a = text.rfind("\n", 0, s) + 1
    b = text.find("\n", s)
    return text[a: b if b != -1 else len(text)]


FAKE_DOMAINS = {"example.com", "example.org", "domain.com", "test.com", "email.com", "company.com",
                "yourcompany.com", "mydomain.com", "localhost", "foo.com", "bar.com", "abc.com", "xyz.com", "sample.com"}


def v_email(v, text, s, e):
    if v.split("@")[-1].lower() in FAKE_DOMAINS:
        return False
    ln = _line_of(text, s).strip().lower().lstrip("*/#- ")
    return not ln.startswith(("@author", "author", "@contact", "maintainer", "copyright", "(c)", "@since", "@see"))


def v_card(v, text, s, e):
    d = _digits(v)
    return 13 <= len(d) <= 19 and d[0] in "3456" and len(set(d)) > 3 and luhn_ok(d)


def v_aadhaar(v, text, s, e):
    d = _digits(v)
    return len(d) == 12 and len(set(d)) > 2 and verhoeff_ok(d)


def v_pan(v, text, s, e):
    return v[3] in "PCHFATBLJG"


def v_iban(v, text, s, e):
    try:
        return iban_ok(v)
    except ValueError:
        return False


PHONE_CTX = re.compile(r"(?i)\b(?:mobile|phone|ph|contact|cell|mob|tel|call|whatsapp|msisdn|sms)\b")


def v_phone10(v, text, s, e):
    return bool(PHONE_CTX.search(text))


def v_phone_intl(v, text, s, e):
    return 10 <= len(_digits(v)) <= 15


def v_ip(v, text, s, e):
    return all(int(x) <= 255 for x in v.split("."))


# (label, category, severity, regex, group, validator)
DIRECT_RULES = [
    ("Private Key", "Token/Key/Secret", "High",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,4000}?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)", 0, None),
    ("AWS Access Key", "Token/Key/Secret", "High", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0, None),
    ("Google API Key", "Token/Key/Secret", "High", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0, None),
    ("GitHub Token", "Token/Key/Secret", "High", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 0, None),
    ("Slack Token", "Token/Key/Secret", "High", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", 0, None),
    ("Stripe Key", "Token/Key/Secret", "High", r"\b[sr]k_live_[0-9a-zA-Z]{16,}", 0, None),
    ("JWT", "Token/Key/Secret", "High", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*", 0, None),
    ("Bearer/Basic Auth Header", "Token/Key/Secret", "High", r"\b(?:Bearer|Basic)\s+([A-Za-z0-9\-._~+/]{16,}=*)", 1, None),
    ("Credentials in URL", "Credential/Password", "High", r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@\"']+:([^\s/@\"']+)@", 1, None),
    ("Password (setter/compare)", "Credential/Password", "High",
     r"(?i)\b(?:set(?:Password|Passwd|Pwd)|\w*(?:password|passwd|pwd)\w*(?:\(\))?\s*\.\s*equals(?:IgnoreCase)?)\s*\(\s*\"([^\"\n]{2,100})\"", 1, None),
    ("DB User (getConnection)", "Identifier", "High", r"getConnection\s*\([^,()]+,\s*\"([^\"\n]+)\"\s*,\s*\"[^\"\n]*\"", 1, None),
    ("DB Password (getConnection)", "Credential/Password", "High", r"getConnection\s*\([^,()]+,\s*\"[^\"\n]*\"\s*,\s*\"([^\"\n]+)\"", 1, None),
    ("Email", "PII", "High", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b", 0, v_email),
    ("Credit/Debit Card No.", "PII", "High", r"(?<![\d\-])(?:\d[ \-]?){12,18}\d(?![\d\-])", 0, v_card),
    ("Aadhaar No.", "PII", "High", r"(?<![\d\-])[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}(?![\d\-])", 0, v_aadhaar),
    ("PAN No.", "PII", "High", r"\b[A-Z]{5}\d{4}[A-Z]\b", 0, v_pan),
    ("US SSN", "PII", "High", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", 0, None),
    ("IBAN", "PII", "High", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", 0, v_iban),
    ("Phone (intl)", "PII", "High", r"(?<![\w+])\+\d{1,3}[\s\-]?(?:\(?\d{2,5}\)?[\s\-]?){2,4}\d{2,4}(?!\d)", 0, v_phone_intl),
    ("Phone (10-digit)", "PII", "High", r"(?<![\d.\-])[6-9]\d{9}(?![\d.\-])", 0, v_phone10),
    ("DB Connection String", "Infrastructure", "Medium", r"\bjdbc:[a-z0-9]+:[^\s\"']+", 0, None),
    ("Private IP address", "Infrastructure", "Medium",
     r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b", 0, v_ip),
]
DIRECT_RULES = [(a, b, c, re.compile(d), g, v) for (a, b, c, d, g, v) in DIRECT_RULES]

_VAL = (r"""(?:"(?P<dq>[^"\n]{1,200})"|'(?P<sq>[^'\n]{1,200})'|(?P<bare>[^\s"'`,;)\]}<>]{1,200}))""")
KV_RX = re.compile(r"""(?P<name>[A-Za-z_][\w\-.]{0,60})["'\]]?[ \t]*(?P<op>=>|:=|==|=|:)[ \t]*""" + _VAL)
XML_RX = re.compile(r"<(?P<name>[A-Za-z_][\w\-.]{0,40})(?:\s[^>]*)?>[ \t]*(?P<dq>[^<\n]{1,200}?)[ \t]*</(?P=name)>")

PASS_W = {"password", "passwd", "pwd", "pass", "passphrase", "passcode", "pswd"}
SECRET_W = {"secret", "token", "apikey", "bearer", "credential", "credentials", "jsessionid", "sessionid",
            "authkey", "accesskey", "secretkey", "privatekey", "auth", "authorization"}
KEY_PFX = {"api", "access", "secret", "private", "encryption", "encrypt", "signing", "license", "aes", "rsa",
           "master", "client", "app", "shared", "auth", "crypto", "session", "hmac", "jwt"}
NOISE_W = {"type", "url", "uri", "endpoint", "header", "expiry", "expires", "expiration", "ttl", "length", "size",
           "count", "timeout", "max", "min", "file", "path", "field", "param", "prefix", "label", "placeholder",
           "hint", "required", "validator", "policy", "pattern", "regex", "mask", "encoder", "format", "class"}
PLACEHOLDER_RX = re.compile(r"(?i)^(?:x+|\*+|\.+|-+|_+|\?+|<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|#\{.*\}|your[_\- ]?.*|"
                            r"change[_\-]?me|placeholder|example|redacted|null|nil|none|undefined|true|false|"
                            r"string|password|passwd|pwd|secret|token|key|value|enter.*|empty|blank|todo|tbd|n/?a)$")
DOTTED_KEY_RX = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
UPPER_CONST_RX = re.compile(r"^[A-Z]+(?:_[A-Z0-9]+)+$")
WORD_SPLIT = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


def classify_name(name):
    w = [x.lower() for x in WORD_SPLIT.findall(name)]
    if not w:
        return None
    ws = set(w)
    if ws & NOISE_W:
        return None
    if ws & PASS_W:
        return ("Password", "Credential/Password", "pass")
    if ws & SECRET_W:
        return ("Token/Secret", "Token/Key/Secret", "secret")
    if "key" in ws:
        if ws & KEY_PFX:
            return ("API/Crypto Key", "Token/Key/Secret", "secret")
        if len(w) == 1:
            return ("Key", "Token/Key/Secret", "strict")
        return None
    if (("user" in ws and ws & {"id", "name", "login"}) or ws & {"uid", "userid", "username", "loginid", "loginname", "empid", "uname"}
            or ("login" in ws and ws & {"id", "name"}) or ws == {"login"} or ws == {"user"}
            or (ws & {"emp", "employee", "customer", "account", "acct", "client", "member"} and ws & {"id", "no", "number", "num"})):
        return ("User/Account ID", "Identifier", "id")
    if ws & {"ssn", "aadhaar", "aadhar", "passport", "cvv", "cvc", "iban", "dob", "pan"} or \
            ("birth" in ws and ws & {"date", "day"}) or ("card" in ws and ws & {"number", "no", "num"}) or \
            ("credit" in ws and "card" in ws):
        return ("PII (" + "_".join(w) + ")", "PII", "pii:" + ("pan" if "pan" in ws else "num"))
    if ws & {"email", "mail"}:
        return ("PII (email)", "PII", "email")
    if ws & {"phone", "mobile", "msisdn", "cell", "contact"}:
        return ("PII (phone)", "PII", "phone")
    return None


def plausible(val, quoted, mode):
    v = val.strip()
    if not v or PLACEHOLDER_RX.match(v) or DOTTED_KEY_RX.match(v) or UPPER_CONST_RX.match(v):
        return False
    if "(" in v or v.startswith(("$", "{", "%", "<", "@")):
        return False
    if quoted and v.count(" ") >= 2:
        return False
    if not quoted:
        if v.isalpha() or re.match(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$", v):
            return False
    if mode == "pass":
        return len(v) >= 3 if quoted else bool(re.search(r"[\d\W]", v)) and len(v) >= 4
    if mode == "secret":
        return len(v) >= 6 and (re.search(r"[\d\W]", v) is not None or (len(v) >= 8 and entropy(v) >= 2.5))
    if mode == "strict":
        return len(v) >= 12 and " " not in v and entropy(v) >= 3.0
    if mode == "id":
        return len(v) >= 2 and (quoted or re.search(r"\d", v) is not None) and v.count(" ") <= 1
    if mode == "email":
        return "@" in v and "." in v and v.split("@")[-1].lower() not in FAKE_DOMAINS
    if mode == "phone":
        return len(_digits(v)) >= 7
    if mode.startswith("pii"):
        if mode.endswith("pan"):
            return re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", v) is not None
        return len(_digits(v)) >= 4
    return False


def mask_val(v):
    if len(v) <= 6:
        return "*" * max(len(v), 3)
    return v[:2] + "*" * min(len(v) - 3, 10) + v[-1]


def detect_sensitive(text, category):
    """-> list of (rule, category, severity, start, end)"""
    hits = []
    if not PREFILTER.search(text):
        return hits
    skip_pii = category == "License"
    for label, cat, sev, rx, g, val in DIRECT_RULES:
        if skip_pii and cat == "PII":
            continue
        for m in rx.finditer(text):
            if val and not val(m.group(g), text, m.start(g), m.end(g)):
                continue
            hits.append((label, cat, sev, m.start(g), m.end(g)))
            if len(hits) > 40:
                return hits
    for rx in (KV_RX, XML_RX):
        for m in rx.finditer(text):
            name = m.group("name")
            if rx is KV_RX and text[max(0, m.start() - 3): m.start()].endswith("://"):
                continue
            cn = classify_name(name)
            if not cn:
                continue
            label, cat, mode = cn
            if skip_pii and cat == "PII":
                continue
            dq, sq = m.group("dq"), m.groupdict().get("sq")
            bare = m.groupdict().get("bare")
            val = dq or sq or bare
            if not val:
                continue
            quoted = bare is None
            if plausible(val, quoted, mode):
                grp = "dq" if dq else ("sq" if sq else "bare")
                hits.append((label, cat, "High", m.start(grp), m.end(grp)))
    # de-duplicate overlapping hits
    seen, out = set(), []
    for h in sorted(hits, key=lambda x: (x[3], -(x[4] - x[3]))):
        if any(not (h[4] <= s or h[3] >= e) for s, e in seen):
            continue
        seen.add((h[3], h[4]))
        out.append(h)
    return out[:30]


def build_snippet(text, hits, mask, limit=450):
    if mask and hits:
        for s, e in sorted({(h[3], h[4]) for h in hits}, reverse=True):
            text = text[:s] + mask_val(text[s:e]) + text[e:]
    lines = text.strip("\n").split("\n")
    sn = "\n".join(l.rstrip() for l in lines[:8])
    if len(lines) > 8 or len(sn) > limit:
        sn = sn[:limit] + " …"
    return sn


# ----------------------------------------------------------------------------
# File scanning (runs inside worker processes)
# ----------------------------------------------------------------------------
CFG = {}


def _init_worker(cfg):
    global CFG
    CFG = cfg


def _decode(raw):
    try:
        t = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        t = raw.decode("latin-1")
    return t.replace("\r\n", "\n").replace("\r", "\n")


def _package_of(text, rel, ext):
    if ext in ("java", "kt", "kts", "scala", "groovy"):
        m = re.search(r"^\s*package\s+([\w.]+)", text[:5000], re.M)
        if m:
            return m.group(1)
    d = os.path.dirname(rel)
    return d.replace(os.sep, "/") if d else "(root)"


def scan_file(path, cfg):
    rel = os.path.relpath(path, cfg["root"])
    ext = os.path.splitext(path)[1][1:].lower()
    lang, family = EXT_MAP.get(ext, (ext.upper() or "Other", "hash"))
    res = dict(path=path, rel=rel, lang=lang, package="", lines=0, comment_lines=0, comment_blocks=0,
               code_blocks=0, code_lines=0, possible_blocks=0, high=0, medium=0, low=0, skipped="", findings=[])
    try:
        if os.path.getsize(path) > cfg["max_size"]:
            res["skipped"] = "Larger than size limit"
            return res
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        res["skipped"] = "Read error: " + e.__class__.__name__
        return res
    if b"\x00" in raw[:8192]:
        res["skipped"] = "Binary file"
        return res
    text = _decode(raw)
    res["lines"] = text.count("\n") + 1
    if len(text) / res["lines"] > 800 and res["lines"] < 300:
        res["skipped"] = "Minified / generated file"
        return res
    res["package"] = _package_of(text, rel, ext)
    try:
        comments = extract_comments(text, family)
    except Exception as e:  # keep scanning other files
        res["skipped"] = "Parse error: " + e.__class__.__name__
        return res

    for (s, e, kind, inline, ctext) in comments:
        cat, conf, _reason = classify(ctext, family, kind)
        if cat == "Empty":
            continue
        hits = detect_sensitive(ctext, cat)
        is_code = cat in ("Commented Code", "Possible Code")
        if kind == "string" and not (is_code or hits):
            continue  # normal multi-line string, not a comment
        nl = e - s + 1
        res["comment_lines"] += nl
        res["comment_blocks"] += 1
        if cat == "Commented Code":
            res["code_blocks"] += 1
            res["code_lines"] += nl
        elif cat == "Possible Code":
            res["possible_blocks"] += 1
        include = bool(hits) or is_code or (cat == "Marker" and cfg["markers"]) or \
            (cat in ("Plain Comment", "Documentation") and cfg["plain"])
        if not include:
            continue
        if any(h[2] == "High" for h in hits):
            sev = "High"
        elif any(h[2] == "Medium" for h in hits) or cat == "Commented Code":
            sev = "Medium"
        elif cat == "Possible Code":
            sev = "Low"
        else:
            sev = "Info"
        res[{"High": "high", "Medium": "medium"}.get(sev, "low")] += 1
        cats = "; ".join(sorted({h[1] for h in hits}))
        det = "; ".join(sorted({f"{h[0]}: {mask_val(ctext[h[3]:h[4]]) if cfg['mask'] else ctext[h[3]:h[4]][:60]}"
                                for h in hits}))[:350]
        style = kind + (" (inline)" if inline else "")
        res["findings"].append((sev, cat, cats, det, rel, res["package"], lang, s, e, nl, style, conf,
                                build_snippet(ctext, hits, cfg["mask"]), path))
    return res


def _scan_chunk(paths):
    out = []
    for p in paths:
        try:
            out.append(scan_file(p, CFG))
        except Exception as e:  # never let one file kill the scan
            out.append(dict(path=p, rel=os.path.relpath(p, CFG["root"]), lang="?", package="", lines=0,
                            comment_lines=0, comment_blocks=0, code_blocks=0, code_lines=0, possible_blocks=0,
                            high=0, medium=0, low=0, skipped="Error: " + e.__class__.__name__, findings=[]))
    return out


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------
def discover(cfg, emit, cancel):
    exts = set(cfg["exts"])
    ex_dirs = {d.strip().lower() for d in cfg["exclude_dirs"].split(",") if d.strip()}
    ex_files = [p.strip().lower() for p in cfg["exclude_files"].split(",") if p.strip()]
    files, n = [], 0
    for dp, dns, fns in os.walk(cfg["root"], followlinks=False):
        if cancel.is_set():
            break
        dns[:] = [d for d in dns if d.lower() not in ex_dirs]
        for fn in fns:
            ext = os.path.splitext(fn)[1][1:].lower()
            if ext in exts and not any(fnmatch.fnmatch(fn.lower(), p) for p in ex_files):
                files.append(os.path.join(dp, fn))
        n += len(fns)
        emit("phase", f"Discovering files… {len(files):,} matched so far")
    files.sort()
    return files


def run_scan(cfg, emit, cancel):
    t0 = time.time()
    emit("log", f"Scanning: {cfg['root']}")
    files = discover(cfg, emit, cancel)
    total = len(files)
    emit("log", f"{total:,} files matched the selected extensions.")
    if cancel.is_set():
        emit("cancelled", None)
        return None
    if total == 0:
        emit("error", "No files matched. Check the folder and the selected file types.")
        return None

    CHUNK = 20
    chunks = [files[i:i + CHUNK] for i in range(0, total, CHUNK)]
    results, done = [], 0
    stats = Counter()
    workers = max(1, cfg["workers"])
    emit("phase", f"Scanning with {workers} worker process(es)…")
    last_emit = 0.0
    with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker, initargs=(cfg,)) as ex:
        pending, ci = set(), 0
        while ci < len(chunks) or pending:
            while ci < len(chunks) and len(pending) < workers * 3 and not cancel.is_set():
                pending.add(ex.submit(_scan_chunk, chunks[ci]))
                ci += 1
            if not pending:
                break
            finished, pending = wait(pending, timeout=0.3, return_when=FIRST_COMPLETED)
            for f in finished:
                for r in f.result():
                    results.append(r)
                    done += 1
                    stats["lines"] += r["lines"]
                    stats["comment_lines"] += r["comment_lines"]
                    stats["code_blocks"] += r["code_blocks"]
                    stats["high"] += r["high"]
                    stats["medium"] += r["medium"]
                    if r["skipped"]:
                        stats["skipped"] += 1
            now = time.time()
            if now - last_emit > 0.15:
                emit("progress", (done, total, dict(stats)))
                last_emit = now
            if cancel.is_set():
                for p in pending:
                    p.cancel()
                break
    if cancel.is_set():
        emit("cancelled", None)
        return None
    emit("progress", (done, total, dict(stats)))
    emit("phase", "Writing Excel report…")
    summary = write_report(cfg, results, time.time() - t0)
    emit("log", f"Report saved: {cfg['output']}")
    emit("done", summary)
    return summary


# ----------------------------------------------------------------------------
# Excel report
# ----------------------------------------------------------------------------
SEV_RANK = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
FINDING_HEADERS = ["Severity", "Finding Type", "Sensitive Category", "Sensitive Details", "File", "Package / Folder",
                   "Language", "Start Line", "End Line", "Lines", "Comment Style", "Code Confidence %",
                   "Snippet (masked)", "Full Path"]
FINDING_WIDTHS = [10, 17, 22, 40, 48, 36, 12, 10, 10, 7, 16, 12, 70, 60]
MAX_ROWS = 1_000_000


def write_report(cfg, results, seconds):
    from openpyxl import Workbook
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.formatting.rule import CellIsRule
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    def xs(v):
        if isinstance(v, str):
            v = ILLEGAL_CHARACTERS_RE.sub("", v)
            if len(v) > 32000:
                v = v[:32000]
            if v.startswith("="):
                v = " " + v
        return v

    HFONT = Font(name="Arial", bold=True, color="FFFFFF")
    HFILL = PatternFill("solid", start_color="1F3864", end_color="1F3864")
    BFONT = Font(name="Arial", bold=True, size=11)
    TFONT = Font(name="Arial", bold=True, size=16, color="1F3864")

    wb = Workbook(write_only=True)

    def hcell(ws, v):
        c = WriteOnlyCell(ws, value=v)
        c.font, c.fill = HFONT, HFILL
        c.alignment = Alignment(vertical="center")
        return c

    def bold(ws, v, font=BFONT):
        c = WriteOnlyCell(ws, value=xs(v))
        c.font = font
        return c

    def sev_rules(ws, col, n):
        rng = f"{col}2:{col}{max(n + 1, 2)}"
        for val, bg, fg in (("High", "FFC7CE", "9C0006"), ("Medium", "FFEB9C", "9C5700"),
                            ("Low", "DDEBF7", "1F4E78")):
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=[f'"{val}"'],
                                                          fill=PatternFill("solid", start_color=bg, end_color=bg),
                                                          font=Font(color=fg, bold=True)))

    def table(title, headers, rows, widths, sev_col=None):
        pages = [rows[i:i + MAX_ROWS] for i in range(0, max(len(rows), 1), MAX_ROWS)] or [[]]
        for pi, page in enumerate(pages):
            ws = wb.create_sheet(title if pi == 0 else f"{title} ({pi + 1})"[:31])
            for i, w in enumerate(widths, 1):
                ws.column_dimensions[get_column_letter(i)].width = w
            ws.freeze_panes = "A2"
            ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{len(page) + 1}"
            ws.append([hcell(ws, h) for h in headers])
            for r in page:
                ws.append([xs(v) for v in r])
            if sev_col:
                sev_rules(ws, sev_col, len(page))

    findings = [f for r in results for f in r["findings"]]
    findings.sort(key=lambda f: (SEV_RANK[f[0]], f[4], f[7]))
    sev_count = Counter(f[0] for f in findings)
    cat_count = Counter()
    rule_count = Counter()
    for f in findings:
        for c in filter(None, f[2].split("; ")):
            cat_count[c] += 1
        for d in filter(None, f[3].split("; ")):
            rule_count[d.split(":")[0]] += 1
    scanned = [r for r in results if not r["skipped"]]
    skipped = [r for r in results if r["skipped"]]
    tot_lines = sum(r["lines"] for r in scanned)
    tot_cl = sum(r["comment_lines"] for r in scanned)

    # ---------------- Summary ----------------
    ws = wb.create_sheet("Summary")
    ws.column_dimensions["A"].width = 38
    for col in "BCDEFG":
        ws.column_dimensions[col].width = 18
    ws.append([bold(ws, APP_NAME, TFONT)])
    ws.append([])

    def kv(k, v):
        ws.append([bold(ws, k), xs(v)])

    kv("Project path", cfg["root"])
    kv("Scan date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    kv("Scan duration (sec)", round(seconds, 1))
    kv("File types scanned", ", ".join(sorted(cfg["exts"])))
    kv("Secret values masked in report", "Yes" if cfg["mask"] else "NO - report contains raw secrets")
    kv("Plain comments included", "Yes" if cfg["plain"] else "No (only commented code / sensitive)")
    ws.append([])
    ws.append([hcell(ws, "Totals"), hcell(ws, "Count")])
    for k, v in (("Files scanned", len(scanned)), ("Files skipped", len(skipped)), ("Total lines", tot_lines),
                 ("Comment lines", tot_cl), ("Comment blocks", sum(r["comment_blocks"] for r in scanned)),
                 ("Commented-code blocks", sum(r["code_blocks"] for r in scanned)),
                 ("Commented-code lines", sum(r["code_lines"] for r in scanned)),
                 ("Possible-code blocks", sum(r["possible_blocks"] for r in scanned))):
        ws.append([k, v])
    ws.append([])
    ws.append([hcell(ws, "Findings by severity"), hcell(ws, "Count")])
    for s in ("High", "Medium", "Low", "Info"):
        ws.append([s, sev_count.get(s, 0)])
    ws.append([])
    ws.append([hcell(ws, "Sensitive category"), hcell(ws, "Findings")])
    for k, v in cat_count.most_common():
        ws.append([k, v])
    ws.append([])
    ws.append([hcell(ws, "Detection rule"), hcell(ws, "Hits")])
    for k, v in rule_count.most_common(25):
        ws.append([k, v])
    ws.append([])
    ws.append([hcell(ws, h) for h in ("Language", "Files", "Lines", "Comment lines", "Commented-code blocks", "High findings")])
    by_lang = defaultdict(lambda: [0, 0, 0, 0, 0])
    for r in scanned:
        a = by_lang[r["lang"]]
        a[0] += 1; a[1] += r["lines"]; a[2] += r["comment_lines"]; a[3] += r["code_blocks"]; a[4] += r["high"]
    for k, a in sorted(by_lang.items()):
        ws.append([k] + a)
    ws.append([])
    ws.append([hcell(ws, "Top 15 files by HIGH findings"), hcell(ws, "High")])
    for r in sorted(scanned, key=lambda r: -r["high"])[:15]:
        if r["high"]:
            ws.append([xs(r["rel"]), r["high"]])
    ws.append([])
    ws.append([bold(ws, "Notes")])
    for note in ("Detection is rule/heuristic based (no AI): results are leads for an analyst to verify.",
                 "Severity HIGH = ID / password / token / key / PII pattern found inside a comment.",
                 "Severity MEDIUM = commented-out code (or DB connection string / internal IP).",
                 "Severity LOW = possible commented code.  INFO = plain comment (only if enabled)."):
        ws.append([note])

    # ---------------- Findings ----------------
    high = [f for f in findings if f[0] == "High"]
    table("High Risk", FINDING_HEADERS, high, FINDING_WIDTHS, "A")
    table("All Findings", FINDING_HEADERS, findings, FINDING_WIDTHS, "A")

    # ---------------- File-wise ----------------
    frows = []
    for r in sorted(scanned, key=lambda r: (-r["high"], -r["code_blocks"], r["rel"])):
        pct = round(100.0 * r["comment_lines"] / r["lines"], 1) if r["lines"] else 0
        frows.append([r["rel"], r["package"], r["lang"], r["lines"], r["comment_lines"], pct, r["comment_blocks"],
                      r["code_blocks"], r["code_lines"], r["possible_blocks"], r["high"], r["medium"], r["path"]])
    table("File-wise", ["File", "Package / Folder", "Language", "Total Lines", "Comment Lines", "Comment %",
                        "Comment Blocks", "Commented-Code Blocks", "Commented-Code Lines", "Possible-Code Blocks",
                        "High", "Medium", "Full Path"],
          frows, [52, 36, 12, 11, 13, 10, 13, 15, 15, 13, 8, 8, 60])

    # ---------------- Package-wise ----------------
    pk = defaultdict(lambda: [0, 0, 0, 0, 0, 0, 0, 0])
    for r in scanned:
        a = pk[r["package"]]
        a[0] += 1; a[1] += r["lines"]; a[2] += r["comment_lines"]; a[3] += r["code_blocks"]
        a[4] += r["code_lines"]; a[5] += r["high"]; a[6] += r["medium"]; a[7] += r["possible_blocks"]
    prow = [[k] + v for k, v in sorted(pk.items(), key=lambda kv: (-kv[1][5], -kv[1][3], kv[0]))]
    table("Package-wise", ["Package / Folder", "Files", "Total Lines", "Comment Lines", "Commented-Code Blocks",
                           "Commented-Code Lines", "High", "Medium", "Possible-Code Blocks"],
          prow, [60, 8, 12, 13, 15, 15, 8, 8, 13])

    if skipped:
        table("Skipped", ["File", "Reason"], [[r["rel"], r["skipped"]] for r in skipped[:50000]], [70, 40])

    wb.save(cfg["output"])
    return dict(output=cfg["output"], files=len(scanned), skipped=len(skipped), lines=tot_lines,
                comment_lines=tot_cl, code_blocks=sum(r["code_blocks"] for r in scanned),
                high=sev_count.get("High", 0), medium=sev_count.get("Medium", 0), low=sev_count.get("Low", 0),
                seconds=seconds,
                preview=[(f[0], f[1], f[4], f[7], f[3] or f[2], f[13]) for f in findings[:2000] if f[0] in ("High", "Medium")])


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def open_path(path, select=False):
    try:
        if platform.system() == "Windows":
            if select:
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            else:
                os.startfile(path)  # type: ignore[attr-defined]
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", "-R", path] if select else ["open", path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(path) if select else path])
    except Exception:
        pass


def selected_exts(group_vars, extra):
    exts = set()
    for name, var in group_vars.items():
        if var.get():
            exts.update(EXT_GROUPS[name][0])
    for e in re.split(r"[,\s;]+", extra or ""):
        e = e.strip().lstrip(".*").lower()
        if e:
            exts.add(e)
    return sorted(exts)


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
if tk is not None:
    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(f"{APP_NAME}  v{VERSION}")
            self.geometry("1040x800")
            self.minsize(920, 680)
            self.q = queue.Queue()
            self.cancel_ev = threading.Event()
            self.worker = None
            self.report = None
            self.item_paths = {}
            self._style()
            self._vars()
            self._build()
            self.after(100, self._poll)

        def _style(self):
            st = ttk.Style(self)
            try:
                st.theme_use("clam")
            except tk.TclError:
                pass
            st.configure("TLabelframe.Label", font=("Segoe UI", 10, "bold"))
            st.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=8)
            st.configure("Treeview", rowheight=22)

        def _vars(self):
            self.path_var = tk.StringVar()
            self.out_var = tk.StringVar()
            self.extra_var = tk.StringVar()
            self.mask_var = tk.BooleanVar(value=True)
            self.plain_var = tk.BooleanVar(value=False)
            self.marker_var = tk.BooleanVar(value=False)
            self.exdirs_var = tk.StringVar(value=DEFAULT_EXCLUDE_DIRS)
            self.exfiles_var = tk.StringVar(value=DEFAULT_EXCLUDE_FILES)
            self.maxmb_var = tk.IntVar(value=5)
            self.workers_var = tk.IntVar(value=max(1, (os.cpu_count() or 2) - 1))
            self.groups = {n: tk.BooleanVar(value=d) for n, (_, d) in EXT_GROUPS.items()}
            self.status_var = tk.StringVar(value="Ready.")
            self.stats_var = tk.StringVar(value="")

        def _build(self):
            pad = dict(padx=10, pady=5)
            root = ttk.Frame(self, padding=8)
            root.pack(fill="both", expand=True)

            f1 = ttk.LabelFrame(root, text=" 1. Project folder ")
            f1.pack(fill="x", **pad)
            ttk.Entry(f1, textvariable=self.path_var).pack(side="left", fill="x", expand=True, padx=8, pady=8)
            ttk.Button(f1, text="Browse…", command=self._browse_project).pack(side="left", padx=8)

            f2 = ttk.LabelFrame(root, text=" 2. File types to scan ")
            f2.pack(fill="x", **pad)
            for i, (name, var) in enumerate(self.groups.items()):
                ttk.Checkbutton(f2, text=name, variable=var).grid(row=i // 4, column=i % 4, sticky="w", padx=10, pady=2)
            ttk.Label(f2, text="Extra extensions (comma separated):").grid(row=4, column=0, columnspan=2, sticky="w", padx=10, pady=4)
            ttk.Entry(f2, textvariable=self.extra_var, width=30).grid(row=4, column=2, columnspan=2, sticky="w", pady=4)

            f3 = ttk.LabelFrame(root, text=" 3. Options ")
            f3.pack(fill="x", **pad)
            ttk.Checkbutton(f3, text="Mask secret values in the Excel report (recommended)", variable=self.mask_var).grid(row=0, column=0, columnspan=3, sticky="w", padx=10, pady=2)
            ttk.Checkbutton(f3, text="Also list plain explanatory comments", variable=self.plain_var).grid(row=1, column=0, columnspan=2, sticky="w", padx=10, pady=2)
            ttk.Checkbutton(f3, text="Include TODO / FIXME markers", variable=self.marker_var).grid(row=1, column=2, sticky="w", padx=10, pady=2)
            ttk.Label(f3, text="Exclude folders:").grid(row=2, column=0, sticky="w", padx=10, pady=2)
            ttk.Entry(f3, textvariable=self.exdirs_var).grid(row=2, column=1, columnspan=3, sticky="ew", padx=6, pady=2)
            ttk.Label(f3, text="Exclude file patterns:").grid(row=3, column=0, sticky="w", padx=10, pady=2)
            ttk.Entry(f3, textvariable=self.exfiles_var).grid(row=3, column=1, columnspan=3, sticky="ew", padx=6, pady=2)
            ttk.Label(f3, text="Skip files larger than (MB):").grid(row=4, column=0, sticky="w", padx=10, pady=4)
            ttk.Spinbox(f3, from_=1, to=200, textvariable=self.maxmb_var, width=6).grid(row=4, column=1, sticky="w", padx=6)
            ttk.Label(f3, text="Parallel workers:").grid(row=4, column=2, sticky="e", padx=6)
            ttk.Spinbox(f3, from_=1, to=64, textvariable=self.workers_var, width=6).grid(row=4, column=3, sticky="w", padx=6)
            f3.columnconfigure(1, weight=1)
            f3.columnconfigure(3, weight=1)

            f4 = ttk.LabelFrame(root, text=" 4. Excel report ")
            f4.pack(fill="x", **pad)
            ttk.Entry(f4, textvariable=self.out_var).pack(side="left", fill="x", expand=True, padx=8, pady=8)
            ttk.Button(f4, text="Save as…", command=self._browse_out).pack(side="left", padx=8)

            bar = ttk.Frame(root)
            bar.pack(fill="x", **pad)
            self.btn_start = ttk.Button(bar, text="▶  Start scan", style="Accent.TButton", command=self._start)
            self.btn_start.pack(side="left")
            self.btn_cancel = ttk.Button(bar, text="Cancel", command=self._cancel, state="disabled")
            self.btn_cancel.pack(side="left", padx=8)
            self.btn_open = ttk.Button(bar, text="Open report", command=lambda: open_path(self.report), state="disabled")
            self.btn_open.pack(side="right")
            self.btn_folder = ttk.Button(bar, text="Show in folder", command=lambda: open_path(self.report, True), state="disabled")
            self.btn_folder.pack(side="right", padx=8)

            self.pb = ttk.Progressbar(root, mode="determinate")
            self.pb.pack(fill="x", **pad)
            ttk.Label(root, textvariable=self.status_var).pack(anchor="w", padx=12)
            ttk.Label(root, textvariable=self.stats_var, foreground="#1F3864", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12)

            nb = ttk.Notebook(root)
            nb.pack(fill="both", expand=True, **pad)
            tf = ttk.Frame(nb)
            nb.add(tf, text="High / Medium findings (double-click opens the file)")
            cols = ("sev", "type", "file", "line", "details")
            self.tree = ttk.Treeview(tf, columns=cols, show="headings")
            for c, t, w in (("sev", "Severity", 70), ("type", "Type", 110), ("file", "File", 380),
                            ("line", "Line", 55), ("details", "Details", 300)):
                self.tree.heading(c, text=t)
                self.tree.column(c, width=w, anchor="w")
            self.tree.tag_configure("High", background="#FDE2E2")
            self.tree.tag_configure("Medium", background="#FFF3D6")
            sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=sb.set)
            self.tree.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            self.tree.bind("<Double-1>", self._open_item)
            lf = ttk.Frame(nb)
            nb.add(lf, text="Log")
            self.log = tk.Text(lf, height=8, state="disabled", wrap="word")
            self.log.pack(fill="both", expand=True)

        # ---- actions ----
        def _browse_project(self):
            p = filedialog.askdirectory(title="Select project folder")
            if p:
                self.path_var.set(p)
                if not self.out_var.get():
                    name = os.path.basename(os.path.normpath(p)) or "project"
                    stamp = datetime.now().strftime("%Y%m%d_%H%M")
                    self.out_var.set(os.path.join(os.path.expanduser("~"), f"{name}_commented_code_report_{stamp}.xlsx"))

        def _browse_out(self):
            p = filedialog.asksaveasfilename(title="Save Excel report", defaultextension=".xlsx",
                                             filetypes=[("Excel workbook", "*.xlsx")],
                                             initialfile=os.path.basename(self.out_var.get()) or "report.xlsx")
            if p:
                self.out_var.set(p)

        def _log(self, msg):
            self.log.configure(state="normal")
            self.log.insert("end", datetime.now().strftime("%H:%M:%S  ") + msg + "\n")
            self.log.see("end")
            self.log.configure(state="disabled")

        def _start(self):
            root = self.path_var.get().strip()
            if not os.path.isdir(root):
                messagebox.showerror(APP_NAME, "Please select a valid project folder.")
                return
            exts = selected_exts(self.groups, self.extra_var.get())
            if not exts:
                messagebox.showerror(APP_NAME, "Select at least one file type.")
                return
            try:
                import openpyxl  # noqa: F401
            except ImportError:
                messagebox.showerror(APP_NAME, "The 'openpyxl' package is missing.\n\nInstall it with:\n    pip install openpyxl")
                return
            out = self.out_var.get().strip()
            if not out:
                out = os.path.join(os.path.expanduser("~"), "commented_code_report.xlsx")
                self.out_var.set(out)
            if not out.lower().endswith(".xlsx"):
                out += ".xlsx"
                self.out_var.set(out)
            cfg = dict(root=os.path.abspath(root), output=out, exts=exts, mask=self.mask_var.get(),
                       plain=self.plain_var.get(), markers=self.marker_var.get(),
                       exclude_dirs=self.exdirs_var.get(), exclude_files=self.exfiles_var.get(),
                       max_size=int(self.maxmb_var.get()) * 1024 * 1024, workers=int(self.workers_var.get()))
            self.cancel_ev.clear()
            self.tree.delete(*self.tree.get_children())
            self.item_paths.clear()
            self.btn_start.configure(state="disabled")
            self.btn_cancel.configure(state="normal")
            self.btn_open.configure(state="disabled")
            self.btn_folder.configure(state="disabled")
            self.pb.configure(mode="indeterminate")
            self.pb.start(12)
            self.stats_var.set("")
            self.worker = threading.Thread(target=self._run, args=(cfg,), daemon=True)
            self.worker.start()

        def _run(self, cfg):
            try:
                run_scan(cfg, lambda k, p: self.q.put((k, p)), self.cancel_ev)
            except Exception:
                self.q.put(("error", traceback.format_exc()))

        def _cancel(self):
            self.cancel_ev.set()
            self.status_var.set("Cancelling…")

        def _finish_ui(self):
            self.pb.stop()
            self.pb.configure(mode="determinate")
            self.btn_start.configure(state="normal")
            self.btn_cancel.configure(state="disabled")

        def _poll(self):
            try:
                while True:
                    kind, p = self.q.get_nowait()
                    if kind == "log":
                        self._log(p)
                    elif kind == "phase":
                        self.status_var.set(p)
                    elif kind == "progress":
                        done, total, s = p
                        if str(self.pb.cget("mode")) != "determinate":
                            self.pb.stop()
                            self.pb.configure(mode="determinate")
                        self.pb["maximum"] = total
                        self.pb["value"] = done
                        self.status_var.set(f"Scanning… {done:,} / {total:,} files")
                        self.stats_var.set(f"Lines: {s.get('lines', 0):,}   Comment lines: {s.get('comment_lines', 0):,}   "
                                           f"Commented-code blocks: {s.get('code_blocks', 0):,}   "
                                           f"HIGH: {s.get('high', 0):,}   MEDIUM: {s.get('medium', 0):,}")
                    elif kind == "done":
                        self._finish_ui()
                        self._on_done(p)
                    elif kind == "cancelled":
                        self._finish_ui()
                        self.status_var.set("Scan cancelled.")
                        self._log("Scan cancelled.")
                    elif kind == "error":
                        self._finish_ui()
                        self.status_var.set("Error.")
                        self._log(str(p))
                        messagebox.showerror(APP_NAME, str(p)[:1500])
            except queue.Empty:
                pass
            self.after(100, self._poll)

        def _on_done(self, s):
            self.report = s["output"]
            self.pb["value"] = self.pb["maximum"]
            self.status_var.set(f"Done in {s['seconds']:.1f}s - report saved.")
            self.stats_var.set(f"Files: {s['files']:,}   Lines: {s['lines']:,}   Commented-code blocks: {s['code_blocks']:,}   "
                               f"HIGH: {s['high']:,}   MEDIUM: {s['medium']:,}   LOW: {s['low']:,}")
            for sev, typ, rel, line, det, path in s["preview"]:
                iid = self.tree.insert("", "end", values=(sev, typ, rel, line, det), tags=(sev,))
                self.item_paths[iid] = path
            self.btn_open.configure(state="normal")
            self.btn_folder.configure(state="normal")
            messagebox.showinfo(APP_NAME, f"Scan complete.\n\nHIGH: {s['high']:,}\nMEDIUM: {s['medium']:,}\n\nReport:\n{s['output']}")

        def _open_item(self, _evt):
            sel = self.tree.selection()
            if sel and sel[0] in self.item_paths:
                open_path(self.item_paths[sel[0]])


# ----------------------------------------------------------------------------
# Entry points
# ----------------------------------------------------------------------------
def main():
    multiprocessing.freeze_support()
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument("--cli", metavar="PATH", help="run headless on PATH (no GUI)")
    ap.add_argument("-o", "--output", help="Excel output path (CLI)")
    ap.add_argument("--ext", default="java,jsp,jspf,html,htm,js,jsx,ts,tsx,rb,py", help="comma separated extensions (CLI)")
    ap.add_argument("--no-mask", action="store_true", help="do not mask secrets in report")
    ap.add_argument("--plain", action="store_true", help="also list plain comments")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    a = ap.parse_args()
    if a.cli:
        cfg = dict(root=os.path.abspath(a.cli),
                   output=a.output or f"commented_code_report_{datetime.now():%Y%m%d_%H%M}.xlsx",
                   exts=[e.strip().lstrip(".").lower() for e in a.ext.split(",") if e.strip()],
                   mask=not a.no_mask, plain=a.plain, markers=False, exclude_dirs=DEFAULT_EXCLUDE_DIRS,
                   exclude_files=DEFAULT_EXCLUDE_FILES, max_size=5 * 1024 * 1024, workers=a.workers)

        def emit(k, p):
            if k in ("log", "phase"):
                print(p)
            elif k == "progress" and p[0] % 200 == 0:
                print(f"  {p[0]:,}/{p[1]:,} files")
            elif k == "error":
                print("ERROR:", p, file=sys.stderr)

        s = run_scan(cfg, emit, threading.Event())
        if s:
            print(f"Done. HIGH={s['high']} MEDIUM={s['medium']} LOW={s['low']}  ->  {s['output']}")
        return
    if tk is None:
        print("tkinter is not available. Install Python with Tk support or use --cli.")
        sys.exit(1)
    App().mainloop()


if __name__ == "__main__":
    main()
