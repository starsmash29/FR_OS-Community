"""Extra YAML texts for FR_OS 1.x, run with the capture plugin next to
1.x's own suite (reference/generate.sh).

1.x reads config.yaml with PyYAML's yaml.safe_load, so YAML 1.1 as
PyYAML has it is part of what FR_OS 2 must reproduce: which texts load,
what they load as (yes is True, 0755 is 493, 1:30 is 90, 2026-11-01 is a
date), and the error for those that don't. This module only feeds texts
to yaml.safe_load, and each config text's value to parse_config; the
plugin records what 1.x answered (yaml.jsonl, yaml_config.jsonl).
Nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import pytest
import yaml

from frfw.config import loader
from test_fros_edge_cases import BASE

# Texts for yaml.safe_load alone.
SCALARS = [
    # booleans: YAML 1.1's words, and what isn't one
    "yes", "Yes", "YES", "yEs", "no", "No", "on", "On", "OFF", "off", "true", "True", "TRUE", "tRue", "false",
    "y", "n", "Y", "N", "~", "null", "Null", "NULL", "nULL", "",
    # integers
    "0", "-0", "+0", "12", "+12", "-12", "012", "0755", "08", "09", "0o17", "0b101", "-0b101", "0b2", "0x1F",
    "0X1F", "-0x1f", "0x", "0b", "0b_", "0x_", "0_", "00", "1_000", "1__0", "_1", "1_", "190:20:30", "-1:30",
    "1:60", "1:5", "0:30", "1:30:", "99999999999999999999999", "1e5", "1E5", "١٢",
    # floats
    "1.5", "-1.5", "+1.5", "1.", ".5", "-.5", "1.0e+5", "1.0e5", "1.0E-5", "1.5e+300", "1e+400", "1.0e+400",
    "-1.0e+400", "1.0e-400", ".inf", "-.inf", "+.inf", ".Inf", ".INF", ".iNf", ".nan", ".NaN", ".NAN", "-.nan",
    "190:20:30.15", "1:30.5", "1_0.5", "1._5", "0.1", "-0.0", "1.7976931348623157e+308", "123456789012345678.0",
    "1.0e+16", "1.0e-5", "0.0001", "0.00001",
    # timestamps
    "2026-11-01", "2026-1-1", "2026-11-1", "2026-11-01T10:00:00", "2026-11-01t10:00:00", "2026-11-01 10:00:00",
    "2026-11-01\t10:00:00", "2026-11-01  10:00:00", "2026-11-01T10:00", "2026-11-01T1:00:00",
    "2026-11-01T10:00:00Z", "2026-11-01T10:00:00 Z", "2026-11-01T10:00:00.5", "2026-11-01T10:00:00.123456789",
    "2026-11-01T10:00:00.", "2026-11-01T10:00:00+01:00", "2026-11-01T10:00:00-05:30", "2026-11-01T10:00:00+5",
    "2026-11-01T10:00:00 +01", "2026-11-01T10:00:00+00:00", "2026-11-01T10:00:00-00:00",
    "2026-11-01T10:00:00+23:59", "2026-11-01T10:00:00+24:00", "2026-11-01T10:00:00+1:30",
    "2026-02-29", "2028-02-29", "2026-13-01", "2026-00-10", "0000-01-01", "2026-11-01T24:00:00",
    "2026-11-01T23:60:00", "2026-11-01T23:59:60", "2026-1-1T10:00:00", "2026-11-01T10:00:00+05:99",
    # strings that look like something else
    "1.2.3.4", "10.73.1.1/24", "aa:bb:cc:dd:ee:ff", "12:34:56", "22-23", "<<", "=", "-", "--", "---x", "a#b",
    "a #b", "'quoted'", "\"double\"", "'it''s'", "'yes'", "\"0x1F\"", "!!str 0x1F", "! 0x1F", "! '0x1F'",
    "!!int '0x1F'", "!!int ' 12 '", "!!int x", "!!int ''", "!!int 1.5", "!!int 0o17", "!!int 09", "!!int --5",
    "!!int +-5", "!!int 0b0b1", "!!float 1", "!!float x", "!!float nan", "!!float ' 1.5'", "!!float 1e5",
    "!!float inf", "!!bool yes", "!!bool maybe", "!!bool ''", "!!null x", "!!null ''", "!!str", "!!int", "!!map",
    "!!seq", "!!timestamp 2026-11-01", "!!timestamp x", "!!timestamp 2026-02-30", "!!binary aGVsbG8=",
    "!!binary é", "!!binary '!'", "!!binary aGVsbG8", "!!binary aGVsbG", "!!binary a", "!!binary 'aGVs bG8='",
    "!!binary a===", "!!binary =", "!!binary aG=Vs", "!!binary aGV=", "!!binary aGVsbA==x", "!!binary ''",
    "!!binary 'éé'", "!!binary 'a€'", "!!binary [a]", "!!set [a]", "!!set {a: 1}", "!!set {[a]: 1}",
    "!!omap [a, b]", "!!omap [{a: 1, b: 2}]", "!!pairs x", "!!omap [{[a]: 1}]", "a: !!set {}\nb: !!int x\n",
    "!!set {? !!set {}}", "!!set {a, b}", "!!omap [a: 1, b: 2]", "!!pairs [a: 1]", "!!omap x",
    "!foo x", "!<tag:yaml.org,2002:str> 5", "!<!foo> x", "!!python/object:os.system x", "!!merge x",
    "!!value x", "!!str [1]", "!!str {a: 1}", "!!str {=: 5}", "!!int {=: 5}", "!!seq x", "!!map x",
    "!!map [1]", "!!seq {a: 1}", "&a x", "&a !!int 5", "!!int &a 5", "*a", "&a",
    # quoted scalars and escapes
    "\"a\\tb\"", "\"\\x41\\u00e9\\U0001F600\"", "\"\\0\\a\\b\\e\\f\\v\\r\\n\\N\\_\\L\\P\\/\\ \"", "\"\\q\"",
    "\"\\x4\"", "\"\\ud800\"", "\"\\U00110000\"", "\"a\nb\"", "\"a\n\nb\"", "\"a \\\n b\"", "'a\nb'", "'a\n\n b'",
    "\"unterminated", "'unterminated", "\"a\n---\nb\"", "\"\\\nx\"",
    # characters
    "\ufeffa: 1", "a: \ufeff", "\x07", "a\x08", "a: \u0085b", "a\u2028b", "é: ö", "a: \U0001F600",
    "a: \ufffe", "a: \ue000",
]

DOCUMENTS = [
    # collections
    "a: 1\nb: 2\n", "- a\n- b\n", "[a, b, c]", "{a: 1, b: [1, 2]}", "[a, [b, [c]]]", "{a: {b: {c: d}}}",
    "a:\n- 1\n- 2\n", "a:\n  - 1\n  - 2\n", "- a: 1\n  b: 2\n- c\n", "- - a\n  - b\n- - c\n", "-\n- a\n-\n",
    "a:\nb:\n", "a: \nb: ~\n", "? a\n: 1\n", "? a\n", "? [a, b]\n: 1\n", "? {a: 1}\n: 2\n", "[a: 1, b]", "[? a]",
    "{a, b: 1}", "{a: 1,}", "[a,]", "[,]", "{,}", "[a b]", "{a: b c}", "[a, {b: c}]", "{[a]: 1}", "{? a}",
    "a: [1, 2]: 3", "{a: 1, a: 2}", "a: 1\na: 2\n", "1: a\n1.0: b\ntrue: c\n", "0: a\nfalse: b\n0.0: c\n",
    "~: a\nnull: b\n", "2026-11-01: a\n2026-11-01T00:00:00: b\n", ".nan: a\n.nan: b\n", "!!float nan: a\n!!float nan: b\n",
    "1: a\n'1': b\n", "[1, 2]: x", "? [1, 2]\n: x\n",
    # anchors, aliases, merges
    "a: &x 1\nb: *x\n", "a: &x [1, 2]\nb: *x\n", "a: *x\n", "a: &x 1\nb: &x 2\n", "a: &x [*x]\n",
    "a: &x {b: *x}\n", "&x [*x]", "- &x a\n- *x\n- &y b\n- *y\n", "base: &b {x: 1, y: 2}\nc:\n  <<: *b\n  y: 3\n",
    "a: &a {x: 1}\nb: &b {y: 2}\nc:\n  <<: [*a, *b]\n  z: 3\n", "a: &a {x: 1}\nb: &b {x: 2}\nc: {<<: [*a, *b]}\n",
    "c:\n  <<: {x: 1}\n  <<: {x: 2}\n", "c: {<<: 5}", "c: {<<: [5]}", "c: {<<: [{a: 1}, 5]}",
    "a: &a {x: 1, <<: {y: 2}}\nb: {<<: *a}\n", "c: {=: 5}", "c: {=: 5, a: 1}", "a: <<\n", "a: =\n",
    "a: &x\nb: *x\n", "a: &x !!str\n", "? &k a\n: *k\n", "&a a: &b b\n*a : *b\n",
    "a: &a [1]\nb: &b [*a, *a]\nc: &c [*b, *b]\n",
    # block scalars
    "a: |\n  x\n  y\n", "a: |-\n  x\n", "a: |+\n  x\n\n", "a: >\n  x\n  y\n\n  z\n", "a: >-\n  x\n   y\n  z\n",
    "a: |2\n   x\n", "a: |0\n  x\n", "a: |10\n  x\n", "a: |-2\n   x\n", "a: |2-\n   x\n", "a: |x\n", "a: | # c\n  x\n",
    "a: |\n\n  x\n", "a: |\n  x\n b: 1\n", "a: >\n  x\n\n\n", "- |\n  a\n- b\n", "a: |\n", "a: >+\n",
    # plain scalars over lines
    "a: x\n  y\n", "a: x\n\n  y\n", "- x\n  y\n", "a: x # c\n  y\n", "a: x\n---\n", "a: x\n...\n",
    # documents
    "", "# only a comment\n", "---\n", "--- a\n", "--- a\n...\n", "a\n---\nb\n", "---\na: 1\n---\nb: 2\n",
    "...\n", "--- !!str\n", "%YAML 1.1\n---\na\n", "%YAML 1.2\n--- a\n", "%YAML 2.0\n--- a\n",
    "%YAML 1.1\n%YAML 1.1\n--- a\n", "%TAG !e! tag:example.com,2000:\n--- !e!x a\n", "%TAG !e! x\n%TAG !e! y\n--- a\n",
    "%FOO bar\n--- a\n", "%YAML\n--- a\n", "%YAML 1\n--- a\n", "%YAML 1.1x\n--- a\n", "%TAG ! !\n--- !x a\n",
    "--- !e!x a\n", "%YAML 1.1\na\n", "a\n%YAML 1.1\n", "--- >\n x\n", "--- |\n x\n", "--- [a]\n--- [b]\n",
    "a: 1\n--- [", "a\n... # c\n", "a\n...\n---\nb\n",
    # errors in the block structure
    "a:\n  - b\n c: d\n", "a: b: c\n", "a:\n\tb: 1\n", "\ta: 1\n", "a: 1\n\tb: 2\n", "- a\nb: 1\n", "a: 1\n- b\n",
    "a: [1, 2\n", "a: {b: 1\n", "a: ]\n", "a: }\n", "@a\n", "`a\n", "%a\n", "a: @b\n", "a: !\n", "a: !!\n",
    "a: !<x\n", "a: !<>\n", "a: !e!x b\n", "a: &\n", "a: *\n", "a: &x$ 1\n", "a: *x$\n", "a: !x%zz b\n",
    "a: !x%41 b\n", "a: !x%ff b\n", "a: !x%c3%a9 b\n", "a: !<x%e2%82> b\n", "a: !x!y! b\n", "? a\n? b\n: c\n",
    "a:\n  b: 1\n   c: 2\n", "a:\n  b: 1\n c: 2\n", "-a\n", "- -a\n", "a:b\n", "a :b\n", "a : b\n",
    "[a\n  ,b]", "{a:\nb}", "{a:b}", "{\"a\":b}", "{'a':b}", "[a:b]", "[a: b, c: d]", "a: 'b'c\n", "a: \"b\"c\n",
    "a: 'b' c\n", "- 'a'\n  b\n", "a: b\n  c: d\n", "a:\n  b\nc\n", "a: |\n  b\n c\n",
    "x" * 1025 + ": 1\n", "x" * 1020 + ": 1\n", "a: " + "x" * 200 + " ]\n", "a: [" + "x, " * 40 + "]]\n",
    "k: v\n" * 3 + "bad: [\n", "a: 1\r\nb: 2\r\n", "a: 1\rb: 2\r", "a: 1\r\n  b: 2\r\n", "a: \"x\r\ny\"\n",
    "a: |\r\n  x\r\n  y\r\n", "a\u2028b: 1", "a: 1\u2029b: 2", "a: 1\x85b: 2",
    "[" * 70 + "]" * 70, "a:\n" + "".join("  " * i + "b:\n" for i in range(1, 70)),
    "[" * 50 + "]" * 50, "- " * 40 + "a\n",
]

# Texts whose value is there for yaml.safe_dump (the plugin records what
# it writes for every value loaded): how it quotes, wraps at 80
# columns, writes a long or multi-line key, and anchors a list or a
# mapping reached twice.
_WORDS = " ".join(f"word{i}" for i in range(30))
DUMPS = [
    "a: " + _WORDS + "\n", "- " + _WORDS + "\n", "a:\n  b:\n    c: " + _WORDS + "\n", _WORDS,
    "a: " + "x" * 120 + "\n", "a: \"" + _WORDS.replace(" ", "  ") + "\"\n", "a: \"- " + _WORDS + "\"\n",
    "a: \": " + _WORDS + "\"\n", "a: \"#" + _WORDS + " '\"\n", "a: \"" + _WORDS + " \"\n",
    "a: \" " + _WORDS + "\"\n", "a: \"" + _WORDS.replace(" ", " \\u00e9 ") + "\"\n",
    "a: \"" + _WORDS.replace(" ", "\\u00e9") + "\"\n", "a: \"" + "\\u00e9" * 100 + "\"\n",
    "a: \"" + "x" * 78 + " y z\"\n", "a: \"" + "x" * 79 + "  y\"\n", "a: \"" + _WORDS + "\\n\"\n",
    "a: \"" + _WORDS.replace(" ", "\\n") + "\"\n", "a: \"" + _WORDS.replace(" ", " \\n ") + "\"\n",
    "a: \"x\\ny\"\n", "a: \"x\\n\\ny\\n\"\n", "a: \"\\nx\"\n", "a: \"x \\n y\"\n", "a: \"x\\n y\"\n",
    "a: \"x \\ny\"\n", "a: \"\\tx\"\n", "a: \"x\\ty\"\n", "a: \"x\\ry\"\n", "a: \"\\x00\\x7f\\x85\\xa0\"\n",
    "a: \"\\u2028\\u2029\\ufeff\\U0001F600\\U0010FFFF\"\n", "a: \"it's\"\n", "a: \"'it'\"\n",
    "a: \"say \\\"x\\\"\"\n", "a: \"back\\\\slash\"\n", "a: ' x'\n", "a: 'x '\n", "a: ''\n",
    "a: '- x'\n", "a: '-x'\n", "a: '-'\n", "a: ': x'\n", "a: ':x'\n", "a: 'x:'\n", "a: 'x: y'\n", "a: 'x :y'\n",
    "a: '? x'\n", "a: '?x'\n", "a: 'x #y'\n", "a: 'x#y'\n", "a: '[x]'\n", "a: 'x[y]'\n", "a: 'x,y'\n",
    "a: '{x}'\n", "a: '---'\n", "a: '--- x'\n", "a: '...'\n", "a: '@x'\n", "a: '%x'\n", "a: '`x'\n",
    "a: '!x'\n", "a: '&x'\n", "a: '*x'\n", "a: '|x'\n", "a: '>x'\n", "a: '\"x'\n", "a: x'y\n",
    "a: '1.0'\n", "a: '1e5'\n", "a: 'null'\n", "a: '~'\n", "a: 'yes'\n", "a: 'NO'\n", "a: '2026-11-01'\n",
    "a: '1:30'\n", "a: '0x1F'\n", "a: '<<'\n", "a: '='\n", "a: '.inf'\n", "a: '-.nan'\n", "a: '+1'\n",
    "\"\": 1\n", "\"" + "k" * 120 + "\": 1\n", "\"" + "k" * 122 + "\": 1\n", "\"" + "k" * 123 + "\": 1\n",
    "\"" + "k" * 130 + "\": 1\n", "\"k\\nl\": 1\n", "\"" + _WORDS + _WORDS + "\": 1\n", "\"yes\": 1\n",
    "\" k\": 1\n", "\"\\u00e9\": 1\n", "~: 1\n", "1: a\n2.5: b\ntrue: c\n2026-11-01: d\n",
    "2026-11-01 10:00:00+01:00: a\n", "a: 2026-11-01T10:00:00.5Z\n", "a: 2026-11-01T10:00:00-05:30\n",
    "a: &x [1, 2]\nb: *x\nc: *x\n", "a: &x {k: v}\nb: *x\n", "a: &x []\nb: *x\n", "a: &x {}\nb: *x\n",
    "a: [&x [1], *x, [*x]]\n", "a: &x\n  b: &y [1]\n  c: *y\nd: *x\n", "&a {k: *a}", "&a [*a, *a]",
    "a: &x 1\nb: *x\n", "a: &s str\nb: *s\n", "a: &d 2026-11-01\nb: *d\n", "a: &t 2026-11-01 10:00:00\nb: [*t]\n", "a: &n ~\nb: *n\n", "a: []\nb: {}\nc: [[], {}]\n",
    "a:\n- - 1\n  - 2\n- {}\n- []\n- k: 1\n  j: [x]\n", "- - - a\n", "- {a: {b: [c]}}\n",
    "a: 1.0e+17\nb: 0.1\nc: -0.0\nd: 1.0e-05\ne: 1.5e+300\nf: 123456789012345678.0\n",
    "a: 99999999999999999999999\nb: -0b101\nc: 0x1F\nd: 0755\ne: 1:30\n",
]

CONFIG = yaml.safe_dump(BASE, sort_keys=False)

# (old, new) changes to the base config's text: one per config case.
CONFIG_EDITS = [
    (None, None),
    ("version: 1\n", "version: 1.0\n"), ("version: 1\n", "version: yes\n"), ("version: 1\n", "version: '1'\n"),
    ("version: 1\n", "version: 0b1\n"), ("version: 1\n", "version: 2026-11-01\n"),
    ("hostname: fr-router\n", "hostname: 2026-11-01\n"), ("hostname: fr-router\n", "hostname: yes\n"),
    ("hostname: fr-router\n", "hostname: 2026-11-01 10:00:00\n"),
    ("hostname: fr-router\n", "hostname: 2026-11-01T10:00:00.5-05:30\n"),
    ("hostname: fr-router\n", "hostname: .inf\n"), ("hostname: fr-router\n", "hostname: .nan\n"),
    ("hostname: fr-router\n", "hostname: -.inf\n"), ("hostname: fr-router\n", "hostname: 1e+400\n"),
    ("timezone: Europe/Budapest\n", "timezone: 2026-11-01\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 2026-12-01T18:00:00\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 2026-12-01 18:00:00\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 2026-12-01T18:00:00Z\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 2026-12-01T18:00:00.75+01:00\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 2026-12-01T18:00:00-05:30\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 2026-12-01\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: '2026-12-01'\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 2026-03-29T02:30:00\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 2026-10-25T02:30:00\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 1970-01-01T00:00:00\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 0001-01-01T00:00:00Z\n"),
    ("  expires: 2026-12-01T18:00\n", "  expires: 2026-12-01T18:00:00\n  schedule: {start: '1:00', end: '2:00'}\n"),
    ("  dst_port: 22\n", "  dst_port: 0x16\n"), ("  dst_port: 22\n", "  dst_port: 026\n"),
    ("  dst_port: 22\n", "  dst_port: 0b10110\n"), ("  dst_port: 22\n", "  dst_port: 0:22\n"),
    ("  dst_port: 22\n", "  dst_port: 1:30\n"), ("  dst_port: 22\n", "  dst_port: 22.0\n"),
    ("  dst_port: 22\n", "  dst_port: 2_2\n"), ("  dst_port: 22\n", "  dst_port: yes\n"),
    ("  dst_port: 22\n", "  dst_port: 22-23\n"), ("  dst_port: 22\n", "  dst_port: 2026-11-01\n"),
    ("  dst_port: 22\n", "  dst_port: .nan\n"), ("  dst_port: 22\n", "  dst_port: 18:12:15\n"),
    ("    dst_port: 8443\n", "    dst_port: 0x20FB\n"), ("    to_port: 443\n", "    to_port: on\n"),
    ("  start: '22:00'\n", "  start: 22:00\n"), ("    end: 06:00\n", "    end: '06:00'\n"),
    ("    start: '22:00'\n", "    start: 22:00\n"), ("    start: '22:00'\n", "    start: 1320\n"),
    ("    end: 06:00\n", "    end: 6:00\n"), ("    end: 06:00\n", "    end: 2026-11-01 06:00:00\n"),
    ("    - weekdays\n", "    - 1\n"), ("    - weekdays\n", "    - Mon\n"), ("    - weekdays\n", "    - no\n"),
    ("  enabled: true\n  source_urls", "  enabled: yes\n  source_urls"),
    ("  enabled: true\n  source_urls", "  enabled: on\n  source_urls"),
    ("  enabled: true\n  source_urls", "  enabled: 'true'\n  source_urls"),
    ("  serve_lan: true\n", "  serve_lan: Off\n"), ("  serve_lan: true\n", "  serve_lan: 1\n"),
    ("  drops_per_minute: 20\n", "  drops_per_minute: 0x14\n"),
    ("  drops_per_minute: 20\n", "  drops_per_minute: 20.0\n"),
    ("      id: 30\n", "      id: 036\n"), ("      id: 30\n", "      id: 0:30\n"), ("      id: 30\n", "      id: '30'\n"),
    # keys that aren't strings
    ("zones:\n  wan: {}\n", "zones:\n  wan: {}\n  30: {}\n"), ("zones:\n  wan: {}\n", "zones:\n  wan: {}\n  yes: {}\n"),
    ("zones:\n  wan: {}\n", "zones:\n  wan: {}\n  ~: {}\n"),
    ("zones:\n  wan: {}\n", "zones:\n  wan: {}\n  2026-11-01: {}\n"),
    ("zones:\n  wan: {}\n", "zones:\n  wan: {}\n  1.5: {}\n"), ("zones:\n  wan: {}\n", "zones:\n  wan: {}\n  .nan: {}\n"),
    ("zones:\n  wan: {}\n", "zones:\n  wan: {}\n  ? [a]\n  : {}\n"),
    ("zones:\n  wan: {}\n", "zones:\n  wan: {}\n  wan: {description: again}\n"),
    ("zones:\n  wan: {}\n", "zones:\n  wan: {}\n  'off': {}\n"),
    ("interfaces:\n", "interfaces:\n  5:\n    device: eth5\n    zone: wan\n"),
    ("dhcp:\n", "dhcp:\n  30:\n    range_start: 10.0.0.1\n"), ("dhcp:\n", "dhcp:\n  no:\n    range_start: 10.0.0.1\n"),
    ("dhcp:\n", "dhcp:\n  2026-11-01:\n    range_start: 10.0.0.1\n"),
    ("  categories:\n", "  categories:\n    5:\n    - https://example.org/x\n"),
    ("  hosts:\n", "  hosts:\n    5: 10.73.1.51\n"), ("  hosts:\n", "  hosts:\n    yes: 10.73.1.51\n"),
    ("  hosts:\n", "  hosts:\n    2026-11-01: 10.73.1.51\n"),
    ("  hosts:\n", "  hosts:\n    nas.lan: 10.73.1.51\n"),
    ("local_dns:\n", "local_dns:\n  5: x\n"), ("local_dns:\n", "local_dns:\n  5: x\n  6: y\n"),
    ("local_dns:\n", "local_dns:\n  5: x\n  zz: y\n"), ("local_dns:\n", "local_dns:\n  1.5: x\n  1: y\n  yes: z\n"),
    ("local_dns:\n", "local_dns:\n  2026-11-02: x\n  2026-11-01: y\n"),
    ("local_dns:\n", "local_dns:\n  2026-11-02: x\n  2026-11-01 10:00:00: y\n"),
    ("local_dns:\n", "local_dns:\n  ~: x\n"), ("local_dns:\n", "local_dns:\n  ~: x\n  zz: y\n"),
    ("local_dns:\n", "local_dns:\n  zz: x\n  aa: y\n  Bb: z\n"),
    ("ipv6:\n", "ipv6:\n  5: x\n"), ("ipv6:\n", "ipv6:\n  .inf: x\n  -.inf: y\n  0: z\n"),
    ("ipv6:\n", "ipv6:\n  .nan: x\n"), ("ipv6:\n", "ipv6:\n  2026-11-01T10:00:00Z: x\n  2026-11-01T09:00:00Z: y\n"),
    ("ipv6:\n", "ipv6:\n  2026-11-01T10:00:00Z: x\n  2026-11-01T10:00:00: y\n"),
    ("    port: 443\n", "    port: 443\n    5: x\n"),
    # merges and aliases in a config
    ("zones:\n", "defaults: &d {description: shared}\nzones:\n"),
    ("  wan: {}\n", "  wan: &w {description: WAN}\n  guest: *w\n"),
    ("  wan: {}\n", "  wan: &w {description: WAN}\n  guest: {<<: *w}\n"),
    ("interfaces:\n  wan:\n", "interfaces:\n  wan: &i\n"),
    ("  iot:\n    device: eth1.30\n", "  iot:\n    <<: {zone: lan}\n    device: eth1.30\n"),
    ("rules:\n- name: ssh\n", "rules:\n- &r\n  name: ssh\n"),
    ("- name: lan-out\n", "- *r\n- name: lan-out\n"),
    ("  blocklist:\n  - bad.example\n", "  blocklist: &bl\n  - bad.example\n"),
    ("  allowlist:\n  - example.com\n", "  allowlist:\n  - example.com\n  - !!str 5\n"),
    ("  allowlist:\n  - example.com\n", "  allowlist:\n  - example.com\n  - 5\n"),
    ("  allowlist:\n  - example.com\n", "  allowlist:\n  - example.com\n  - 2026-11-01\n"),
    ("  allowlist:\n  - example.com\n", "  allowlist:\n  - example.com\n  - |\n    x.example\n"),
    ("  allowlist:\n  - example.com\n", "  allowlist:\n  - example.com\n  - \"x.example\\n\"\n"),
    ("  allowlist:\n  - example.com\n", "  allowlist: !!set {example.com}\n"),
    ("  allowlist:\n  - example.com\n", "  allowlist: !!omap [example.com: 1]\n"),
    ("  allowlist:\n  - example.com\n", "  allowlist: !!binary aGVsbG8=\n"),
    ("  allowlist:\n  - example.com\n", "  allowlist: example.com\n"),
    ("  - tiktok\n", "  - !!str tiktok\n"), ("  - tiktok\n", "  - yes\n"),
    ("    description: LAN\n", "    description: 2026-11-01\n"),
    ("    description: LAN\n", "    description: [a, 2026-11-01 10:00:00+05:30]\n"),
    ("    description: LAN\n", "    description: !!float nan\n"),
    ("    description: LAN\n", "    description: &x [*x]\n"),
    ("  - 10.73.1.5/32\n", "  - 10.73.1.5/0x20\n"), ("  - 10.73.1.5/32\n", "  - 167838981\n"),
    ("  - 10.73.1.5/32\n", "  - 0x0A490105\n"), ("    address: 10.73.1.50\n", "    address: 0x0A490132\n"),
    ("    - mac: AA:BB:CC:DD:EE:01\n", "    - mac: 11:22:33:44:55:66\n"),
    ("    - mac: AA:BB:CC:DD:EE:01\n", "    - mac: 01:02:03:04:05:06\n"),
    ("    - mac: AA:BB:CC:DD:EE:01\n", "    - mac: 1:02:03:04:05:06\n"),
    ("  - 10.73.1.1\n", "  - 10.73.1.1\n  - 1:2:3:4\n"),
    ("version: 1\n", "version: 1\n---\nversion: 1\n"), ("version: 1\n", "version: 1\nversion: 2\n"),
    ("version: 1\n", "version: 1\n'version': 2\n"),
]


def _config_text(edit):
    old, new = edit
    if old is None:
        return CONFIG
    assert old in CONFIG, old
    return CONFIG.replace(old, new, 1)


TEXTS = SCALARS + DOCUMENTS + DUMPS + ["a: " + s + "\n" for s in SCALARS if "\n" not in s] + \
    ["- " + s + "\n" for s in SCALARS if "\n" not in s] + ["{a: " + s + "}" for s in SCALARS if "\n" not in s] + \
    [s + ": a\n" for s in SCALARS if "\n" not in s and s]


@pytest.mark.parametrize("index", range(len(TEXTS)))
def test_yaml_text(index):
    try:
        yaml.safe_load(TEXTS[index])
    except Exception:  # recorded by the plugin
        pass


@pytest.mark.parametrize("index", range(len(CONFIG_EDITS)))
def test_yaml_config(index):
    try:
        raw = yaml.safe_load(_config_text(CONFIG_EDITS[index]))
        loader.parse_config(raw)
    except Exception:  # recorded by the plugin
        pass
