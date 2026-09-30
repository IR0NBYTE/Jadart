#!/usr/bin/env python3
"""Check that the fenced code blocks in the Markdown docs pair up as CommonMark reads.

One missing closing fence does not break one example. Under CommonMark the next fence
closes the block instead, and the fences after it are inverted: examples render as prose
and prose as code. #22 left one in SKILL.md, which agents read, and eight of its
thirteen headings stopped rendering. Nothing noticed, because the file still looks right
in an editor.

A count of fence lines misses some of these. A fence with an info string
(```` ```bash ````) can open a block but never close one, so when one stands where a
closing fence was needed and the total stays even, the count passes while the block
before it runs on. This walks the fences the way CommonMark does and reports:

  unclosed     a block still open at the end of the file
  opener       a fence with an info string where the open block needed a closing fence
  nested       a fence the walk does not model: indented, quoted, on a list marker or a
               footnote definition, or in HTML
  unsupported  a fence other than three backticks, a byte order mark or a NUL, or HTML
               outside the few tags and attributes the check allows, left open on its
               line, with a `<` inside a tag or a comment, an unquoted value that is
               not plain (_PLAIN_VALUE), a closing tag holding more than its name, a
               block tag inside an inline or heading element (_INLINE) or Markdown's
               inline syntax (_SYNTAX), a block left open in a list, a quote or an
               indent, HTML going on from a line of Markdown or followed by a line
               CommonMark can read as a heading (_HEADING), or a comment block never
               closed or holding `--!>`
  missing      a file that was listed but is not there
  unreadable   a file that cannot be read as UTF-8 text

Neither of the first two knows where the missing closing fence belongs: it may belong to
any earlier block, so both list the blocks before the one they report.

The last four fail the check without naming a missing fence. It keeps to a dialect in
which a single missing closing fence always fails it, usually as `unclosed` or `opener`
and otherwise as a refusal where the inverted text puts a fence by HTML, a list, a quote
or an indent, and it refuses anything outside the dialect rather than guess:

- Fences are three backticks. A longer fence, or a tilde one, could close a block the
  missing fence left open and hide it.
- Opening fences sit at column 0, outside lists and quotes, whose rules depend on the
  container; a closing fence may be indented up to three spaces, as CommonMark allows.
- No fence is in HTML. Any line opening with `<` starts HTML that runs to the next
  blank line, or for a comment block at column 0 to the line holding its `-->`, and a
  fence in it is refused. HTML other than a comment block starts after a blank line or
  a comment block, so no emphasis, link or title opened on a line before it can reach
  into it.
- HTML uses only a short list of plain tags and attributes (_ALLOWED, _ALLOWED_ATTRS),
  closes every tag, attribute quote and comment on the line that opens it, writes each
  closing tag as its name and spaces or tabs, leaves no inline or heading element open
  past that line (_CLOSE_ON_LINE) and puts no block tag inside one (_INLINE), leaves no
  block open in a list, a quote or an indent (_STAYS_OPEN), has no line CommonMark can
  read as a heading (_HEADING), holds none of Markdown's inline syntax outside a comment
  block (_SYNTAX), holds no `<` inside a tag or a comment, and quotes any attribute
  value that is not a run of plain characters (_PLAIN_VALUE). Renderers disagree about
  which lines start an HTML block (GitHub's follows CommonMark 0.29, markdown-it the
  0.31 tags) and where some of them end. A line that starts one is copied into the page
  as it is, where a comment, `<script>`, `<select>`, `<details>` or an open quote hides
  everything after it, fences included; a line that opens with an inline tag and goes on
  past it is read as a paragraph instead (alone on its line, the tag starts an HTML
  block too), where CommonMark's own grammar, code spans and escapes decide which `<`
  are tags, so a `<` the walk read as inside a tag or a comment could come out as one,
  and a character one reader takes as a space and another does not can move where a tag
  ends. Keeping to plain tags that open blocks ending at a blank line, with every `<` at
  the start of a tag the walk has read and every unquoted value plain, leaves nothing to
  disagree on. A comment need not close on its line only where it starts a new HTML
  block at column 0, which every renderer reads as a comment block running to its first
  `-->`.
- The file does not start with a byte order mark, which GitHub drops and markdown-it
  keeps as text, so the two pair the fences after it differently, and holds no NUL, with
  which GitHub renders none of it as Markdown.

HTML is checked on a line that opens with `<` and on the lines after it up to a blank
line, or for a comment block up to the line holding its `-->`; inline HTML later in any
other line, in a paragraph, a heading, a list item or a quote, is not. The docs already
keep to the dialect.

    python3 tools/fencecheck.py FILE.md ...     # 0 problems is the contract
    python3 tools/fencecheck.py --tracked       # every `.md` file git tracks or
                                                # would, once added
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: CommonMark ends a line at \n, \r\n or \r and nowhere else. str.splitlines() also
#: breaks on U+2028, \x0b, \x85 and others, which would let an invisible character make
#: content look like a closing fence that CommonMark never sees.
_LINES = re.compile(r"\r\n|\r|\n")

#: A fence line: up to three spaces, three or more backticks or tildes, then the info
#: string. An opening fence is only accepted at column 0; a closing one may be indented,
#: as CommonMark allows.
_FENCE = re.compile(r"^( {0,3})(`{3,}|~{3,})(.*)$")

#: One container marker a line can open with: an indent, a quote, a list marker or a GFM
#: footnote definition (`[^1]:`). No two alternatives match the same text, so a prefix
#: splits only one way and a line costs time linear in its length.
_MARKER = r"(?:[ \t>]|[-*+][ \t]|\d+[.)][ \t]|\[\^[^\]]*\]:)"

#: A fence the walk does not model: indented further, inside a quote, or after one or
#: more list markers or a footnote definition.
_NESTED = re.compile(r"^" + _MARKER + r"+(`{3,}|~{3,})(.*)$")

#: A line opening with `<`, after any indent, quote, list or footnote markers.
_HTML = re.compile(r"^" + _MARKER + r"*<")

#: A line CommonMark can read as a heading, after an indent and quote markers and then
#: `-`, `+` or ordered list markers (a `*` bullet or a footnote label is refused as
#: Markdown syntax anyway): an ATX `#` line, a heading of what it holds, or a setext
#: underline of `=` or `-`, which makes the paragraph above it one. Either heading holds
#: any block its HTML leaves open and, its closer lost inside that block, can wrap
#: everything after it. An underline has no inner spaces (`- - -` is a thematic break),
#: and none of its dashes can be taken for a list marker as well, so a line of them
#: costs time linear in its length.
_HEADING = re.compile(r"[ \t>]*(?:(?:[-+]|\d+[.)])[ \t]+)*(?:#|=+[ \t]*$|-+[ \t]*$)")

#: The HTML tags and attributes an HTML block in the docs may use: the ones they use today
#: (h1, img, table, tr, th, td, code; align, src, alt, width), block tags like them and
#: inline formatting, none of which, closed on its line (_CLOSE_ON_LINE), hides what
#: follows it or changes how a renderer reads the lines after it. Anything else in an
#: HTML block is refused, which keeps out `<pre>`, `<script>`, `<style>`, `<textarea>`,
#: `<select>`, `<details>` and the rest, the tags renderers disagree on (`<search>`,
#: `<source>`), every custom element, and attributes such as `hidden` or `style` that
#: hide what they hold.
_ALLOWED = frozenset((
    "a b br code div em h1 h2 h3 h4 h5 h6 hr i img kbd p span strong sub sup table "
    "tbody td th thead tr").split())
_ALLOWED_ATTRS = frozenset("align alt height href src title width".split())

#: The allowed tags that must close on the line that opens them. Left open, one alone on
#: its line (an HTML block) or a formatting tag such as `<b>` can wrap the rest of the
#: page, and repeated, GitHub keeps the nesting and scales each level down until what
#: follows is too small to read. Only the table structure, `div` and `p` may stay open
#: across lines (_STAYS_OPEN), and only outside a list, a quote or an indent: there the
#: container's closer lands inside the open block, which a browser ignores inside a
#: table and GitHub after a `div`, so that the container wraps everything after it. A
#: `p` is held to the same rule to keep it one rule. `br`, `hr` and `img` are void.
_CLOSE_ON_LINE = frozenset((
    "a b code em h1 h2 h3 h4 h5 h6 i kbd span strong sub sup").split())
_STAYS_OPEN = frozenset("div p table tbody td th thead tr".split())

#: What may stand inside an open inline or heading element on its line. While a block tag
#: there is open, a browser or GitHub can ignore the element's closer or reopen the
#: element after the block, so it can wrap the rest of the page after all; any other tag
#: is refused rather than tell when.
_INLINE = frozenset("a b br code em i img kbd span strong sub sup".split())

#: Markdown's inline syntax, which HTML in the docs does not hold anywhere on its lines,
#: in a tag, a comment, the text between them or a `*` bullet or footnote label before
#: them, which a reader without those can take for text. On a line CommonMark reads as
#: a paragraph, emphasis, strikethrough, a link, an image, a code span or an escape can
#: open around a block tag or swallow a closer, including one on another line of the
#: paragraph or inside a tag CommonMark does not read as one, and then an element wraps
#: the rest of the page. HTML starts after a blank line or a comment block, so its
#: paragraph holds nothing but the lines checked here. The lines of a comment block, from
#: `<!--` at column 0 to the line holding its `-->`, are not read as Markdown, so they
#: may hold them. `&#42;` and the like write the characters.
_SYNTAX = re.compile(r"[*_~\[\]\\`]")

#: A closing tag is its name and optional spaces or tabs before `>`. CommonMark reads an
#: attribute or a `/` there as text and leaves the element open. A form feed, which the
#: 0.31 spec reads as text and GitHub and markdown-it as a space, is refused too.
_CLOSER_END = re.compile(r"[ \t]*>")

#: HTML whitespace, which is not Python's: no vertical tab, no-break or other Unicode
#: space, so a tag a browser reads as one name is not split where it is not.
_WS = " \t\n\f\r"
_TAG_NAME = re.compile(r"[A-Za-z][^ \t\n\f\r/>]*")
_ATTR_NAME = re.compile(r"[^ \t\n\f\r/>=]+")
_EQUALS = re.compile(r"[ \t\n\f\r]*=[ \t\n\f\r]*")
_UNQUOTED = re.compile(r"[^ \t\n\f\r>]+")

#: An unquoted value every reader takes to the same end: CommonMark's grammar, with no
#: character that one of them counts as whitespace where another does not (`\v`, which
#: markdown-it and cmark treat as whitespace around `=`, and no-break and other Unicode
#: spaces, which markdown-it's `\s` does, and U+FEFF, which JavaScript's `\s` does; a
#: browser treats none of them as whitespace), and no control character.
_PLAIN_VALUE = re.compile(r"[^\"'=<>`\s\x00-\x20\x7f-\x9f\ufeff]+")


def _shown(name: str) -> str:
    """A name from the file, escaped unless it is printable ASCII, since it is printed."""
    return name if name.isascii() and name.isprintable() else ascii(name)


def _html_problem(text: str, markdown: bool = True, contained: bool = False):
    """(position, what) of the first thing in `text` that the check does not accept in an
    HTML block, or None. A comment must close in `text`; "<!--" at a position means one
    that does not, which is fine only where a comment block starts. `markdown` is False
    for a line of a comment block, which no renderer reads as Markdown; `contained` is
    True for HTML in a list, a quote or an indent, where no tag may stay open."""
    found = _markup_problem(text, contained)
    if found is not None or not markdown:
        return found
    syntax = _SYNTAX.search(text)
    if syntax is None:
        return None
    html = _HTML.match(text)
    before = html is not None and syntax.start() < html.end() - 1
    return syntax.start(), "marker" if before else "syntax"


def _markup_problem(text: str, contained: bool = False):
    """The first problem with the markup in `text`, read the way a browser reads it: a
    comment is skipped to its end, a tag through its attributes to its `>`, and anything
    inside either is not markup."""
    tracked = _CLOSE_ON_LINE | _STAYS_OPEN if contained else _CLOSE_ON_LINE
    i = 0
    open_tags = {}                   # name: positions of that tag not yet closed
    inline = 0                       # how many of them are inline or heading elements
    while True:
        i = text.find("<", i)
        if i < 0:
            first = min(((p[0], t) for t, p in open_tags.items() if p), default=None)
            if first is None:
                return None
            return first[0], "open" if first[1] in _CLOSE_ON_LINE else "contained"
        if text.startswith("<!--", i):
            end = text.find("-->", i + 2)               # `<!-->` is a closed comment too
            if end < 0:
                # A browser also ends one at `--!>`; what follows it is live even where
                # the walk would treat the line as starting a comment block
                return i, "--!>" if "--!>" in text[i:] else "<!--"
            if "<" in text[i + 4:end]:
                return i, "<in"
            i = end + 3
            continue
        if text.startswith(("<!", "<?"), i):
            return i, text[i:i + 2]
        closing = text.startswith("</", i)
        name = _TAG_NAME.match(text, i + 1 + closing)
        if name is None:
            if closing:
                return i, "</"       # a browser drops it or reads it as a comment
            i += 1                   # `<` and text
            continue
        k = name.end()               # a browser's tag name runs to whitespace, `/`, `>`
        if name.group(0).lower() not in _ALLOWED:
            return i, f"<{_shown(name.group(0).lower())}>"
        if closing:
            end = _CLOSER_END.match(text, k)
            if end is None:
                return i, "closer"
            k = end.end()
        while not closing:           # its attributes, up to the `>` on this line
            while k < len(text) and text[k] in _WS:
                k += 1
            if k >= len(text):
                return i, "tag"
            if text[k] == ">":
                k += 1
                break
            if text[k] == "/":
                k += 1
                continue
            attr = _ATTR_NAME.match(text, k)
            if attr is None:
                return i, "attr"
            if attr.group(0).lower() not in _ALLOWED_ATTRS:
                return i, f"attribute {_shown(attr.group(0).lower())}"
            k = attr.end()
            eq = _EQUALS.match(text, k)
            if eq is None:
                continue
            k = eq.end()
            if k < len(text) and text[k] in "\"'":
                k = text.find(text[k], k + 1) + 1
                if k == 0:
                    return i, "quote"
            else:
                value = _UNQUOTED.match(text, k)
                if value is None:
                    return i, "attr"
                if not _PLAIN_VALUE.fullmatch(value.group(0)):
                    return i, "value"
                k = value.end()
        if "<" in text[i + 1:k]:
            return i, "<in"
        tag = name.group(0).lower()
        if not closing and tag not in _INLINE and inline:
            return i, "block"        # the open element's closer might not end it
        if tag in tracked:
            if not closing:
                open_tags.setdefault(tag, []).append(i)
                inline += tag in _CLOSE_ON_LINE
            elif open_tags.get(tag):
                open_tags[tag].pop()
                inline -= tag in _CLOSE_ON_LINE
        i = k


_WHY = {
    "<!--": "a comment left open at the end of the line; only a comment that starts a "
            "new HTML block at column 0, not right after other HTML and outside a list "
            "or a quote, may run onto the next",
    "--!>": "`--!>`, which ends a comment in a browser but not in a renderer's reading",
    "<!": "a declaration, CDATA section or other `<!` markup in HTML; the docs use none",
    "<?": "a processing instruction in HTML; the docs use none",
    "</": "`</` not followed by a tag name, which a browser drops or reads as a comment "
          "running to the next `>`",
    "<in": "a `<` inside a tag or a comment, which a renderer that reads the line as a "
           "paragraph can make a tag of its own",
    "tag": "a tag not closed on its line",
    "open": "an inline or heading element left open at the end of its line, which in "
            "an HTML block, or for a formatting tag such as `<b>` or `<code>`, can wrap "
            "everything after it",
    "block": "a block tag inside an open inline or heading element, where a browser or "
             "GitHub can ignore or undo the element's closer so that it wraps everything "
             "after it",
    "contained": "a block tag left open in a list, a quote or an indent, where the "
                 "container's closer lands inside it and a browser (in a table) or "
                 "GitHub (after a div) can ignore it, so that the container wraps "
                 "everything after it",
    "heading": "a line CommonMark can read as a heading, an ATX line or a setext "
               "underline of the HTML above it, which then holds any block that HTML "
               "left open and can wrap everything after it",
    "marker": "a `*` bullet or a footnote label before HTML, which a paragraph's "
              "continuation line, or markdown-it, which has no footnotes, reads as text; "
              "use a `-` bullet, and no footnote, before HTML",
    "joined": "HTML that goes on from a line of Markdown, whose emphasis, link or title "
              "can reach into it; start it after a blank line or a comment block",
    "syntax": "Markdown syntax (`*`, `_`, `~`, `[`, `]`, a backslash or a backtick) in "
              "HTML, which on a paragraph line can open emphasis, a link or a code span "
              "that keeps an element open over everything after it; write it as an "
              "entity such as `&#42;`",
    "closer": "a closing tag holding more than its name and spaces or tabs, which "
              "CommonMark can read as text, leaving the element open",
    "attr": "an attribute this check cannot read",
    "value": "an unquoted attribute value holding a quote, `=`, `<`, a backtick, a "
             "control character or a character some readers take as a space, where "
             "renderers and a browser can end it in different places",
    "quote": "an attribute quote not closed on its line",
}


def _is_fence(run: str, info: str) -> bool:
    """A backtick run followed by another backtick is inline code, not a fence."""
    return not (run[0] == "`" and "`" in info)


def _fence_at(pattern, line: str) -> bool:
    m = pattern.match(line)
    return bool(m) and _is_fence(m.group(m.lastindex - 1), m.group(m.lastindex))


def _earlier(starts: list) -> str:
    """The blocks opened before the last one, for a message: at most the last eight."""
    count = len(starts) - 1
    if count <= 0:
        return ""
    shown = ", ".join(str(s) for s in starts[-9:-1])
    if count > 8:
        return f" (the last 8 of {count} earlier blocks opened at lines {shown})"
    return f" (earlier blocks opened at lines {shown})"


def check(text: str) -> list:
    """(line, kind, message) for every problem in one Markdown text, sorted by line."""
    problems = []
    if text.startswith("\ufeff"):
        problems.append((1, "unsupported", "a byte order mark, which renderers read "
                                           "differently"))
        text = text[1:]
    if "\x00" in text:
        nul = len(_LINES.split(text[:text.index("\x00")]))
        problems.append((nul, "unsupported", "a NUL character, with which GitHub renders "
                                             "none of the file as Markdown"))
    open_at = None                   # (line, char, length) of the open fenced block
    starts = []                      # every block opened so far, for the messages
    html = False                     # inside HTML, which runs to the next blank line
    comment = 0                      # line of the comment block the walk is inside
    contained = False                # this HTML has a line in a list, quote or indent
    after_break = True               # the line before was blank or ended a comment block
    for n, line in enumerate(_LINES.split(text), 1):
        at_break, after_break = after_break, not line.strip(" \t")
        if open_at is None and (html or comment or _HTML.match(line)):
            fence = _fence_at(_FENCE, line) or _fence_at(_NESTED, line)
            if fence:
                problems.append((n, "nested", "fence in HTML, which runs to the next "
                                              "blank line, or for a comment block to "
                                              "its `-->`; this check refuses fences "
                                              "there"))
            new_block = not (html or comment)
            block_comment = comment or new_block and line.startswith("<!--")
            html = bool(line.strip(" \t"))
            contained = contained and not new_block or bool(re.match(_MARKER, line))
            if new_block and not block_comment and not at_break:
                problems.append((n, "unsupported", _WHY["joined"]))
                continue
            if not block_comment and _HEADING.match(line):
                problems.append((n, "unsupported", _WHY["heading"]))
                continue
            scan = line
            if comment:
                if "--!>" in line.split("-->", 1)[0]:
                    problems.append((n, "unsupported", _WHY["--!>"]))
                if "-->" not in line:
                    continue         # still inside the comment block
                comment, scan = 0, line[line.index("-->") + 3:]
            bad = _html_problem(scan, not block_comment, contained)
            if bad == (0, "<!--") and new_block:
                # A comment opening new HTML at column 0, which every renderer reads as a
                # comment block running to its first `-->`, blank lines included.
                # Indented, it could be the continuation of a list item, whose HTML ends
                # with the item.
                comment = n
            elif bad and not fence:  # a fence is reported as nested already
                problems.append((n, "unsupported", _WHY.get(
                    bad[1], f"{bad[1]} in HTML, which is not among the few this check "
                            f"allows")))
            elif not bad and block_comment:
                # A comment block ends at the line holding its `-->`, which this one
                # does, and the lines after it are Markdown again.
                html, after_break = False, True
            continue
        m = _FENCE.match(line)
        if open_at is None and (m is None or m.group(1)) and _fence_at(_NESTED, line):
            problems.append((n, "nested", "fence not at column 0 or inside a list, a "
                                          "quote or a footnote; this check models "
                                          "fences at column 0 only"))
            continue
        if not m:
            continue
        run, info = m.group(2), m.group(3).strip(" \t")
        if not _is_fence(run, info):
            continue
        if run != "```":
            problems.append((n, "unsupported", f"a fence of {run!r}; this check models "
                                               "three-backtick fences only"))
            continue
        if open_at is None:
            open_at = (n, run[0], len(run))
            starts.append(n)
            continue
        if info:
            problems.append((n, "opener",
                             f"fence with info string {info!r} inside the block "
                             f"opened at line {open_at[0]}, which it cannot close; the "
                             f"missing closing fence may belong to that block or an "
                             f"earlier one" + _earlier(starts)))
            continue
        open_at = None
    if comment:
        problems.append((comment, "unsupported", "comment block never closed; it hides "
                                                 "everything after it"))
    if open_at is not None:
        problems.append((open_at[0], "unclosed",
                         "block opened here runs to the end of the file; the missing "
                         "closing fence may belong to it or to an earlier block"
                         + _earlier(starts)))
    return sorted(problems)


def tracked() -> list:
    """Every Markdown file in this checkout that git tracks or would track once added,
    as absolute paths, so a new doc is checked before its first commit."""
    def git(*args):
        try:
            out = subprocess.run(["git", "-C", ROOT, *args], capture_output=True)
        except OSError:
            raise SystemExit("fencecheck: git not found; name the Markdown files")
        return out.stdout.decode() if out.returncode == 0 else None
    top = git("rev-parse", "--show-toplevel")
    if top is None or not os.path.samefile(top.strip(), ROOT):
        raise SystemExit("fencecheck: not a git checkout of this repository; "
                         "name the Markdown files")
    listed = git("ls-files", "-z", "--cached", "--others", "--exclude-standard",
                 "--", "*.md") or ""
    paths = (os.path.join(ROOT, p) for p in listed.split("\0") if p)
    return [p for p in paths if os.path.lexists(p)]      # not one deleted but not staged


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    paths = tracked() if args == ["--tracked"] else args
    if not paths:
        print("fencecheck: no files given", file=sys.stderr)
        return 2
    bad = 0
    for path in paths:
        try:
            with open(path, encoding="utf-8", newline="") as f:
                found = check(f.read())
        except FileNotFoundError:
            found = [(0, "missing", "listed but not there")]
        except (OSError, UnicodeDecodeError) as exc:
            found = [(0, "unreadable", str(exc))]
        inside = os.path.abspath(path).startswith(ROOT + os.sep)
        shown = os.path.relpath(path, ROOT) if os.path.isabs(path) and inside else path
        for n, kind, msg in found:
            print(f"{shown}:{n}: {kind}: {msg}")
        bad += len(found)
    print(f"{len(paths)} files: {bad} fence problems")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
