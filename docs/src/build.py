#!/usr/bin/env python3
"""Build the SENA PDFs from the Markdown sources in this directory.

Usage:  python3 build.py [name ...]     (no args = build all)
Requires: python3-markdown, libreoffice (soffice) on PATH.
"""
import re, subprocess, sys, pathlib, markdown

SRC = pathlib.Path(__file__).resolve().parent
OUT = SRC.parent

CSS = """
@page { margin: 2.2cm 2cm; }
body { font-family: 'Liberation Serif', Georgia, serif; font-size: 11pt; line-height: 1.45; color: #111; }
h1 { font-size: 20pt; margin: 0 0 0.6em 0; page-break-after: avoid; }
h2 { font-size: 15pt; margin: 1.4em 0 0.4em 0; page-break-after: avoid; }
h3 { font-size: 12.5pt; margin: 1.1em 0 0.3em 0; page-break-after: avoid; }
h4 { font-size: 11pt; margin: 0.9em 0 0.3em 0; page-break-after: avoid; }
p { margin: 0.45em 0; }
ul, ol { margin: 0.4em 0 0.4em 1.4em; }
li { margin: 0.22em 0; }
code { font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace; font-size: 9.5pt; }
pre { font-family: 'Liberation Mono', 'DejaVu Sans Mono', monospace; font-size: 9pt;
      background: #f4f4f4; padding: 0.7em; margin: 0.6em 0; page-break-inside: avoid; }
table { border-collapse: collapse; width: 100%; margin: 0.7em 0; font-size: 9.5pt;
        page-break-inside: avoid; }
th, td { border: 1px solid #999; padding: 4px 7px; text-align: left; vertical-align: top; }
th { background: #eaeaea; font-weight: bold; }
blockquote { margin: 0.7em 0 0.7em 1em; padding-left: 0.9em; border-left: 3px solid #bbb; color: #333; }
hr { border: none; border-top: 1px solid #bbb; margin: 1.4em 0; }
"""


def _fix_tables(html: str) -> str:
    """LibreOffice's HTML filter ignores most stylesheet rules but honours the
    legacy table attributes and inline styles, so express table formatting that
    way rather than through the stylesheet."""
    html = html.replace(
        "<table>", '<table border="1" cellpadding="4" cellspacing="0">')
    html = html.replace("<th>", '<th align="left" style="background-color:#eaeaea">')
    # Shrink monospaced identifiers inside tables so long ones are not broken
    # mid-token across two lines, and widen a first column that holds nothing
    # but identifiers, which LibreOffice otherwise sizes too narrow for them.
    def fix(m):
        t = re.sub(r"<code>", '<code style="font-size:8pt">', m.group(0))
        if re.search(r"<td><code\b[^>]*>[^<]{14,}</code></td>", t):
            t = t.replace("<td><code", '<td width="27%"><code', 1)
            t = t.replace('<th align="left"', '<th width="27%" align="left"', 1)
        return t
    return re.sub(r"<table\b.*?</table>", fix, html, flags=re.S)


def build(md_path: pathlib.Path) -> None:
    html_body = markdown.markdown(
        md_path.read_text(encoding="utf-8"),
        extensions=["tables", "fenced_code", "sane_lists", "attr_list"],
    )
    html_body = _fix_tables(html_body)
    html = (f'<html><head><meta charset="utf-8"><title>{md_path.stem}</title>'
            f"<style>{CSS}</style></head><body>{html_body}</body></html>")
    tmp = md_path.with_suffix(".html")
    tmp.write_text(html, encoding="utf-8")
    subprocess.run(
        ["soffice", "--headless", "--convert-to", "pdf", "--outdir", str(OUT), str(tmp)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    tmp.unlink()
    print(f"  {md_path.name} -> {OUT.name}/{md_path.stem}.pdf")

if __name__ == "__main__":
    names = sys.argv[1:]
    targets = ([SRC / f"{n}.md" if not n.endswith(".md") else SRC / n for n in names]
               if names else sorted(SRC.glob("SENA_*.md")))
    for t in targets:
        build(t)
