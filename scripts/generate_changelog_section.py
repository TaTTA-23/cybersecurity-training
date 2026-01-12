#!/usr/bin/env python3
"""
Gera uma secção do CHANGELOG.md para usar como release notes.

Uso:
  python3 scripts/generate_changelog_section.py --section "Unreleased" > release_notes.md

O script procura a secção que começa com o cabeçalho indicado e imprime o conteúdo até ao próximo cabeçalho.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


def extract_section(changelog: str, section: str) -> str:
    lines = changelog.splitlines()
    # Normalize header candidates: exact match for the header line
    for i, line in enumerate(lines):
        if line.strip() == section:
            # skip the underline (next line) if present
            start = i + 1
            if start < len(lines) and re.match(r'^[-=]{3,}\s*$', lines[start]):
                start += 1
            # collect until the next header (a line followed by underline)
            out_lines = []
            j = start
            while j < len(lines):
                # lookahead for a header underline
                if j + 1 < len(lines) and re.match(r'^[-=]{3,}\s*$', lines[j + 1]):
                    break
                out_lines.append(lines[j])
                j += 1
            return "\n".join(out_lines).rstrip() + "\n"
    raise SystemExit(f"Section '{section}' not found in CHANGELOG.md")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--changelog', default='CHANGELOG.md', help='Path to CHANGELOG.md')
    p.add_argument('--section', default='Unreleased', help='Section header to extract')
    args = p.parse_args()

    changelog_path = Path(args.changelog)
    if not changelog_path.exists():
        raise SystemExit(f"{changelog_path} does not exist")

    content = changelog_path.read_text(encoding='utf-8')
    notes = extract_section(content, args.section)
    sys.stdout.write(notes)


if __name__ == '__main__':
    main()
