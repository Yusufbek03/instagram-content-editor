#!/usr/bin/env python3
"""Build a skills-only ChatGPT plugin ZIP from an explicit public-file allowlist."""
import argparse
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REFERENCES = ('evaluation.md', 'formats.md', 'business.md', 'portfolio.md', 'workbook.md')


def package_files(root=ROOT):
    source = root / 'chatgpt'
    manifest = json.loads((source / 'plugin.json').read_text())
    interface = manifest['extensions']['com.openai']['interface']
    for key in ('displayName', 'shortDescription'):
        if not 1 <= len(interface[key]) <= 30:
            raise ValueError(key + ' must contain 1–30 characters')
    if len(interface['longDescription']) > 4000:
        raise ValueError('longDescription too long')
    if len(interface.get('defaultPrompt', [])) > 3 or any(len(p) > 128 for p in interface.get('defaultPrompt', [])):
        raise ValueError('Invalid starter prompts')
    files = {
        'plugin.json': (source / 'plugin.json').read_bytes(),
        'README.md': (source / 'README.md').read_bytes(),
        'assets/icon.svg': (source / 'icon.svg').read_bytes(),
        'skills/instagram-content-editor/SKILL.md': (source / 'SKILL.md').read_bytes(),
        'skills/instagram-content-editor/references/connections.md': (source / 'connections.md').read_bytes(),
        'skills/instagram-get-started/SKILL.md': (source / 'GET-STARTED.md').read_bytes(),
    }
    for name in REFERENCES:
        files['skills/instagram-content-editor/references/' + name] = (root / 'references' / name).read_bytes()
    onboarding = manifest['extensions']['com.openai']['onboardingSkill'].removeprefix('./')
    for path in (onboarding, interface['composerIcon'].removeprefix('./'), interface['logo'].removeprefix('./')):
        if path not in files:
            raise ValueError('Referenced resource is not packaged: ' + path)
    icon = ET.fromstring(files['assets/icon.svg'])
    width, height = float(icon.attrib['width']), float(icon.attrib['height'])
    if width != height or width < 48:
        raise ValueError('Plugin icon must be square and at least 48 pixels')
    for name, data in files.items():
        if name.endswith('/SKILL.md'):
            text = data.decode()
            if not re.match(r'^---\nname: [a-z0-9-]+\ndescription:', text):
                raise ValueError('Invalid skill frontmatter: ' + name)
        if name.endswith('.md'):
            for link in re.findall(r'\]\(([^)]+)\)', data.decode()):
                if '://' in link or link.startswith('#'):
                    continue
                target = (Path(name).parent / link.split('#', 1)[0]).as_posix()
                if target not in files:
                    raise ValueError('Broken package link: ' + target)
    return files


def build(output, root=ROOT):
    files = package_files(root)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Fixed order and timestamp make the same sources produce identical archives.
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 9, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    return len(files)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build the ChatGPT plugin, without local CLI/OAuth dependencies.')
    parser.add_argument('output', type=Path, help='Destination ZIP file')
    args = parser.parse_args()
    print('Packaged %s files: %s' % (build(args.output), args.output))
