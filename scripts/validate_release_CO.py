"""Check the standalone release inventory, hashes, local links and public boundaries."""
from pathlib import Path
from urllib.parse import unquote, urlsplit
import argparse
import hashlib
import json
import re
import sys
import zipfile

PUBLIC = 'hehe-expert-interview'
TEXT = {'.md', '.json', '.yaml', '.yml', '.svg', '.html', '.txt', '.py'}
LINK = re.compile(r'!?\[[^\]]*\]\(([^)]+)\)|(?:href|src)=["\x27]([^"\x27]+)["\x27]')
PRIVATE = re.compile(r'[A-Z]:[/\\](?:Users|LenovoSoftstore|AI-)|file:///|gh[pousr]_[A-Za-z0-9]{20,}|\bAKIA[A-Z0-9]{16}\b', re.I)
FORBIDDEN = {'__pycache__', '_本地维护', '90_历史备份', '.venv', 'node_modules'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(repo):
    errors = []
    for name in ['README.md', 'LICENSE', 'CHANGELOG.md', 'release-manifest.json']:
        if not (repo / name).is_file():
            errors.append('Missing release file: ' + name)
    if errors:
        return errors
    manifest = json.loads((repo / 'release-manifest.json').read_text(encoding='utf-8-sig'))
    runtime = repo / 'skills' / PUBLIC
    if manifest.get('entry_skill') != PUBLIC or manifest.get('required_skills') != []:
        errors.append('Invalid standalone entry or mandatory Skill dependency')
    if set(manifest.get('optional_external_skills', {})) != {'tanzi', 'baojie'}:
        errors.append('Invalid optional Skill declarations')
    entries = sorted(p.parent.name for p in repo.rglob('SKILL.md') if '.git' not in p.parts)
    if entries != [PUBLIC]:
        errors.append('Exactly one installable Skill is required')
    skills = manifest.get('skills', [])
    if len(skills) != 1 or skills[0].get('name') != PUBLIC:
        return errors + ['Invalid runtime inventory']
    expected = set(skills[0].get('required_files', []))
    actual = {p.relative_to(runtime).as_posix() for p in runtime.rglob('*') if p.is_file()}
    if actual != expected or len(expected) != 10:
        errors.append('Runtime inventory mismatch')
    for name in expected:
        path = (runtime / name).resolve()
        if not path.is_relative_to(runtime.resolve()) or not path.is_file():
            errors.append('Missing or unsafe runtime path: ' + name)
            continue
        if digest(path) != manifest.get('public_sha256', {}).get(name):
            errors.append('Runtime hash mismatch: ' + name)
        text = path.read_text(encoding='utf-8-sig')
        if re.search(r'(?<![A-Za-z0-9-])expert-interview(?![A-Za-z0-9-])', text):
            errors.append('Unconverted Skill name: ' + name)
        refs = set(re.findall(r'(?<![A-Za-z0-9-])hehe-[a-z0-9]+(?:-[a-z0-9]+)*', text))
        if refs - {PUBLIC}:
            errors.append('Undeclared external Skill reference: ' + name)
    entry = runtime / 'SKILL.md'
    if entry.is_file() and not re.search(r'^name: ' + PUBLIC + r'\s*$', entry.read_text(encoding='utf-8-sig'), re.M):
        errors.append('Frontmatter name mismatch')
    for name in manifest.get('examples', {}).get('files', []):
        path = (repo / name).resolve()
        if not path.is_relative_to(repo) or not path.is_file():
            errors.append('Missing or unsafe example: ' + name)
    for name, expected_hash in manifest.get('examples', {}).get('unchanged_outline_sha256', {}).items():
        if (repo / name).is_file() and digest(repo / name) != expected_hash:
            errors.append('Example hash mismatch: ' + name)
    for path in repo.rglob('*'):
        rel = path.relative_to(repo)
        if '.git' in rel.parts:
            continue
        if path.is_symlink() or any(part in FORBIDDEN for part in rel.parts) or path.suffix == '.pyc':
            errors.append('Forbidden release path: ' + rel.as_posix())
        if not path.is_file():
            continue
        if path.suffix == '.docx':
            try:
                with zipfile.ZipFile(path) as doc:
                    if doc.testzip():
                        errors.append('Corrupt Word file: ' + rel.as_posix())
                    for part in doc.namelist():
                        if part.endswith(('.xml', '.rels')) and PRIVATE.search(doc.read(part).decode('utf-8', errors='replace')):
                            errors.append('Local path or credential in Word: ' + rel.as_posix())
            except zipfile.BadZipFile:
                errors.append('Invalid Word file: ' + rel.as_posix())
            continue
        if path.suffix.lower() not in TEXT:
            continue
        text = path.read_text(encoding='utf-8-sig')
        # Only this validator contains its own forbidden-pattern literals.
        if rel.as_posix() != 'scripts/validate_release_CO.py':
            if PRIVATE.search(text) or re.search(r'AgentKey|agentkey|0\.2 credits|tanzi-pro', text):
                errors.append('Private path, credential or tooling record: ' + rel.as_posix())
        if path.suffix.lower() not in {'.md', '.svg', '.html'}:
            continue
        for match in LINK.finditer(text):
            raw = (match.group(1) or match.group(2)).strip().strip('<>')
            if raw.startswith(('#', 'data:', 'mailto:')):
                continue
            parsed = urlsplit(raw)
            if parsed.scheme or parsed.netloc:
                continue
            target = (path.parent / unquote(parsed.path)).resolve()
            if not target.is_relative_to(repo) or not target.exists():
                errors.append(f'Broken local link: {rel.as_posix()} -> {raw}')
            if path.is_relative_to(runtime) and not target.is_relative_to(runtime.resolve()):
                errors.append(f'Package-external dependency: {rel.as_posix()} -> {raw}')
    return errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repo', nargs='?', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    issues = validate(args.repo.resolve())
    for issue in issues:
        print('ERROR:', issue)
    if not issues:
        print('Release valid: 1 standalone Skill, 10 runtime files, hashes, local links, examples and public boundaries checked.')
    sys.exit(bool(issues))
