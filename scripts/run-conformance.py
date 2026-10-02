#!/usr/bin/env python3
"""Local pinned draft report, with exclusive output outside source repositories."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))
from tools.conformance_preflight import load_fixture
from tools.conformance_runner import run_suite
from tools.kil_profile_adapter import evaluate

PIN_HEAD = '8dda717a51818a5e9ef00e36898ddae6af890230'
PIN_FIXTURE = '2bc1ac15ba1608658dabd392ed60a114dfd6ca9778593a55c11d757a62cf0ebd'
PINS = {
    'spec': ('specifications/software-substrate-execution-profile.md',
             '4932de21f0fec380edaa9e5ad767e44539866f779aa5469ebd3bd6bb67912427'),
    'schema': ('schemas/software-substrate-decision.json',
               '32af0e975fe6c37aa26452bc7d7c9d365eb552ed702a1cf763d7e2a88836a8f2')}


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          capture_output=True, text=True, timeout=10).stdout.strip()


def output_parent(path, fixture, profile_source):
    """Open each parent by descriptor without following symlinks (POSIX)."""
    path = Path(os.path.abspath(path))
    sources = [ROOT, fixture.resolve().parent]
    if profile_source is not None:
        sources.append(profile_source.resolve())
    if any(path == source or path.is_relative_to(source) for source in sources):
        raise ValueError('report must be outside source')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            try:
                os.stat('.git', dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('report must be outside Git source repositories')
        try:
            os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return path, fd
        raise ValueError('refusing existing output or symlink')
    except BaseException:
        os.close(fd)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--profile-root', '--profile-source', dest='profile_root', type=Path,
                        help='optional local checkout at fixed HEAD for spec/schema verification; no fetch')
    parser.add_argument('--spec', type=Path, help='explicit local spec path; requires --profile-root')
    parser.add_argument('--schema', type=Path, help='explicit local schema path; requires --profile-root')
    args = parser.parse_args()
    parent_fd = None
    try:
        if (args.spec is not None or args.schema is not None) and args.profile_root is None:
            raise ValueError('--spec/--schema require --profile-root')
        target, parent_fd = output_parent(args.report, args.fixture, args.profile_root)
        if args.sha256 != PIN_FIXTURE:
            raise ValueError('CLI requires the disclosed draft fixture pin')
        if args.fixture.stat().st_size > 2 * 1024 * 1024:
            raise ValueError('fixture exceeds 2 MiB')
        document = load_fixture(args.fixture, args.sha256)
        if args.profile_root is not None and git(args.profile_root, 'rev-parse', 'HEAD') != PIN_HEAD:
            raise ValueError('profile source HEAD differs from fixed pin')
        pins = {'fixture': {'head': PIN_HEAD, 'sha256': args.sha256,
                            'path': str(args.fixture.resolve()), 'verified': True}}
        for label, (relative, digest) in PINS.items():
            path = getattr(args, label) or (args.profile_root / relative if args.profile_root is not None else None)
            if path is not None:
                if path.stat().st_size > 2 * 1024 * 1024:
                    raise ValueError(f'{label} exceeds 2 MiB')
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise ValueError(f'{label} SHA-256 mismatch')
            pins[label] = {'head': PIN_HEAD if path is not None else None,
                           'expectedHead': PIN_HEAD, 'sha256': digest,
                           'path': str(path.resolve()) if path is not None else relative,
                           'verified': path is not None}
        pins['source'] = {'head': git(ROOT, 'rev-parse', 'HEAD'), 'verified': True}
        dirty = bool(git(ROOT, 'status', '--porcelain', '--untracked-files=all'))
        report = run_suite(document, evaluate, {'pins': pins, 'sourceDirty': dirty,
            'profileSourceDirty': (bool(git(args.profile_root, 'status', '--porcelain', '--untracked-files=all'))
                                   if args.profile_root is not None else None),
            'schemaVectorsExecuted': False, 'schemaVectorCount': len(document.get('schemaVectors', []))})
        raw = json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + '\n'
        fd = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent_fd)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(raw)
        for case in report['cases']:
            print(f"{case['id']} expected={json.dumps(case['expected'], sort_keys=True)} "
                  f"actual={json.dumps(case['actual'], sort_keys=True)} status={case['status']}")
        print(f"totals={report['totals']} dirty={dirty} qualification={report['qualification']}")
        return 0 if report['qualification'] and report['aggregatePass'] else 1
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f'conformance report refused: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 2
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


if __name__ == '__main__':
    raise SystemExit(main())
