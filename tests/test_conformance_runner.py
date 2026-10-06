"""Contract tests for actual evaluation, never fixture-derived answers."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FIXTURE = ROOT / 'tests/fixtures/software-substrate-execution.json'
DIGEST = '2bc1ac15ba1608658dabd392ed60a114dfd6ca9778593a55c11d757a62cf0ebd'


@pytest.fixture
def runner():
    class LazyRunner:
        def run_suite(self, *args):
            path = ROOT / 'tools/conformance_runner.py'
            assert path.is_file(), 'report harness is not implemented'
            spec = importlib.util.spec_from_file_location('runner', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module.run_suite(*args)
    return LazyRunner()


def suite(expect=None):
    return {'profile': 'software-substrate-execution', 'vectors': [
        {'id': 'one', 'request': {'nested': {'value': 1}},
         'expect': expect or {'decision': 'allow'}}]}


def response(actual=None, unsupported=None):
    return {'actual': actual if actual is not None else {'decision': 'allow'},
            'unsupported': unsupported or [], 'observations': {}}


def run(runner, document=None, adapter=None, dirty=False):
    return runner.run_suite(document or suite(), adapter or (lambda r: response()),
                            {'sourceDirty': dirty, 'profileSourceDirty': False, 'pins': clean_pins()})


def clean_pins():
    return {name: {'head': 'a' * 40, 'sha256': 'b' * 64, 'verified': True}
            for name in ('fixture', 'spec', 'schema', 'source')}


def test_crash_is_error_never_pass(runner):
    def crash(request):
        raise RuntimeError('crash')
    report = run(runner, adapter=crash)
    assert report['totals']['error'] == 1
    assert not report['aggregatePass'] and not report['qualification']
    assert report['cases'][0]['expected'] == {'decision': 'allow'}
    assert report['cases'][0]['actual'] == {}
    assert report['cases'][0]['rationale']


@pytest.mark.parametrize('adapter,status', [
    (lambda r: response({'decision': 'deny'}), 'fail'),
    (lambda r: response({}), 'unsupported'),
    (lambda r: response(unsupported=['signature']), 'unsupported'),
    (lambda r: {'actual': []}, 'error'),
    (lambda r: response({'decision': True}), 'error'),
])
def test_statuses(runner, adapter, status):
    report = run(runner, adapter=adapter)
    assert report['cases'][0]['status'] == status
    assert not report['aggregatePass']


def test_partial_mismatch_retained(runner):
    case = run(runner, adapter=lambda r: response({'decision': 'deny'}, ['profile']))['cases'][0]
    assert case['status'] == 'unsupported'
    assert case['mismatches'] and case['unsupported'] == ['profile']


def component_outputs():
    return {
        'componentDecision': {'requestId': 'synthetic', 'stateId': 'synthetic',
            'mode': 'signed_state_only', 'outcome': 'permit', 'reasons': ['permitted'],
            'signedCharge': '1', 'decayedCharge': '1', 'effectiveCharge': '1'},
        'ordinaryAuthorization': True,
        'authorizationBaseline': {'track': 'credential_policy_baseline', 'outcome': 'permit',
            'reasons': ['baseline_permitted'], 'decisionDigest': 'a' * 64},
        'decisionProjectionComplete': True,
    }


@pytest.mark.parametrize('extension', [
    {'undeclaredComparator': 'nonsense'},
    {'ordinaryAuthorization': 1},
    {'decisionProjectionComplete': 1},
    {'undefinedRecorded': 1},
    {'componentDecision': []},
    {'authorizationBaseline': []},
])
def test_unknown_or_malformed_actual_extensions_cannot_qualify(runner, extension):
    report = run(runner, adapter=lambda r: response({'decision': 'allow', **extension}))
    assert report['cases'][0]['status'] == 'error'
    assert not report['qualification'] and not report['aggregatePass']


def test_declared_component_outputs_and_freeform_observations(runner):
    result = response({'decision': 'allow', **component_outputs()})
    result['observations'] = {'undeclaredComparator': 'diagnostic only',
                              'arbitrary': {'nested': [True, 'note', 1]}}
    report = run(runner, adapter=lambda r: result)
    assert report['qualification']
    assert report['cases'][0]['observations'] == result['observations']


@pytest.mark.parametrize('expected', [
    {'identicalResultRequired': False},
    {'autonomyDemandNotLessThanCompared': False},
    {'environmentalCapacityNotGreaterThanCompared': False},
    {'identicalResultRequired': False, 'autonomyDemandNotLessThanCompared': False,
     'environmentalCapacityNotGreaterThanCompared': False, 'repeatCount': 2},
    {'tightenedAtMost': {}},
])
def test_vacuous_expectations_rejected_before_adapter(runner, expected):
    def forbidden(request):
        pytest.fail('adapter invoked for vacuous expectation')
    with pytest.raises(ValueError):
        run(runner, suite(expected), forbidden)


def test_compare_to_does_not_make_inactive_expectation_active(runner):
    document = suite({'compareTo': 'base', 'identicalResultRequired': False})
    document['vectors'].append({'id': 'base', 'request': {}, 'expect': {'decision': 'allow'}})
    with pytest.raises(ValueError):
        run(runner, document, lambda r: response({}))


def test_false_ordinary_expectation_remains_active(runner):
    report = run(runner, suite({'undefinedRecorded': False}),
                 lambda r: response({'undefinedRecorded': False}))
    assert report['qualification']


@pytest.mark.parametrize('decision', ['allow', 'deny'])
def test_explicit_incomplete_actual_projection_cannot_qualify(runner, decision):
    report = run(runner, adapter=lambda r: response(
        {'decision': decision, 'decisionProjectionComplete': False}))
    case = report['cases'][0]
    assert case['status'] == 'unsupported'
    assert 'decisionProjectionComplete' in str(case['unsupported'])
    assert not report['qualification'] and not report['aggregatePass']
    if decision == 'deny':
        assert case['mismatches']


def test_expectation_isolation_deep_copy_and_repeat(runner):
    document = suite({'decision': 'allow', 'repeatCount': 3, 'identicalResultRequired': True})
    original = copy.deepcopy(document)
    received = []
    def adapter(request):
        assert set(request) == {'nested'}
        received.append(request)
        return response()
    report = run(runner, document, adapter)
    assert report['aggregatePass'] and len(received) == 3
    assert len({id(r['nested']) for r in received}) == 3
    assert document == original


def test_mutation_detected_without_affecting_fixture(runner):
    document = suite()
    def mutate(request):
        request['nested']['value'] = 2
        return response()
    report = run(runner, document, mutate)
    assert report['cases'][0]['status'] == 'error'
    assert document['vectors'][0]['request']['nested']['value'] == 1


def test_nondeterminism_including_observations(runner):
    count = 0
    def changing(request):
        nonlocal count
        count += 1
        result = response()
        result['observations'] = {'count': count}
        return result
    report = run(runner, suite({'decision': 'allow', 'repeatCount': 2}), changing)
    assert report['cases'][0]['status'] == 'fail'
    assert 'nondeterministic' in str(report['cases'][0]['rationale'])


def test_dirty_disqualifies_otherwise_passing_report(runner):
    report = run(runner, dirty=True)
    assert report['totals']['pass'] == 1
    assert not report['qualification'] and not report['aggregatePass']
    assert report['sourceDirty'] is True
    assert report['reportVersion'] and report['toolchain'] and report['pins']
    assert report['evidenceLane'] and report['limits']


@pytest.mark.parametrize('expect,actual,status', [
    ({'undefinedRecorded': True}, {'undefinedRecorded': 1}, 'error'),
    ({'tightenedAtMost': {'effectBytes': 4}}, {'tightenedAtMost': {'effectBytes': 3}}, 'pass'),
    ({'tightenedAtMost': {'effectBytes': 4}}, {'tightenedAtMost': {'effectBytes': 5}}, 'fail'),
    ({'tightenedAtMost': {'effectBytes': 4}}, {'tightenedAtMost': {'effectBytes': True}}, 'error'),
    ({'decisionNotLooserThan': 'escalate'}, {'decision': 'deny'}, 'pass'),
    ({'decisionNotLooserThan': 'escalate'}, {'decision': 'allow'}, 'fail'),
    ({'supervisionAtLeast': 'regulated'}, {'supervision': 'silent_veto'}, 'pass'),
    ({'supervisionAtLeast': 'regulated'}, {'supervision': 'stable'}, 'fail'),
])
def test_typed_values_and_ordered_bounds(runner, expect, actual, status):
    assert run(runner, suite(expect), lambda r: response(actual))['cases'][0]['status'] == status


@pytest.mark.parametrize('mutation', [
    lambda d: d.update(unknown=True),
    lambda d: d['vectors'][0].update(unknown=True),
    lambda d: d['vectors'][0].update(setup={'authority': True}),
    lambda d: d['vectors'][0].update(expect={'compareTo': 'missing'}),
    lambda d: d['vectors'][0].update(expect={'compareTo': 'one'}),
    lambda d: d['vectors'][0].update(expect={'autonomyDemandNotLessThanCompared': True}),
    lambda d: d['vectors'][0].update(expect={'decisionNotLooserThan': 'permit'}),
    lambda d: d['vectors'][0].update(expect={'supervisionAtLeast': 'unknown'}),
    lambda d: d['vectors'][0].update(expect={'undefinedRecorded': 1}),
    lambda d: d['vectors'][0].update(expect={'tightenedAtMost': {'unknown': 1}}),
    lambda d: d['vectors'][0].update(expect={'tightenedAtMost': {'effectBytes': 2**53}}),
    lambda d: d['vectors'][0].update(expect={'repeatCount': True}),
    lambda d: d['vectors'][0].update(expect={'repeatCount': 101}),
    lambda d: d['vectors'][0].update(expect={'repeatCount': 0}),
    lambda d: d['vectors'][0].update(request={'bad': float('nan')}),
])
def test_invalid_documents_rejected_before_adapter(runner, mutation):
    document = suite()
    mutation(document)
    def forbidden(request):
        pytest.fail('adapter invoked for invalid document')
    with pytest.raises(ValueError):
        run(runner, document, forbidden)


def test_compare_uses_independent_actual_not_candidate_envelope(runner):
    document = suite({'compareTo': 'base', 'autonomyDemandNotLessThanCompared': True,
                      'environmentalCapacityNotGreaterThanCompared': True})
    document['vectors'][0]['request'] = {'index': 1, 'candidateEnvelope': {'autonomyDemand': 100}}
    document['vectors'].append({'id': 'base', 'request': {'index': 0}, 'expect': {'decision': 'allow'}})
    def adapter(request):
        return response({'decision': 'allow', 'autonomyDemand': [2, 1][request['index']],
                         'environmentalCapacity': [1, 2][request['index']]})
    assert run(runner, document, adapter)['cases'][0]['status'] == 'fail'
    assert run(runner, document, lambda r: response())['cases'][0]['status'] == 'unsupported'


def cli(report):
    return subprocess.run([sys.executable, str(ROOT / 'scripts/run-conformance.py'),
                           '--fixture', str(FIXTURE), '--sha256', DIGEST,
                           '--report', str(report)], capture_output=True, text=True, cwd='/')


def test_cli_reports_38_unsupported_nonzero(tmp_path):
    checked_dirty = bool(subprocess.run(
        ['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=all'],
        check=True, capture_output=True, text=True).stdout.strip())
    target = tmp_path / 'report.json'
    result = cli(target)
    assert result.returncode == 1, result.stderr
    report = json.loads(target.read_text())
    assert len(report['cases']) == 38 and report['totals']['pass'] == 0
    assert report['totals']['unsupported'] == 38
    assert 'expected=' in result.stdout and 'actual=' in result.stdout and 'status=' in result.stdout
    assert report['pins']['spec']['sha256'].startswith('4932de21')
    assert report['pins']['spec']['verified'] is False
    assert report['pins']['spec']['head'] is None
    assert type(report['sourceDirty']) is bool
    assert report['sourceDirty'] is checked_dirty


def test_fixed_fixture_digest():
    import hashlib
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == DIGEST


def test_cli_rejects_arbitrary_digest(tmp_path):
    target = tmp_path / 'report.json'
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/run-conformance.py'),
        '--fixture', str(FIXTURE), '--sha256', '0' * 64, '--report', str(target)],
        capture_output=True, text=True, cwd='/')
    assert result.returncode == 2 and not target.exists()


def test_metadata_cannot_default_to_green(runner):
    for metadata in ({}, {'sourceDirty': False}, {'sourceDirty': False, 'pins': {}},
                     {'sourceDirty': 0, 'pins': clean_pins()}):
        with pytest.raises(ValueError):
            runner.run_suite(suite(), lambda r: response(), metadata)
    pins = clean_pins()
    pins['spec']['verified'] = False
    report = runner.run_suite(suite(), lambda r: response(),
                              {'sourceDirty': False, 'profileSourceDirty': False, 'pins': pins})
    assert not report['qualification']


@pytest.mark.parametrize('mutate', [
    lambda m: m.pop('profileSourceDirty'),
    lambda m: m.update(profileSourceDirty=0),
    lambda m: m['pins']['spec'].update(sha256=123),
    lambda m: m['pins']['spec'].update(head=123),
    lambda m: m['pins']['spec'].pop('verified'),
    lambda m: m['pins'].pop('schema'),
])
def test_malformed_required_metadata_rejected(runner, mutate):
    metadata = {'sourceDirty': False, 'profileSourceDirty': False, 'pins': clean_pins()}
    mutate(metadata)
    with pytest.raises(ValueError):
        runner.run_suite(suite(), lambda r: response(), metadata)


def test_actual_ordered_comparison_preserves_tighter_baseline(runner):
    document = suite({'compareTo': 'base', 'decisionNotLooserThan': 'allow',
                      'supervisionAtLeast': 'stable'})
    document['vectors'][0]['request'] = {'baseline': False}
    document['vectors'].append({'id': 'base', 'request': {'baseline': True},
                               'expect': {'decision': 'deny'}})
    def adapter(request):
        return response({'decision': 'deny' if request['baseline'] else 'allow',
                         'supervision': 'silent_veto' if request['baseline'] else 'stable'})
    assert run(runner, document, adapter)['cases'][0]['status'] == 'fail'


def test_cli_detects_untracked_source_in_portable_checkout(tmp_path):
    checkout = tmp_path / 'source'
    checkout.mkdir()
    for name in ('tools', 'scripts', 'src'):
        shutil.copytree(ROOT / name, checkout / name, ignore=shutil.ignore_patterns('__pycache__'))
    fixture = checkout / 'fixture.json'
    shutil.copyfile(FIXTURE, fixture)
    def git(*args):
        subprocess.run(['git', '-C', str(checkout), *args], check=True, capture_output=True)
    git('init', '-q')
    git('add', '.')
    git('-c', 'user.name=Harness Test', '-c', 'user.email=harness@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'synthetic test checkout')
    target = tmp_path / 'clean-report.json'
    def execute(target):
        return subprocess.run([sys.executable, str(checkout / 'scripts/run-conformance.py'),
            '--fixture', str(fixture), '--sha256', DIGEST, '--report', str(target)],
            capture_output=True, text=True, cwd='/')
    assert execute(target).returncode == 1
    assert json.loads(target.read_text())['sourceDirty'] is False
    (checkout / 'untracked-source.py').write_text('# synthetic source\n')
    target = tmp_path / 'dirty-report.json'
    assert execute(target).returncode == 1
    assert json.loads(target.read_text())['sourceDirty'] is True


def test_cli_refuses_any_git_source_destination(tmp_path):
    source = tmp_path / 'other-source'
    source.mkdir()
    (source / '.git').mkdir()
    target = source / 'report.json'
    assert cli(target).returncode == 2
    assert not target.exists()


def test_cli_explicit_metadata_paths_require_pinned_root(tmp_path):
    target = tmp_path / 'report.json'
    command = [sys.executable, str(ROOT / 'scripts/run-conformance.py'),
        '--fixture', str(FIXTURE), '--sha256', DIGEST, '--report', str(target)]
    result = subprocess.run(command + ['--spec', str(FIXTURE), '--schema', str(FIXTURE)],
                            capture_output=True, text=True)
    assert result.returncode == 2
    assert 'require --profile-root' in result.stderr
    result = subprocess.run(command + ['--profile-root', str(ROOT)], capture_output=True, text=True)
    assert result.returncode == 2 and 'fixed pin' in result.stderr
    assert not target.exists()


def test_retained_response_buffers_cannot_rewrite_snapshots(runner):
    buffer = response()
    count = 0
    def adapter(request):
        nonlocal count
        count += 1
        if count > 1:
            buffer['actual']['decision'] = 'deny'
        return buffer
    report = run(runner, suite({'decision': 'allow', 'repeatCount': 2}), adapter)
    assert report['cases'][0]['actual']['decision'] == 'allow'
    assert report['cases'][0]['status'] == 'fail'
    buffer['actual']['decision'] = 'escalate'
    assert report['cases'][0]['repetitions'][1]['actual']['decision'] == 'deny'


def test_retained_request_mutation_is_detected(runner):
    requests = []
    def adapter(request):
        if requests:
            requests[0]['nested']['value'] = 99
        requests.append(request)
        return response()
    report = run(runner, suite({'decision': 'allow', 'repeatCount': 2}), adapter)
    assert report['cases'][0]['status'] == 'error'


def test_original_document_and_metadata_cannot_rewrite_report(runner):
    document = suite()
    metadata = {'sourceDirty': False, 'profileSourceDirty': False, 'pins': clean_pins()}
    def adapter(request):
        document['vectors'][0]['expect']['decision'] = 'deny'
        metadata['pins']['spec']['verified'] = False
        return response()
    report = runner.run_suite(document, adapter, metadata)
    assert report['qualification'] is True
    assert report['cases'][0]['expected']['decision'] == 'allow'
    assert report['metadata']['pins']['spec']['verified'] is True


def test_identical_check_needs_two_samples(runner):
    with pytest.raises(ValueError):
        run(runner, suite({'decision': 'allow', 'repeatCount': 1, 'identicalResultRequired': True}))
    calls = []
    report = run(runner, suite({'identicalResultRequired': True}),
                 lambda r: calls.append(r) or response())
    assert len(calls) == 2 and report['aggregatePass']


def test_cli_rejects_symlink_parent_and_fixture_source_output(tmp_path):
    parent = tmp_path / 'parent'
    parent.mkdir()
    link = tmp_path / 'linked-parent'
    link.symlink_to(parent, target_is_directory=True)
    assert cli(link / 'report.json').returncode == 2
    assert not (parent / 'report.json').exists()
    assert cli(FIXTURE.parent / 'forbidden.json').returncode == 2


def test_cli_refuses_overwrite_symlink_and_source_output(tmp_path):
    existing = tmp_path / 'existing.json'
    existing.write_text('preserve')
    assert cli(existing).returncode != 0
    assert existing.read_text() == 'preserve'
    link = tmp_path / 'link.json'
    link.symlink_to(tmp_path / 'absent.json')
    assert cli(link).returncode != 0
    assert not (tmp_path / 'absent.json').exists()
    assert cli(ROOT / 'forbidden-report.json').returncode != 0
    assert not (ROOT / 'forbidden-report.json').exists()
