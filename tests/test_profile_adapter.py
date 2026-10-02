"""Honest imported component projections against every pinned request."""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FIXTURE = ROOT / 'tests/fixtures/software-substrate-execution.json'


@pytest.fixture
def adapter():
    def evaluate(request):
        path = ROOT / 'tools/kil_profile_adapter.py'
        assert path.is_file(), 'component adapter is not implemented'
        spec = importlib.util.spec_from_file_location('adapter', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.evaluate(request)
    return evaluate


def requests():
    return [v['request'] for v in json.loads(FIXTURE.read_text())['vectors']]


def test_all_requests_incomplete_and_no_fabricated_envelope(adapter):
    for request in requests():
        original = copy.deepcopy(request)
        result = adapter(request)
        assert request == original
        assert result['unsupported'] and result['observations']['decisionProjectionComplete'] is False
        assert not {'supervision', 'tightenedAtMost', 'autonomyDemand', 'environmentalCapacity'} & result['actual'].keys()
        assert result['actual']['componentDecision']['outcome'] in {'permit', 'deny'}


def test_real_veto_class_authenticity_and_separate_baseline(adapter):
    reqs = requests()
    for index, reason in ((3, 'immutable_veto'), (5, 'class_mismatch'), (11, 'state_unauthentic')):
        result = adapter(reqs[index])
        assert result['actual']['componentDecision']['outcome'] == 'deny'
        assert reason in result['actual']['componentDecision']['reasons']
    result = adapter(reqs[20])
    assert result['actual']['ordinaryAuthorization'] is False
    assert result['actual']['authorizationBaseline']['outcome'] == 'deny'
    assert result['actual']['componentDecision']['outcome'] == 'permit'


def test_no_false_mapping_of_binding_time_capacity_or_repair(adapter):
    reqs = requests()
    for index in (4, 6, 7, 8, 9, 10, 21, 22, 23, 24, 25, 26, 28, 34, 35, 36, 37):
        result = adapter(reqs[index])
        assert result['actual']['componentDecision']['outcome'] == 'permit'
        assert result['unsupported']
    assert adapter(reqs[0]) == adapter(copy.deepcopy(reqs[0]))


@pytest.mark.parametrize('path', [(), ('softwareContext',),
    ('softwareContext', 'magnitudes'), ('softwareContext', 'conditions'),
    ('softwareContext', 'trustedFixtures'), ('softwareContext', 'candidateEnvelope'),
    ('softwareContext', 'candidateEnvelope', 'ceilings'), ('softwareContext', 'existingCeilings')])
def test_unknown_maps_fail_closed(adapter, path):
    request = copy.deepcopy(requests()[0])
    target = request
    for key in path:
        target = target[key]
    target['unknown'] = True
    with pytest.raises(ValueError):
        adapter(request)


def test_bad_controls_fail_closed(adapter):
    for key, value in [('ordinaryAuthorization', 1), ('signatureVerified', 'true')]:
        request = copy.deepcopy(requests()[0])
        request['softwareContext']['trustedFixtures'][key] = value
        with pytest.raises(ValueError):
            adapter(request)
    request = copy.deepcopy(requests()[0])
    del request['softwareContext']['trustedFixtures']['ordinaryAuthorization']
    with pytest.raises(ValueError):
        adapter(request)
