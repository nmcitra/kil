"""Bounded, request-only draft report harness; not runtime certification."""
from copy import deepcopy
from importlib.metadata import PackageNotFoundError, version
import math
import platform
import re
import sys

from tools.conformance_preflight import EXPECTATIONS

SAFE_INTEGER = 2**53 - 1
CEILINGS = frozenset({'effectBytes', 'affectedObjects', 'fanoutTargets'})
DECISIONS = ('allow', 'escalate', 'deny')
SUPERVISION = ('stable', 'regulated', 'assisted', 'silent_veto')
ROOT_FIELDS = frozenset({'profile', 'ktpReleaseBaseline', 'status', 'note',
    'timeNotation', 'normativeExpectations', 'vectors', 'schemaFixtureNote',
    'schemaFixture', 'schemaVectors'})
BOOLEAN_EXPECTATIONS = frozenset({'undefinedRecorded', 'identicalResultRequired',
    'autonomyDemandNotLessThanCompared', 'environmentalCapacityNotGreaterThanCompared'})
ACTUAL_FIELDS = frozenset({'decision', 'supervision', 'tightenedAtMost',
    'undefinedRecorded', 'autonomyDemand', 'environmentalCapacity',
    'componentDecision', 'ordinaryAuthorization', 'authorizationBaseline',
    'decisionProjectionComplete'})
REPORT_VERSION = 'kil-draft-conformance-report/1'


def validate_json(value, integer_limit=SAFE_INTEGER):
    """Reject non-JSON types, unsafe numbers, Unicode errors and resource abuse."""
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > 100000 or depth > 32:
            raise ValueError('JSON node/depth limit exceeded')
        kind = type(item)
        if kind is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError('JSON object keys must be strings')
                pending.extend(((key, depth + 1), (child, depth + 1)))
        elif kind is list:
            pending.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item) > 8192:
                raise ValueError('JSON string limit exceeded')
            try:
                item.encode('utf-8', errors='strict')
            except UnicodeError as exc:
                raise ValueError('invalid Unicode') from exc
        elif kind is int:
            if abs(item) > integer_limit:
                raise ValueError('unsafe JSON integer')
        elif kind is float:
            if not math.isfinite(item) or abs(item) > SAFE_INTEGER:
                raise ValueError('unsafe JSON number')
        elif item is not None and kind is not bool:
            raise ValueError('not a JSON value')


def fields(value, allowed, required=()):
    if type(value) is not dict or set(value) - set(allowed) or set(required) - set(value):
        raise ValueError('missing or undeclared object fields')


def enum(value, choices):
    if type(value) is not str or value not in choices:
        raise ValueError('invalid ordered comparator value')


def ceilings(value):
    fields(value, CEILINGS)
    if not value or any(type(n) is not int or not 0 <= n <= SAFE_INTEGER for n in value.values()):
        raise ValueError('ceilings must be named nonnegative safe integers')


def typed_equal(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(typed_equal(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(typed_equal(a, b) for a, b in zip(left, right))
    return left == right


def validate_document(document):
    # Schema negative-test mutation values include an intentionally unsafe count.
    # They are bounded metadata, never runtime inputs or authority.
    validate_json(document, integer_limit=2**63 - 1)
    fields(document, ROOT_FIELDS, ('profile', 'vectors'))
    if document['profile'] != 'software-substrate-execution':
        raise ValueError('wrong profile')
    for name in ROOT_FIELDS - {'vectors', 'normativeExpectations', 'schemaFixture', 'schemaVectors'}:
        if name in document and type(document[name]) is not str:
            raise ValueError('root description must be a string')
    if 'normativeExpectations' in document:
        names = document['normativeExpectations']
        if type(names) is not list or any(type(n) is not str or n not in EXPECTATIONS for n in names):
            raise ValueError('unknown normative expectation')
    vectors = document['vectors']
    if type(vectors) is not list or not 1 <= len(vectors) <= 1000:
        raise ValueError('vector count must be 1..1000')
    identifiers = set()
    for vector in vectors:
        validate_json(vector)
        fields(vector, {'id', 'request', 'expect', 'note', 'setup'}, ('id', 'request', 'expect'))
        identifier = vector['id']
        if type(identifier) is not str or not identifier.strip() or identifier in identifiers:
            raise ValueError('empty or duplicate vector ID')
        identifiers.add(identifier)
        if 'note' in vector and type(vector['note']) is not str:
            raise ValueError('vector note must be a string')
        if 'setup' in vector:
            fields(vector['setup'], ())  # No setup fields declared in this suite.
        if type(vector['request']) is not dict:
            raise ValueError('request must be an object')
        expected = vector['expect']
        fields(expected, EXPECTATIONS)
        if not expected:
            raise ValueError('empty expectation')
        for key, value in expected.items():
            if key in BOOLEAN_EXPECTATIONS and type(value) is not bool:
                raise ValueError('boolean expectation required')
            if key in {'decision', 'decisionNotLooserThan'}:
                enum(value, DECISIONS)
            if key in {'supervision', 'supervisionAtLeast'}:
                enum(value, SUPERVISION)
            if key == 'tightenedAtMost':
                ceilings(value)
            if key == 'repeatCount' and (type(value) is not int or not 1 <= value <= 100):
                raise ValueError('repeatCount must be 1..100')
        result_checks = {'decision', 'supervision', 'tightenedAtMost', 'undefinedRecorded',
                         'decisionNotLooserThan', 'supervisionAtLeast'}
        enabled_checks = ('identicalResultRequired', 'autonomyDemandNotLessThanCompared',
                          'environmentalCapacityNotGreaterThanCompared')
        if not (set(expected) & result_checks or any(expected.get(key) is True for key in enabled_checks)):
            raise ValueError('no result expectation')
        if expected.get('identicalResultRequired') and expected.get('repeatCount', 2) < 2:
            raise ValueError('identicalResultRequired needs at least two repetitions')
    for vector in vectors:
        expected = vector['expect']
        if 'compareTo' in expected:
            reference = expected['compareTo']
            if type(reference) is not str or reference not in identifiers or reference == vector['id']:
                raise ValueError('missing or invalid comparison baseline')
        if any(expected.get(key) for key in (
                'autonomyDemandNotLessThanCompared', 'environmentalCapacityNotGreaterThanCompared')):
            if 'compareTo' not in expected:
                raise ValueError('comparison requires compareTo')
    if 'schemaFixture' in document and type(document['schemaFixture']) is not dict:
        raise ValueError('schemaFixture must be an object')
    if 'schemaVectors' in document:
        if type(document['schemaVectors']) is not list or len(document['schemaVectors']) > 1000:
            raise ValueError('invalid schema vector list')
        seen = set()
        for vector in document['schemaVectors']:
            fields(vector, {'id', 'expect', 'mutation', 'note'}, ('id', 'expect'))
            identifier = vector['id']
            if type(identifier) is not str or not identifier.strip() or identifier in seen:
                raise ValueError('invalid schema vector ID')
            seen.add(identifier)
            fields(vector['expect'], {'schemaValid'}, ('schemaValid',))
            if type(vector['expect']['schemaValid']) is not bool:
                raise ValueError('schemaValid must be boolean')
            if 'mutation' in vector:
                mutation = vector['mutation']
                fields(mutation, {'path', 'operation', 'value'}, ('path', 'operation', 'value'))
                enum(mutation['operation'], ('set', 'remove'))
                if (type(mutation['path']) is not list or not mutation['path'] or
                        any(type(p) not in (str, int) for p in mutation['path'])):
                    raise ValueError('invalid schema mutation path')


def validate_response(response):
    validate_json(response)
    fields(response, {'actual', 'unsupported', 'observations'}, ('actual', 'unsupported', 'observations'))
    if type(response['actual']) is not dict or type(response['observations']) is not dict:
        raise ValueError('actual and observations must be objects')
    unsupported = response['unsupported']
    if type(unsupported) is not list or any(type(s) is not str or not s.strip() for s in unsupported):
        raise ValueError('unsupported must be a list of nonblank strings')
    actual = response['actual']
    fields(actual, ACTUAL_FIELDS)
    for key in ('undefinedRecorded', 'ordinaryAuthorization', 'decisionProjectionComplete'):
        if key in actual and type(actual[key]) is not bool:
            raise ValueError(f'{key} must be a boolean')
    for key in ('componentDecision', 'authorizationBaseline'):
        if key in actual and type(actual[key]) is not dict:
            raise ValueError(f'{key} must be an object')
    for key, choices in (('decision', DECISIONS), ('supervision', SUPERVISION)):
        if key in actual:
            enum(actual[key], choices)
    if 'tightenedAtMost' in actual:
        ceilings(actual['tightenedAtMost'])
    for key in ('autonomyDemand', 'environmentalCapacity'):
        if key in actual and (type(actual[key]) not in (int, float) or actual[key] < 0):
            raise ValueError('invalid actual envelope value')


def run_suite(document, adapter, metadata):
    """Evaluate independent requests, then compare actual results in a second pass."""
    validate_document(document)
    validate_json(metadata)
    if type(metadata) is not dict or type(metadata.get('sourceDirty')) is not bool:
        raise ValueError('metadata requires explicit boolean sourceDirty')
    if ('profileSourceDirty' not in metadata or
            (metadata['profileSourceDirty'] is not None and type(metadata['profileSourceDirty']) is not bool)):
        raise ValueError('metadata requires explicit profileSourceDirty status')
    pins = metadata.get('pins')
    fields(pins, {'fixture', 'spec', 'schema', 'source'}, ('fixture', 'spec', 'schema', 'source'))
    for name, pin in pins.items():
        if type(pin) is not dict or type(pin.get('verified')) is not bool:
            raise ValueError('each pin requires explicit verification status')
        if name != 'source' and (type(pin.get('sha256')) is not str or
                                not re.fullmatch('[0-9a-f]{64}', pin['sha256'])):
            raise ValueError('pin requires SHA-256')
        if pin['verified'] and (type(pin.get('head')) is not str or
                               not re.fullmatch('[0-9a-f]{40}', pin['head'])):
            raise ValueError('verified pin requires exact HEAD')
    if not callable(adapter):
        raise ValueError('adapter must be callable')
    document, metadata = deepcopy(document), deepcopy(metadata)
    pins = metadata['pins']
    cases = []
    supplied_requests = []
    for vector in document['vectors']:
        case = {'id': vector['id'], 'expected': deepcopy(vector['expect']), 'actual': {},
                'status': 'pass', 'rationale': [], 'observations': {}, 'unsupported': [],
                'mismatches': [], 'repetitions': []}
        cases.append(case)
        first = None
        default_repeats = 2 if vector['expect'].get('identicalResultRequired') else 1
        for _ in range(vector['expect'].get('repeatCount', default_repeats)):
            request = deepcopy(vector['request'])
            supplied_requests.append((request, vector['request'], case))
            try:
                result = adapter(request)
                if not typed_equal(request, vector['request']):
                    raise ValueError('adapter mutated request')
                validate_response(result)
                result = deepcopy(result)  # Protect earlier results from shared adapter buffers.
                case['repetitions'].append(result)
                if first is None:
                    first = result
                    case.update(actual=deepcopy(result['actual']), unsupported=deepcopy(result['unsupported']),
                                observations=deepcopy(result['observations']))
                elif not typed_equal(first, result):
                    case['status'] = 'fail'
                    case['mismatches'].append('nondeterministic response')
            except Exception as exc:
                case['status'] = 'error'
                # Do not publish arbitrary exception text (may contain sensitive data).
                case['rationale'].append(f'adapter error: {type(exc).__name__}')
                break
    for request, original, case in supplied_requests:
        if not typed_equal(request, original):
            case['status'] = 'error'
            case['rationale'].append('adapter mutated a retained request')
    by_id = {case['id']: case for case in cases}
    for case in cases:
        if case['status'] == 'error':
            continue
        actual, expected = case['actual'], case['expected']
        unsupported = case['unsupported']
        mismatches = case['mismatches']
        incomplete_projection = actual.get('decisionProjectionComplete') is False
        if incomplete_projection:
            unsupported.append('decisionProjectionComplete: false; incomplete projection')

        def check(key, predicate, description):
            if key not in actual:
                unsupported.append(f'missing output: {key}')
            elif not predicate(actual[key]):
                mismatches.append(description)

        for key in ('decision', 'supervision', 'undefinedRecorded'):
            if key in expected:
                check(key, lambda value, k=key: typed_equal(value, expected[k]), f'{key} mismatch')
        for key, output, order in (('decisionNotLooserThan', 'decision', DECISIONS),
                                    ('supervisionAtLeast', 'supervision', SUPERVISION)):
            if key in expected:
                check(output, lambda value, k=key, o=order: o.index(value) >= o.index(expected[k]),
                      f'{key} bound violated')
                if 'compareTo' in expected:
                    baseline = by_id[expected['compareTo']]
                    if baseline['status'] == 'error' or output not in baseline['actual']:
                        unsupported.append(f'missing independent comparison output: {output}')
                    elif output in actual and order.index(actual[output]) < order.index(baseline['actual'][output]):
                        mismatches.append(f'{key} actual baseline violated')
        if 'tightenedAtMost' in expected:
            if 'tightenedAtMost' not in actual:
                unsupported.append('missing output: tightenedAtMost')
            else:
                for name, maximum in expected['tightenedAtMost'].items():
                    if name not in actual['tightenedAtMost']:
                        unsupported.append(f'missing ceiling: {name}')
                    elif actual['tightenedAtMost'][name] > maximum:
                        mismatches.append(f'ceiling exceeded: {name}')
        for key, output, demand in (
                ('autonomyDemandNotLessThanCompared', 'autonomyDemand', True),
                ('environmentalCapacityNotGreaterThanCompared', 'environmentalCapacity', False)):
            if expected.get(key):
                baseline = by_id[expected['compareTo']]
                if baseline['status'] == 'error' or output not in baseline['actual'] or output not in actual:
                    unsupported.append(f'missing independent comparison output: {output}')
                elif (actual[output] < baseline['actual'][output] if demand else
                      actual[output] > baseline['actual'][output]):
                    mismatches.append(f'{key} violated')
        if incomplete_projection:
            case['status'] = 'unsupported'
        elif case['status'] != 'fail':
            case['status'] = 'unsupported' if unsupported else 'fail' if mismatches else 'pass'
        case['rationale'].extend(unsupported + mismatches or ['all requested comparisons satisfied'])
    totals = {status: sum(c['status'] == status for c in cases)
              for status in ('pass', 'fail', 'unsupported', 'error')}
    qualified = (totals['pass'] == len(cases) and not metadata['sourceDirty']
                 and all(pin['verified'] for pin in pins.values())
                 and metadata['profileSourceDirty'] is False)
    try:
        cryptography_version = version('cryptography')
    except PackageNotFoundError:
        cryptography_version = 'unavailable'
    return {'reportVersion': REPORT_VERSION, 'profile': document['profile'],
            'evidenceLane': 'modeled-component-evaluation',
            'limits': ['Draft runtime vectors only; no runtime certification or target effects.',
                       'Schema vectors are metadata only and are not executed by this harness.',
                       'Qualification is limited to this supplied suite and adapter.'],
            'pins': deepcopy(metadata.get('pins', {})),
            'toolchain': {'python': sys.version, 'implementation': platform.python_implementation(),
                          'cryptography': cryptography_version, 'platform': platform.platform()},
            'metadata': deepcopy(metadata), 'sourceDirty': metadata['sourceDirty'],
            'qualification': qualified, 'aggregatePass': qualified, 'totals': totals, 'cases': cases}
