"""Honest, synthetic component exercise; no new authority/profile interface."""
from decimal import Decimal

from kil.domain import ActionRequest, CompositeState, EnforcementMode
from kil.engine import decide
from kil.live_authz import AuthorizationAdapter, LiveFixture, LiveTrack
from tools.conformance_runner import CEILINGS, SUPERVISION, enum, fields, validate_json

REQUEST_FIELDS = frozenset({'resource', 'action', 'softwareContext'})
CONTEXT_FIELDS = frozenset({'magnitudes', 'conditions', 'nowMs', 'observedAtMs',
    'maxAgeMs', 'proofIssuedAtMs', 'proofExpiresAtMs', 'decisionExpiresAtMs',
    'candidateEnvelope', 'existingSupervision', 'existingCeilings', 'trustedFixtures'})
CONDITION_FIELDS = frozenset({'resourcePressure', 'controlLatencyMs', 'irreversibility',
    'novelty', 'repairPathVerified', 'supervisionAvailable'})
TRUSTED_FIELDS = frozenset({'ordinaryAuthorization', 'repairPathVerified',
    'supervisionAvailable', 'signatureVerified', 'requestMatches', 'destinationMatches',
    'authorityClassMatches', 'proofMatches', 'profileMatches', 'policyMatches',
    'evidenceMatches', 'prerequisitesCurrent', 'epochCurrent', 'sourceAuthenticated',
    'sourceHealthy', 'sequenceCurrent', 'trustedTime', 'restrictionContinuity',
    'unresolvedRestriction', 'revoked', 'scaleMatches'})
ENVELOPE_FIELDS = frozenset({'autonomyDemand', 'environmentalCapacity', 'capacityKnown',
    'supervision', 'ceilings'})
UNSUPPORTED = (
    'decision: incomplete component projection, not a profile consumption decision',
    'supervision: ordered composition and signed silent veto',
    'tightenedAtMost: request-bound ceilings and no-loosen composition',
    'autonomyDemand: independent envelope evaluation (charge is not A)',
    'environmentalCapacity: independent envelope evaluation (charge is not E)',
    'undefinedRecorded: profile undefined-observation recording',
    'bindings: actual request, destination, proof, profile, policy and evidence',
    'signatureVerified: no profile JWS verification; modeled authenticity only',
    'current authority: prerequisites, epoch, revocation, sequence and source health',
    'time: trusted millisecond freshness, proof lifetime and decision deadlines',
    'restriction continuity: refresh, unresolved restrictions and restart',
    'capacity: conditions, scale, unknown capacity, repair path and supervision availability',
    'ordinaryAuthorization: synthetic credential/policy baseline only, no real acquisition',
)


def validate_request(request):
    validate_json(request)
    fields(request, REQUEST_FIELDS, REQUEST_FIELDS)
    if request['resource'] != 'software:///test-object' or request['action'] not in ('replace', 'repair'):
        raise ValueError('unsupported request resource/action')
    context = request['softwareContext']
    fields(context, CONTEXT_FIELDS, CONTEXT_FIELDS)
    for name, allowed in (('magnitudes', CEILINGS), ('existingCeilings', CEILINGS),
                          ('conditions', CONDITION_FIELDS), ('trustedFixtures', TRUSTED_FIELDS),
                          ('candidateEnvelope', ENVELOPE_FIELDS)):
        fields(context[name], allowed, allowed)
    envelope = context['candidateEnvelope']
    fields(envelope['ceilings'], CEILINGS, CEILINGS)
    enum(envelope['supervision'], SUPERVISION)
    enum(context['existingSupervision'], SUPERVISION)
    booleans = list(context['trustedFixtures'].values()) + [envelope['capacityKnown']]
    booleans += [context['conditions'][k] for k in ('repairPathVerified', 'supervisionAvailable')]
    if any(type(v) is not bool for v in booleans):
        raise ValueError('modeled control flags must be booleans')
    for name in CONTEXT_FIELDS:
        if name.endswith('Ms') and type(context[name]) is not int:
            raise ValueError('modeled times must be integer milliseconds')
    for name in ('autonomyDemand', 'environmentalCapacity'):
        if type(envelope[name]) not in (int, float) or envelope[name] < 0:
            raise ValueError('invalid candidate envelope number')
    for name in ('resourcePressure', 'irreversibility', 'novelty'):
        if type(context['conditions'][name]) not in (int, float) or not 0 <= context['conditions'][name] <= 1:
            raise ValueError('invalid modeled capacity condition')
    latency = context['conditions']['controlLatencyMs']
    if type(latency) is not int or latency < 0:
        raise ValueError('invalid modeled latency')
    # Null, negative and boolean magnitudes are intentional negative vectors;
    # accepting their JSON representation does not mean evaluating their semantics.
    for value in context['magnitudes'].values():
        if value is not None and type(value) not in (int, bool):
            raise ValueError('unknown magnitude representation')
    for values in (context['existingCeilings'], envelope['ceilings']):
        if any(type(v) is not int or v < 0 for v in values.values()):
            raise ValueError('invalid modeled ceiling')
    return context


def evaluate(request):
    """Exercise real imports on fixed state, with only three disclosed projections."""
    context = validate_request(request)
    flags = context['trustedFixtures']
    action = ActionRequest('synthetic-component-request', 'synthetic-actor', 'replace', 100)
    state = CompositeState(
        state_id='synthetic-component-state', identity='synthetic-actor',
        authority_class='replace' if flags['authorityClassMatches'] else 'other',
        issued_at_s=99, not_before_s=99, expires_at_s=109,
        charge=Decimal('1'), threshold=Decimal('0.5'), history_count=1, minimum_history=1,
        authentic=flags['signatureVerified'], veto_clear=context['existingSupervision'] != 'silent_veto',
        envelope_allows=True, decay_rate=Decimal('0'), maximum_charge=Decimal('1'))
    record = decide(action, state, EnforcementMode.SIGNED_STATE_ONLY)
    baseline = AuthorizationAdapter(LiveTrack.CREDENTIAL_POLICY_BASELINE).evaluate(
        LiveFixture(action, 'replace', flags['ordinaryAuthorization'], True, None, None, None))
    component = {'requestId': record.request_id, 'stateId': record.state_id,
                 'mode': record.mode.value, 'outcome': record.outcome.value,
                 'reasons': [reason.value for reason in record.reasons],
                 'signedCharge': str(record.signed_charge), 'decayedCharge': str(record.decayed_charge),
                 'effectiveCharge': str(record.effective_charge)}
    actual = {'componentDecision': component,
              'ordinaryAuthorization': baseline.outcome.value == 'permit',
              'authorizationBaseline': {'track': baseline.track.value, 'outcome': baseline.outcome.value,
                  'reasons': list(baseline.adapter_reasons), 'decisionDigest': baseline.decision_digest}}
    if record.outcome.value in ('permit', 'deny'):
        actual['decision'] = {'permit': 'allow', 'deny': 'deny'}[record.outcome.value]
    return {'actual': actual, 'unsupported': list(UNSUPPORTED), 'observations': {
        'decisionProjectionComplete': False,
        'inputAction': request['action'],
        'evidenceLane': 'fixed-synthetic-component-state',
        'syntheticState': {'timestampS': 100, 'issuedAtS': 99, 'expiresAtS': 109,
                           'charge': '1', 'threshold': '0.5', 'decayRate': '0',
                           'historyCount': 1, 'minimumHistory': 1, 'envelopeAllows': True},
        'syntheticRequest': {'identity': 'synthetic-actor', 'authorityClass': 'replace', 'timestampS': 100},
        'projections': ['existing silent_veto -> modeled veto_clear',
                       'authorityClassMatches -> synthetic class equality',
                       'signatureVerified -> modeled authentic boolean, no signature verification'],
        'limits': ['No input milliseconds are rounded into engine seconds.',
                   'Q-state is not a signed profile; engine deny is not a signed veto.',
                   'constrain is not projected as escalate; candidateEnvelope is never returned as actual.',
                   'Baseline credential flag is synthetic; policy_allows_action is fixed true.']}}
