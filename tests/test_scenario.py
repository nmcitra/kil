import copy
import json
from pathlib import Path
import unittest

from kil.evidence import EvidenceClass
from kil.scenario import load_scenario


FIXTURE = Path(__file__).parent / "fixtures/scenario-minimal-v1.json"


def fixture_data():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class ScenarioTest(unittest.TestCase):
    def test_loads_source_cited_observed_event_and_modeled_context(self):
        scenario = load_scenario(FIXTURE)
        event = scenario.events[0]
        self.assertEqual(scenario.schema_version, "kil.scenario.v1")
        self.assertEqual(event.observed_summary.evidence_class, EvidenceClass.OBSERVED)
        self.assertEqual(event.control_assumption.evidence_class, EvidenceClass.MODELED)
        self.assertEqual(event.state_assumption.evidence_class, EvidenceClass.MODELED)
        self.assertEqual(
            event.local_evidence_assumption.evidence_class, EvidenceClass.MODELED
        )

    def test_rejects_observed_event_without_source(self):
        raw = fixture_data()
        del raw["events"][0]["source_ref"]
        with self.assertRaisesRegex(ValueError, "source_ref"):
            load_scenario(raw)

    def test_rejects_modeled_context_without_rationale(self):
        raw = fixture_data()
        del raw["events"][0]["modeled_context"]["rationale"]
        with self.assertRaisesRegex(ValueError, "rationale"):
            load_scenario(raw)

    def test_rejects_control_assumption_without_rationale(self):
        raw = fixture_data()
        del raw["events"][0]["control_rationale"]
        with self.assertRaisesRegex(ValueError, "control_rationale"):
            load_scenario(raw)

    def test_rejects_composite_state_without_modeled_rationale(self):
        raw = fixture_data()
        del raw["events"][0]["state_rationale"]
        with self.assertRaisesRegex(ValueError, "state_rationale"):
            load_scenario(raw)

    def test_rejects_unknown_fields_at_every_schema_level(self):
        cases = []
        root = fixture_data()
        root["silent_override"] = True
        cases.append(root)
        event = fixture_data()
        event["events"][0]["silent_override"] = True
        cases.append(event)
        state = fixture_data()
        state["events"][0]["state"]["silent_override"] = True
        cases.append(state)
        local = fixture_data()
        local["events"][0]["modeled_context"]["silent_override"] = True
        cases.append(local)
        for raw in cases:
            with self.subTest(keys=sorted(raw)):
                with self.assertRaisesRegex(ValueError, "unknown fields"):
                    load_scenario(raw)

    def test_rejects_json_type_coercion(self):
        mutations = (
            (("events", 0, "phase"), True, "phase"),
            (("events", 0, "timestamp_s"), "10", "timestamp_s"),
            (("events", 0, "credential_valid"), "false", "credential_valid"),
            (("events", 0, "policy_allows_action"), 1, "policy_allows_action"),
            (("events", 0, "state", "charge"), 5, "charge"),
            (("events", 0, "state", "authentic"), 1, "authentic"),
            (("events", 0, "modeled_context", "fresh"), 1, "fresh"),
        )
        for path, replacement, expected in mutations:
            raw = fixture_data()
            target = raw
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = replacement
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, expected):
                    load_scenario(raw)

    def test_rejects_duplicate_or_forward_dependencies(self):
        raw = fixture_data()
        first = raw["events"][0]
        duplicate = copy.deepcopy(first)
        duplicate["timestamp_s"] = 20
        raw["events"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "duplicate event_id"):
            load_scenario(raw)

        raw = fixture_data()
        raw["events"][0]["depends_on"] = ["future-event"]
        with self.assertRaisesRegex(ValueError, "earlier events"):
            load_scenario(raw)

    def test_rejects_empty_or_malformed_scenario_collections(self):
        cases = (
            ({**fixture_data(), "events": []}, "events"),
            ({**fixture_data(), "events": {}}, "events"),
            ({**fixture_data(), "primary_source": "not-a-uri"}, "primary_source"),
        )
        for raw, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(ValueError, expected):
                    load_scenario(raw)

    def test_rejects_text_that_cannot_enter_canonical_utf8(self):
        raw = fixture_data()
        raw["events"][0]["summary"] = "invalid surrogate: \ud800"
        with self.assertRaisesRegex(ValueError, "summary.*UTF-8"):
            load_scenario(raw)


if __name__ == "__main__":
    unittest.main()
