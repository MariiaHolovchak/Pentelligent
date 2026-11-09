"""Unit and protocol tests for the Pentelligent synthetic-lab engine.

The fake Ollama endpoint validates the real HTTP/JSON protocol without requiring
an Ollama installation. It does not claim to validate any particular real model.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import socket
import sys
import threading
import tempfile
from pathlib import Path
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from typing import Any

from fastapi import HTTPException

import pentelligent as pf
import run_experiment as runner
from pentelligent import (
    ACTION_CATALOG,
    FIXED_SEQUENCE,
    ActionValidationError,
    ActionValidator,
    ActionSelector,
    ContextManager,
    HTTPExecutor,
    VulnerabilityDetector,
    calculate_cvss_v31_base,
    build_cvss_profile,
    load_cvss_profile,
)


class FakeOllamaServer:
    """Tiny local /api/tags + /api/generate test double using Ollama's JSON shape."""

    def __init__(
        self,
        response_key: str = "action_id",
        preferred_action: str | None = None,
        assessment_limit: int | None = None,
        truncate_response: bool = False,
        truncated_action_id: str | None = None,
        truncate_risk_batch_multi_only: bool = False,
        invalid_global_ranking: bool = False,
        generation_error: bool = False,
        forced_plan: list[str] | None = None,
    ) -> None:
        self.requests: list[dict[str, Any]] = []
        self.response_key = response_key
        self.preferred_action = preferred_action
        self.assessment_limit = assessment_limit
        self.truncate_response = truncate_response
        self.truncated_action_id = truncated_action_id
        self.truncate_risk_batch_multi_only = truncate_risk_batch_multi_only
        self.invalid_global_ranking = invalid_global_ranking
        self.generation_error = generation_error
        self.forced_plan = list(forced_plan or [])

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:
                return

            def _send(self, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/api/tags":
                    self._send({"models": [{"name": "test-model:latest"}]})
                else:
                    self.send_error(404)

            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/api/generate":
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                request = json.loads(self.rfile.read(length).decode("utf-8"))
                outer.requests.append(request)
                if outer.generation_error:
                    self._send({"error": "synthetic Ollama model-generation failure"})
                    return
                prompt = request.get("prompt", "")
                context_text = prompt.split("\n\n", 1)[-1]
                try:
                    context = json.loads(context_text)
                except (json.JSONDecodeError, TypeError):
                    context = {}
                catalog = context.get("action_catalog", {})
                candidate_actions = context.get("candidate_actions", [])
                candidate_ids = context.get("candidate_action_ids", []) or [
                    item.get("id") for item in candidate_actions if isinstance(item, dict) and item.get("id")
                ]
                remaining = set(context.get("remaining_findings", context.get("remaining", [])))
                chosen = outer.preferred_action if outer.preferred_action in candidate_ids else None
                if chosen is None and outer.forced_plan and outer.forced_plan[0] in candidate_ids:
                    chosen = outer.forced_plan[0]
                for action_id in ([] if chosen else candidate_ids):
                    action = catalog.get(action_id, "")
                    finding = None
                    if isinstance(action, str):
                        for part in action.split("; "):
                            if part.startswith("finding="):
                                finding = part.split("=", 1)[1]
                                break
                    elif isinstance(action, dict):
                        finding = action.get("finding")
                    if not finding:
                        finding = next((item.get("finding") for item in candidate_actions if item.get("id") == action_id), None)
                    if finding in remaining:
                        chosen = action_id
                        break
                if chosen is None and context.get("cvss_scoring_required"):
                    for target in context.get("cvss_targets", []):
                        if target.get("finding") in remaining and target.get("action_id") in candidate_ids:
                            chosen = target["action_id"]
                            break
                if chosen is None:
                    for prerequisite in context.get("unresolved_finding_prerequisites", []):
                        if prerequisite in candidate_ids:
                            chosen = prerequisite
                            break
                if chosen is None and candidate_ids:
                    chosen = candidate_ids[0]
                if not context:
                    # Compatibility for any unrelated tiny readiness checks.
                    response_text = json.dumps({"ready": True})
                elif context.get("task") == "independent_qualitative_severity_assessment_batch":
                    severity_by_action = {
                        "injection_probe": "high", "ssrf_probe": "high", "jwt_config_probe": "high",
                        "mass_assignment_probe": "high", "bola_probe": "medium", "admin_access_probe": "medium",
                        "weak_password_policy_probe": "medium", "redirect_probe": "medium",
                        "security_headers_probe": "low", "error_disclosure_probe": "low",
                        "internal_docs_probe": "low",
                    }
                    response_text = json.dumps({"assessments": [
                        {
                            "action_id": item["action_id"],
                            "severity_estimate": severity_by_action.get(item["action_id"], "medium"),
                            "confidence": "medium",
                            "rationale": "Protocol test assessment for the synthetic finding class.",
                        }
                        for item in context.get("targets", [])
                    ]})
                elif context.get("task") == "adaptive_short_horizon_plan":
                    if outer.response_key == "unexpected_key":
                        response_text = json.dumps({"unexpected_key": chosen, "reason": "invalid protocol response"})
                    elif outer.response_key == "selected_action":
                        response_text = json.dumps({"selected_action": chosen, "reason": "Legacy test response."})
                    else:
                        horizon = int(context.get("planning_horizon", 3))
                        if outer.forced_plan:
                            chosen_ids = [action_id for action_id in outer.forced_plan if action_id in candidate_ids]
                        else:
                            chosen_ids = [chosen] if chosen else []
                            chosen_ids.extend(
                                action_id for action_id in candidate_ids
                                if action_id not in chosen_ids
                                and next((item.get("finding") for item in candidate_actions if item.get("id") == action_id), None) is not None
                            )
                            chosen_ids.extend(action_id for action_id in candidate_ids if action_id not in chosen_ids)
                        response_text = json.dumps({"plan": [
                            {
                                "action_id": action_id,
                                "reason": "Select this feasible intent to improve coverage with bounded cost.",
                            }
                            for action_id in chosen_ids[:horizon]
                        ]})
                else:
                    result = {
                        outer.response_key: chosen,
                        "reason": "Test double: select the next unresolved finding intent.",
                    }
                    if context.get("cvss_scoring_required"):
                        cvss_targets = context.get("cvss_targets", [])
                        result["cvss_assessments"] = [
                            {
                                "action_id": item["action_id"],
                                "vector": (
                                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                                    if item["action_id"] == "bola_probe"
                                    else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
                                ),
                            }
                            for item in cvss_targets
                        ]
                        if outer.assessment_limit is not None:
                            result["cvss_assessments"] = result["cvss_assessments"][:outer.assessment_limit]
                    response_text = json.dumps(result)
                force_length_stop = False
                if outer.truncate_response and ("candidate_action_ids" in context or "candidate_actions" in context):
                    # Reproduce the observed action-selection failure only: the
                    # candidate ID is complete but rationale JSON is truncated.
                    truncated_id = outer.truncated_action_id or chosen
                    response_text = (
                        '{"action_id":' + json.dumps(truncated_id)
                        + ',"reason":"This deliberately verbose explanation is truncated before JSON closes'
                    )
                    force_length_stop = True
                if (outer.truncate_risk_batch_multi_only
                        and context.get("task") == "independent_qualitative_severity_assessment_batch"
                        and len(context.get("targets", [])) > 1):
                    first_id = context["targets"][0]["action_id"]
                    response_text = (
                        '{"assessments":[{"action_id":' + json.dumps(first_id)
                        + ',"severity_estimate":"high","confidence":"medium","rationale":"truncated before close'
                    )
                    force_length_stop = True
                metrics = {
                    "model": request.get("model", "test-model:latest"),
                    "total_duration": 1_000_000,
                    "load_duration": 100_000,
                    "prompt_eval_count": 25,
                    "eval_count": 10,
                    "done_reason": "length" if force_length_stop else "stop",
                }
                if request.get("stream") is True:
                    # Simulate Ollama NDJSON streaming in two response fragments.
                    midpoint = max(1, len(response_text) // 2)
                    records = [
                        {"response": response_text[:midpoint], "done": False},
                        {"response": response_text[midpoint:], "done": False},
                        {"response": "", "done": True, **metrics},
                    ]
                    body = b"".join((json.dumps(record) + "\n").encode("utf-8") for record in records)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-ndjson")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    # Writes are deliberately separated to exercise line-based consumption.
                    split = max(1, len(body) // 2)
                    self.wfile.write(body[:split])
                    self.wfile.flush()
                    self.wfile.write(body[split:])
                    self.wfile.flush()
                else:
                    self._send({"response": response_text, "done": True, **metrics})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class PentelligentSafetyAndContextTests(unittest.TestCase):
    _profile_environment_names = (
        "PENTELLIGENT_CVSS_PROFILE_FILE",
        "PENTELLIGENT_LLM_RISK_PROFILE_FILE",
        "PENTELLIGENT_CVSS_PROFILE_GENERATION_THIS_RUN_SECONDS",
        "PENTELLIGENT_CVSS_PROFILE_REUSED",
        "PENTELLIGENT_LLM_RISK_PROFILE_GENERATION_SECONDS",
        "PENTELLIGENT_LLM_RISK_PROFILE_REUSED",
        "PENTELLIGENT_ACTION_SELECTION_PREFLIGHT_SECONDS",
    )

    def setUp(self):
        import os
        self._saved_profile_environment = {
            key: os.environ[key] for key in self._profile_environment_names if key in os.environ
        }
        for key in self._profile_environment_names:
            os.environ.pop(key, None)
        self.addCleanup(self._restore_profile_environment)

    def _restore_profile_environment(self):
        import os
        for key in self._profile_environment_names:
            os.environ.pop(key, None)
        os.environ.update(self._saved_profile_environment)

    def test_remote_target_is_blocked_by_default(self):
        with self.assertRaises(ValueError):
            HTTPExecutor("http://example.com")

    def test_embedded_target_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            HTTPExecutor("http://user:password@127.0.0.1:8000")

    def test_target_url_must_be_origin_without_path_query_or_fragment(self):
        for url in (
            "http://127.0.0.1:8000/api",
            "http://127.0.0.1:8000/?debug=1",
            "http://127.0.0.1:8000/#fragment",
            "https://127.0.0.1:8000",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                HTTPExecutor(url)

    def test_resource_id_is_discovered_from_user_control(self):
        context = ContextManager()
        context.update(
            "user_control",
            {"method": "GET", "url": "http://localhost/lab/users/1", "request_params": {},
             "request_json": None, "status_code": 200, "body": {"id": 1, "username": "alice"}},
            [],
        )
        self.assertEqual(context.observations["known_user_ids"], [1])
        self.assertEqual(context.observations["primary_user_id"], 1)
        self.assertIn("user_control", context.observations["successful_actions"])

    def test_boolean_resource_id_is_not_accepted_as_integer_id(self):
        context = ContextManager()
        context.update("health_check", {"status_code": 200, "body": {"status": "ok"}}, [])
        context.update("user_control", {"status_code": 200, "body": {"id": True}}, [])
        self.assertNotIn("user_control", context.observations["successful_actions"])
        self.assertIn("user_control", context.observations["failed_actions"])
        self.assertEqual(context.observations["known_user_ids"], [])
        with self.assertRaises(ActionValidationError):
            ActionValidator().validate("mass_assignment_probe", [], context.observations)

    def test_user_control_200_without_id_does_not_unlock_dependency(self):
        context = ContextManager()
        context.update("health_check", {"status_code": 200, "body": {"status": "ok"}}, [])
        context.update("user_control", {"status_code": 200, "body": {"username": "alice"}}, [])
        self.assertNotIn("user_control", context.observations["successful_actions"])
        self.assertIn("user_control", context.observations["failed_actions"])
        self.assertEqual(context.observations["known_user_ids"], [])
        with self.assertRaises(ActionValidationError):
            ActionValidator().validate("mass_assignment_probe", [], context.observations)

    def test_health_check_requires_semantically_valid_response(self):
        context = ContextManager()
        context.update("health_check", {"status_code": 200, "body": {"unexpected": True}}, [])
        self.assertNotIn("health_check", context.observations["successful_actions"])
        self.assertIn("health_check", context.observations["failed_actions"])

    def test_expected_synthetic_500_counts_as_successful_probe_not_global_failure(self):
        context = ContextManager()
        response = {
            "status_code": 500,
            "headers": {"content-type": "application/json"},
            "body": {
                "lab_marker": "VERBOSE_SYNTHETIC_ERROR_DISCLOSURE",
                "stack_trace": "synthetic-only stack trace",
            },
        }
        finding = VulnerabilityDetector().detect("error_disclosure_probe", response)
        self.assertEqual([item["category"] for item in finding], ["VERBOSE_ERROR_DISCLOSURE"])
        context.update("error_disclosure_probe", response, finding)
        self.assertIn("error_disclosure_probe", context.observations["successful_actions"])
        self.assertNotIn("error_disclosure_probe", context.observations["failed_actions"])
        # Expected HTTP 500 for a probe must not satisfy any ordinary prerequisite.
        self.assertFalse(ContextManager._response_means_action_successful("health_check", response))
        self.assertFalse(ContextManager._response_means_action_successful("user_control", response))

    def test_dependent_action_is_blocked_until_prerequisites_and_id_exist(self):
        validator = ActionValidator()
        with self.assertRaises(ActionValidationError):
            validator.validate("mass_assignment_probe", [], {})
        with self.assertRaises(ActionValidationError):
            validator.validate("mass_assignment_probe", ["health_check"], {})
        with self.assertRaises(ActionValidationError):
            validator.validate(
                "mass_assignment_probe",
                ["health_check", "user_control"],
                {"known_user_ids": [1], "primary_user_id": 1, "successful_actions": ["user_control"]},
            )
        validator.validate(
            "mass_assignment_probe",
            ["health_check", "user_control"],
            {"known_user_ids": [1], "primary_user_id": 1, "successful_actions": ["health_check", "user_control"]},
        )

    def test_unrelated_known_id_cannot_replace_primary_user_control_id(self):
        validator = ActionValidator()
        context = {
            "successful_actions": ["health_check", "user_control"],
            "known_user_ids": [2],
            "primary_user_id": None,
        }
        with self.assertRaises(ActionValidationError):
            validator.validate("mass_assignment_probe", ["health_check", "user_control"], context)

    def test_transfer_requires_discovered_resource_too(self):
        validator = ActionValidator()
        context = {"successful_actions": ["health_check", "user_control"], "known_user_ids": []}
        with self.assertRaises(ActionValidationError):
            validator.validate("transfer_control", [], context)
        self.assertEqual(ACTION_CATALOG["transfer_control"]["resource_id_key"], "user_id")

    def test_fallback_prefers_prerequisite_that_unlocks_finding(self):
        selector = ActionSelector()
        selected = selector._fallback(
            {"MASS_ASSIGNMENT"},
            ["health_check", "user_control"],
            [],
        )
        self.assertEqual(selected, "health_check")

    def test_fallback_does_not_run_unrelated_controls_after_all_progress_options_are_gone(self):
        selector = ActionSelector()
        selected = selector._fallback(
            {"MASS_ASSIGNMENT"},
            ["search_control"],
            ["health_check", "user_control", "mass_assignment_probe"],
        )
        self.assertEqual(selected, "")

    def test_catalogue_has_unique_allowlisted_paths_and_methods(self):
        self.assertEqual(len(ACTION_CATALOG), len(set(ACTION_CATALOG)))
        for action_id, action in ACTION_CATALOG.items():
            with self.subTest(action=action_id):
                self.assertIn(action["method"], {"GET", "POST"})
                self.assertTrue(action["path"] == "/" or action["path"].startswith(("/lab/", "/health")))
                self.assertNotIn(action_id, action["requires"])
                for dependency in action["requires"]:
                    self.assertIn(dependency, ACTION_CATALOG)

    def test_transfer_uses_discovered_user_id_template(self):
        action = ACTION_CATALOG["transfer_control"]
        self.assertIn("user_control", action["requires"])
        self.assertEqual(action["body"]["from_user"], "{user_id}")

    def test_primary_resource_id_from_user_control_takes_precedence(self):
        context = ContextManager()
        context.update("bola_probe", {"status_code": 200, "body": {"user_id": 2}}, [])
        context.update("user_control", {"status_code": 200, "body": {"id": 1}}, [])
        self.assertEqual(context.observations["known_user_ids"], [1, 2])

    def test_failed_prerequisite_is_not_marked_successful(self):
        context = ContextManager()
        context.update("health_check", {"status_code": 503, "body": {}}, [])
        self.assertNotIn("health_check", context.observations["successful_actions"])
        self.assertIn("health_check", context.observations["failed_actions"])

    def test_skipped_action_is_recorded_without_being_marked_executed_successfully(self):
        context = ContextManager()
        context.record_skipped(
            "mass_assignment_probe",
            "Missing successful prerequisite action: user_control",
            {"method": "POST", "path_template": "/lab/users/{user_id}/profile"},
        )
        self.assertIn("mass_assignment_probe", context.observations["skipped_actions"])
        self.assertNotIn("mass_assignment_probe", context.observations["successful_actions"])
        self.assertNotIn("mass_assignment_probe", context.observations["tested_actions"])
        self.assertTrue(context.history[-1]["skipped"])
        self.assertIn("Missing successful prerequisite", context.history[-1]["error"])

    def test_selector_does_not_offer_resource_action_when_successful_source_has_no_primary_id(self):
        context = ContextManager()
        context.observations["remaining_findings"] = ["MASS_ASSIGNMENT"]
        context.observations["successful_actions"] = ["health_check", "user_control"]
        context.observations["known_user_ids"] = [2]
        context.observations["primary_user_id"] = None
        executed = [action_id for action_id in ACTION_CATALOG if action_id != "mass_assignment_probe"]
        selector = ActionSelector()
        action_id, trace = asyncio.run(selector.select(context, executed))
        self.assertIsNone(action_id)
        self.assertEqual(selector.calls, 0)
        self.assertFalse(trace["llm_request_made"])

    def test_synthetic_transfer_endpoint_rejects_boolean_amount(self):
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(pf.transfer({"amount": True}))
        self.assertEqual(caught.exception.status_code, 400)

    def test_selector_stops_without_llm_request_when_no_findings_remain(self):
        context = ContextManager()
        context.observations["remaining_findings"] = []
        selector = ActionSelector()
        action_id, trace = asyncio.run(selector.select(context, []))
        self.assertIsNone(action_id)
        self.assertEqual(selector.calls, 0)
        self.assertEqual(trace["selection_source"], "none")
        self.assertFalse(trace["llm_request_made"])
        self.assertIsNone(trace["prompt_text_sent"])
        self.assertIsNone(trace["raw_model_response"])

    def test_failed_action_is_in_context_history_with_error(self):
        context = ContextManager()
        context.record_failure("bola_probe", "ConnectError: connection refused", {"path": "/lab/users/2/profile"})
        self.assertEqual(context.observations["last_action"], "bola_probe")
        self.assertEqual(context.observations["last_error"], "ConnectError: connection refused")
        self.assertEqual(context.history[-1]["error"], "ConnectError: connection refused")
        self.assertEqual(context.history[-1]["request"]["path"], "/lab/users/2/profile")

    def test_context_history_preserves_actual_request_and_response_details(self):
        context = ContextManager()
        response = {
            "method": "GET", "url": "http://127.0.0.1/lab/search?q=alice",
            "request_params": {"q": "alice"}, "request_json": None,
            "status_code": 200, "headers": {"content-type": "application/json"},
            "body": {"results": [{"id": 1}]}, "elapsed_seconds": 0.01,
        }
        context.update("search_control", response, [])
        history = context.history[-1]
        self.assertEqual(history["request"]["params"], {"q": "alice"})
        self.assertEqual(history["response_body"], {"results": [{"id": 1}]})
        self.assertEqual(history["response_headers"]["content-type"], "application/json")

    def test_redirect_response_counts_as_handled_action(self):
        context = ContextManager()
        context.update("redirect_probe", {"status_code": 307, "body": {}}, [])
        self.assertIn("redirect_probe", context.observations["successful_actions"])

    def test_fixed_sequence_places_all_prerequisites_before_dependent_actions(self):
        self.assertEqual(set(FIXED_SEQUENCE), set(ACTION_CATALOG))
        self.assertEqual(len(FIXED_SEQUENCE), len(set(FIXED_SEQUENCE)))
        positions = {action_id: index for index, action_id in enumerate(FIXED_SEQUENCE)}
        for action_id, action in ACTION_CATALOG.items():
            for dependency in action["requires"]:
                self.assertIn(dependency, positions, f"Unknown prerequisite {dependency!r}")
                self.assertLess(positions[dependency], positions[action_id])

    def test_detector_uses_synthetic_marker_for_bola(self):
        findings = VulnerabilityDetector().detect(
            "bola_probe",
            {"status_code": 200, "headers": {}, "body": {"lab_marker": "BOLA_CROSS_USER_PROFILE_ACCESS", "user_id": 2, "requester_id": 1, "email": "bob@lab.invalid"}},
        )
        self.assertEqual([item["category"] for item in findings], ["BOLA"])
        self.assertTrue(findings[0]["synthetic_lab"])
        self.assertEqual(findings[0]["benchmark_severity"], "High")
        self.assertIn("not the CVSS", findings[0]["benchmark_severity_definition"])
        self.assertNotIn("severity", findings[0])

    def test_selector_accepts_legacy_selected_action_response_key(self):
        fake = FakeOllamaServer(response_key="selected_action")
        critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict(pf.CVSS_REFERENCE_VECTORS, {"bola_probe": critical, "admin_access_probe": critical}):
                selector = ActionSelector()
                context = ContextManager()
                context.update("health_check", {"status_code": 200, "body": {"status": "ok"}}, [])
                action_id, trace = asyncio.run(selector.select(context, ["health_check"]))
                self.assertEqual(action_id, "bola_probe")
                self.assertEqual(trace["selection_source"], "llm")
                self.assertEqual(trace["legacy_response_key_used"], "selected_action")
                self.assertEqual(trace["ollama_metrics"]["eval_count"], 10)
                self.assertTrue(fake.requests[0]["stream"])
        finally:
            fake.close()

    def test_real_http_json_ollama_protocol_logs_full_candidate_set_and_prerequisite_metadata(self):
        fake = FakeOllamaServer()
        tie_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        tied_actions = {"bola_probe", "admin_access_probe", "mass_assignment_probe", "injection_probe", "ssrf_probe"}
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict(pf.CVSS_REFERENCE_VECTORS, {aid: tie_vector for aid in tied_actions}):
                context = ContextManager()
                selector = ActionSelector()
                first, first_trace = asyncio.run(selector.select(context, []))
                self.assertEqual(first, "bola_probe")
                self.assertEqual(first_trace["selection_source"], "llm")
                self.assertTrue(first_trace["llm_request_made"])
                prompt_ctx = first_trace["prompt_context"]
                self.assertNotIn("action_catalog", prompt_ctx)
                self.assertNotIn("cvss_targets", prompt_ctx)
                prompt_candidate_ids = {item["id"] for item in prompt_ctx["candidate_actions"]}
                self.assertIn("mass_assignment_probe", prompt_candidate_ids)
                mass_candidate = next(item for item in prompt_ctx["candidate_actions"] if item["id"] == "mass_assignment_probe")
                self.assertEqual(mass_candidate["needs"], ["user_control"])
                self.assertIn('"candidate_actions"', first_trace["prompt_text_sent"])
                self.assertNotIn('"available_actions"', first_trace["prompt_text_sent"])
                self.assertIn("ssrf_probe", prompt_candidate_ids)
                self.assertIn("internal_docs_probe", prompt_candidate_ids)
                self.assertGreater(len(prompt_candidate_ids), 17)
                self.assertIn("all listed candidates", prompt_ctx["selection_policy"][0].lower())
                self.assertEqual(prompt_ctx["planning_horizon"], 3)
                self.assertEqual(len(first_trace["planned_actions"]), 3)
                self.assertTrue(fake.requests[0]["stream"])
                self.assertEqual(fake.requests[0]["options"]["num_predict"], 192)
                self.assertEqual(fake.requests[0]["options"]["num_ctx"], 2048)
                self.assertIsInstance(fake.requests[0]["format"], dict)
                self.assertEqual(
                    fake.requests[0]["format"]["properties"]["plan"]["items"]["properties"]["action_id"]["enum"],
                    [item["id"] for item in prompt_ctx["candidate_actions"]],
                )
                self.assertEqual(fake.requests[0]["format"]["properties"]["plan"]["items"]["properties"]["reason"]["maxLength"], 80)

                context.update("health_check", {"status_code": 200, "body": {"status": "ok"}}, [])
                context.update("bola_probe", {
                    "method": "GET", "url": "http://127.0.0.1/lab/users/2/profile",
                    "request_params": {"requester_id": 1}, "request_json": None,
                    "status_code": 404, "headers": {}, "body": {"detail": "not found"},
                }, [])
                third, third_trace = asyncio.run(selector.select(context, ["health_check", "bola_probe"]))
                self.assertEqual(third, "admin_access_probe")
                self.assertEqual(third_trace["selection_source"], "llm")
                self.assertIn('"s":404', third_trace["prompt_text_sent"].replace(" ", ""))
                self.assertIn("recent", third_trace["prompt_context"])
                self.assertNotIn("full_action_history", third_trace["prompt_context"])
                self.assertNotIn("bola_probe", [x.get("a") for x in first_trace["prompt_context"]["recent"]])
                self.assertEqual(len(fake.requests), 2)
                self.assertEqual(fake.requests[0]["model"], "test-model:latest")
                self.assertEqual(third_trace["ollama_metrics"]["eval_count"], 10)
        finally:
            fake.close()

    def test_llm_can_choose_blocked_target_intent_and_engine_plans_prerequisites(self):
        fake = FakeOllamaServer(preferred_action="mass_assignment_probe")
        critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict(pf.CVSS_REFERENCE_VECTORS, {"admin_access_probe": critical, "mass_assignment_probe": critical}):
                selector = ActionSelector()
                context = ContextManager()
                intended, trace = asyncio.run(selector.select(context, []))
                self.assertEqual(intended, "mass_assignment_probe")
                self.assertEqual(trace["selection_source"], "llm")
                self.assertTrue(trace["llm_request_made"])
                engine = pf.PentelligentEngine()
                prerequisite, error = engine._next_unmet_prerequisite(intended, context, [])
                self.assertEqual(prerequisite, "health_check")
                self.assertIsNone(error)
                context.update("health_check", {"status_code": 200, "body": {"status": "ok"}}, [])
                prerequisite, error = engine._next_unmet_prerequisite(intended, context, ["health_check"])
                self.assertEqual(prerequisite, "user_control")
                self.assertIsNone(error)
                context.update("user_control", {"status_code": 200, "body": {"id": 1}}, [])
                prerequisite, error = engine._next_unmet_prerequisite(intended, context, ["health_check", "user_control"])
                self.assertIsNone(prerequisite)
                self.assertIsNone(error)
                self.assertEqual(selector.errors, 0)
                self.assertEqual(selector.fallbacks, 0)
        finally:
            fake.close()

    def test_strict_mode_suppresses_fallback_after_invalid_llm_decision(self):
        fake = FakeOllamaServer(response_key="unexpected_key")
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict("os.environ", {"PENTELLIGENT_ALLOW_FALLBACK": "0"}), \
                 patch.dict(pf.CVSS_REFERENCE_VECTORS, {aid: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" for aid in pf._cvss_action_ids()}):
                context = ContextManager()
                context.update("health_check", {"status_code": 200, "body": {"status": "ok"}}, [])
                selector = ActionSelector()
                action_id, trace = asyncio.run(selector.select(context, ["health_check"]))
                self.assertIsNone(action_id)
                self.assertEqual(trace["selection_source"], "none")
                self.assertTrue(trace["fallback_suppressed"])
                self.assertEqual(selector.errors, 1)
                self.assertEqual(selector.fallbacks, 0)
        finally:
            fake.close()

    def test_truncated_rationale_recovers_only_complete_allowlisted_action_id(self):
        fake = FakeOllamaServer(preferred_action="internal_docs_probe", truncate_response=True)
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict("os.environ", {"PENTELLIGENT_ALLOW_FALLBACK": "0"}):
                context = ContextManager()
                selector = ActionSelector()
                selected, trace = asyncio.run(selector.select(context, []))

            self.assertEqual(selected, "internal_docs_probe")
            self.assertEqual(trace["selection_source"], "llm")
            self.assertTrue(trace["model_proposal_valid"])
            self.assertTrue(trace["model_response_recovered"])
            self.assertFalse(trace["model_response_json_valid"])
            self.assertEqual(trace["model_response_recovery_kind"], "complete_action_id_before_truncated_json")
            self.assertIn('"action_id":"internal_docs_probe"', trace["partial_model_response"])
            self.assertIn("rationale was truncated", trace["reason"])
            self.assertIsNone(trace.get("error"))
            self.assertEqual(selector.errors, 0)
            self.assertEqual(selector.response_recoveries, 1)
            self.assertEqual(selector.fallbacks, 0)
            self.assertEqual(len(fake.requests), 1)
        finally:
            fake.close()

    def test_truncated_response_with_non_candidate_id_is_not_recovered_in_strict_mode(self):
        fake = FakeOllamaServer(truncate_response=True, truncated_action_id="not_a_candidate")
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict("os.environ", {"PENTELLIGENT_ALLOW_FALLBACK": "0"}):
                selector = ActionSelector()
                selected, trace = asyncio.run(selector.select(ContextManager(), []))

            self.assertIsNone(selected)
            self.assertEqual(trace["selection_source"], "none")
            self.assertFalse(trace.get("model_response_recovered", False))
            self.assertTrue(trace["fallback_suppressed"])
            self.assertEqual(selector.response_recoveries, 0)
            self.assertEqual(selector.errors, 1)
            self.assertEqual(selector.fallbacks, 0)
        finally:
            fake.close()

    def test_prompt_context_is_compact_and_does_not_duplicate_full_history(self):
        fake = FakeOllamaServer()
        tie_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict(pf.CVSS_REFERENCE_VECTORS, {aid: tie_vector for aid in pf._cvss_action_ids()}):
                context = ContextManager()
                context.update("health_check", {"status_code": 200, "body": {"status": "ok"}}, [])
                selector = ActionSelector()
                _, trace = asyncio.run(selector.select(context, ["health_check"]))
                prompt = trace["prompt_text_sent"]
                self.assertLess(len(prompt), 6500, f"LLM selection prompt is too large: {len(prompt)} characters")
                self.assertLessEqual(trace["prompt_estimated_tokens"], 1625)
                prompt_context = trace["prompt_context"]
                prompt_candidate_ids = {item["id"] for item in prompt_context["candidate_actions"]}
                self.assertGreater(len(prompt_candidate_ids), len(pf._cvss_action_ids()))
                self.assertTrue(set(pf._cvss_action_ids()).issubset(prompt_candidate_ids))
                self.assertNotIn("action_catalog", prompt_context)
                self.assertNotIn("cvss_targets", prompt_context)
                self.assertNotIn('"method"', prompt)
                self.assertNotIn('"path"', prompt)
                self.assertNotIn("response_body", prompt)
                self.assertNotIn("observations_after_action", prompt)
        finally:
            fake.close()


    def test_single_remaining_finding_is_selected_without_unnecessary_llm_call(self):
        context = ContextManager()
        context.observations["remaining_findings"] = ["MASS_ASSIGNMENT"]
        context.observations["confirmed_findings"] = sorted(pf.TARGET_FINDINGS - {"MASS_ASSIGNMENT"})
        context.observations["successful_actions"] = ["health_check", "user_control"]
        context.observations["primary_user_id"] = 1
        executed = [
            action_id for action_id, definition in ACTION_CATALOG.items()
            if not definition.get("finding") or definition.get("finding") != "MASS_ASSIGNMENT"
        ]
        selector = ActionSelector()
        action_id, trace = asyncio.run(selector.select(context, executed))
        self.assertEqual(action_id, "mass_assignment_probe")
        self.assertEqual(trace["selection_source"], "single_candidate")
        self.assertEqual(trace["decision_method"], "only_feasible_meaningful_intent")
        self.assertFalse(trace["llm_request_made"])
        self.assertEqual(selector.calls, 0)
        self.assertEqual(selector.errors, 0)
        self.assertEqual(selector.fallbacks, 0)

    def test_cvss_v31_known_critical_vector_scores_9_8(self):
        result = calculate_cvss_v31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result["base_score"], 9.8)
        self.assertEqual(result["severity"], "Critical")

    def test_cvss_v31_scope_changed_critical_vector_scores_10(self):
        result = calculate_cvss_v31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertEqual(result["base_score"], 10.0)
        self.assertEqual(result["severity"], "Critical")

    def test_cvss_v31_zero_impact_scores_zero(self):
        result = calculate_cvss_v31_base("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
        self.assertEqual(result["base_score"], 0.0)
        self.assertEqual(result["severity"], "None")

    def test_cvss_v31_matches_first_mysql_sql_injection_example(self):
        # FIRST CVSS v3.1 examples: MySQL Stored SQL Injection (CVE-2013-0375).
        result = calculate_cvss_v31_base("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N")
        self.assertEqual(result["base_score"], 6.4)
        self.assertEqual(result["severity"], "Medium")

    def test_cvss_v31_matches_first_sslv3_poodle_example(self):
        # FIRST CVSS v3.1 examples: SSLv3 POODLE (CVE-2014-3566).
        result = calculate_cvss_v31_base("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
        self.assertEqual(result["base_score"], 3.1)
        self.assertEqual(result["severity"], "Low")

    def test_cvss_v31_rejects_missing_duplicate_or_invalid_metrics(self):
        invalid = [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
            "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:X/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ]
        for vector in invalid:
            with self.subTest(vector=vector), self.assertRaises(ValueError):
                calculate_cvss_v31_base(vector)

    def test_cvss_profile_requires_all_seventeen_actions_and_calculates_scores(self):
        input_items = []
        for action_id in pf._cvss_action_ids():
            input_items.append({
                "action_id": action_id,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            })
        input_items[0]["vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        profile = build_cvss_profile(input_items, "test-model:latest")
        self.assertEqual(len(profile["assessments"]), 17)
        # The model proposed a Critical vector for BOLA, but its hypothetical
        # scenario-reference vector is Low-privilege/C:H and scores 6.5.
        bola = profile["assessments"]["bola_probe"]
        self.assertEqual(bola["base_score"], 6.5)
        self.assertEqual(bola["model_proposed_base_score"], 10.0)
        self.assertEqual(bola["model_proposal_status"], "differs_from_scenario_reference")
        self.assertEqual(profile["priority_order"][0], "ssrf_probe")
        with self.assertRaises(ValueError):
            build_cvss_profile(input_items[:-1], "test-model:latest")

    def test_reference_cvss_rubric_has_varied_scores_without_forcing_unique_ties(self):
        profile = pf.build_cvss_reference_profile("test-model:latest")
        assessments = profile["assessments"]
        scores = {item["base_score"] for item in assessments.values()}
        vectors = {item["vector"] for item in assessments.values()}
        self.assertEqual(len(assessments), 17)
        self.assertGreaterEqual(len(vectors), 9)
        self.assertGreaterEqual(len(scores), 8)
        self.assertEqual(min(scores), 5.3)
        self.assertEqual(max(scores), 9.9)
        # Equivalent assumptions should keep equivalent vectors/scores rather than
        # receiving artificial differences merely to make every score unique.
        self.assertEqual(
            assessments["bola_probe"]["vector"],
            assessments["cache_control_probe"]["vector"],
        )
        self.assertEqual(
            assessments["bola_probe"]["base_score"],
            assessments["cache_control_probe"]["base_score"],
        )
        self.assertEqual(assessments["ssrf_probe"]["severity"], "Critical")
        self.assertEqual(assessments["error_disclosure_probe"]["severity"], "Medium")
        self.assertFalse(profile["model_proposal_summary"]["scores_are_driven_by_model_proposals"])

    def test_cvss_profile_load_recalculates_scores_from_vectors(self):
        raw_assessments = [
            {
                "action_id": action_id,
                "vector": (
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                    if action_id == "bola_probe"
                    else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
                ),
            }
            for action_id in pf._cvss_action_ids()
        ]
        profile = build_cvss_profile(raw_assessments, pf.OLLAMA_MODEL)
        # Deliberately tamper with a persisted number. Loader must calculate from
        # the vector and not trust the stored base_score value.
        profile["assessments"]["bola_probe"]["base_score"] = 1.0
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = Path(temp_dir) / "cvss_profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            loaded = load_cvss_profile(profile_path, pf.OLLAMA_MODEL)
        self.assertEqual(loaded["assessments"]["bola_probe"]["base_score"], 6.5)
        self.assertEqual(loaded["assessments"]["bola_probe"]["model_proposed_base_score"], 10.0)
        self.assertEqual(loaded["priority_order"][0], "ssrf_probe")

    def test_selector_exposes_full_candidate_set_including_lower_cvss_scores(self):
        fake = FakeOllamaServer(preferred_action="admin_access_probe")
        critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict(pf.CVSS_REFERENCE_VECTORS, {"bola_probe": critical, "admin_access_probe": critical}):
                selector = ActionSelector()
                selected, trace = asyncio.run(selector.select(ContextManager(), []))
                self.assertEqual(trace["proposed_action"], "admin_access_probe")
                self.assertEqual(selected, "admin_access_probe")
                self.assertEqual(trace["selection_source"], "llm")
                self.assertEqual(trace["selected_cvss_score"], 10.0)
                candidate_ids = set(trace["candidate_action_ids_sent_to_model"])
                self.assertTrue(set(pf._cvss_action_ids()).issubset(candidate_ids))
                self.assertIn("ssrf_probe", candidate_ids)
                self.assertIn("error_disclosure_probe", candidate_ids)
                self.assertGreater(len(candidate_ids), len(pf._cvss_action_ids()))
                self.assertEqual(len(trace["prompt_context"]["candidate_actions"]), len(candidate_ids))
                self.assertEqual(selector.errors, 0)
        finally:
            fake.close()

    def test_catalogue_contains_seventeen_distinct_target_categories_and_more_than_twenty_actions(self):
        findings = {action.get("finding") for action in ACTION_CATALOG.values() if action.get("finding")}
        self.assertEqual(findings, pf.TARGET_FINDINGS)
        self.assertEqual(len(findings), 17)
        self.assertGreaterEqual(len(ACTION_CATALOG), 28)
        self.assertGreaterEqual(sum(1 for action in ACTION_CATALOG.values() if action.get("action_type") in {"control", "reconnaissance"}), 8)

    def test_dependency_planner_resolves_target_intent_in_order(self):
        context = ContextManager()
        engine = pf.PentelligentEngine()
        first, error = engine._next_unmet_prerequisite("mass_assignment_probe", context, [])
        self.assertEqual(first, "health_check")
        self.assertIsNone(error)
        context.update("health_check", {"status_code": 200, "body": {"status": "ok"}}, [])
        first, error = engine._next_unmet_prerequisite("mass_assignment_probe", context, ["health_check"])
        self.assertEqual(first, "user_control")
        self.assertIsNone(error)
        context.update("user_control", {"status_code": 200, "body": {"id": 1}}, [])
        first, error = engine._next_unmet_prerequisite("mass_assignment_probe", context, ["health_check", "user_control"])
        self.assertIsNone(first)
        self.assertIsNone(error)

    def test_context_extracts_ids_from_user_list_without_promoting_primary_id(self):
        context = ContextManager()
        context.update("users_list_control", {
            "status_code": 200,
            "body": {"users": [{"id": 1}, {"id": 2}]},
        }, [])
        self.assertEqual(context.observations["known_user_ids"], [1, 2])
        self.assertIsNone(context.observations["primary_user_id"])

    def test_new_vulnerability_detectors_require_matching_synthetic_evidence(self):
        detector = VulnerabilityDetector()
        cases = [
            ("cors_probe", {"status_code": 200, "headers": {"access-control-allow-origin": "https://attacker.invalid", "access-control-allow-credentials": "true"}, "body": {"lab_marker": "CORS_REFLECTS_UNTRUSTED_ORIGIN", "origin": "https://attacker.invalid"}}, "CORS_MISCONFIGURATION"),
            ("security_headers_probe", {"status_code": 200, "headers": {"content-type": "application/json"}, "body": {"lab_marker": "MISSING_SECURITY_HEADERS_SIMULATION"}}, "MISSING_SECURITY_HEADERS"),
            ("data_exposure_probe", {"status_code": 200, "headers": {}, "body": {"lab_marker": "EXCESSIVE_SYNTHETIC_DATA_EXPOSURE", "records": [{"api_key": "SYNTHETIC"}]}}, "EXCESSIVE_DATA_EXPOSURE"),
            ("error_disclosure_probe", {"status_code": 500, "headers": {}, "body": {"lab_marker": "VERBOSE_SYNTHETIC_ERROR_DISCLOSURE", "stack_trace": "synthetic"}}, "VERBOSE_ERROR_DISCLOSURE"),
            ("internal_docs_probe", {"status_code": 200, "headers": {}, "body": {"lab_marker": "INTERNAL_DOCUMENTATION_EXPOSED", "internal_routes": ["/lab/admin"]}}, "EXPOSED_INTERNAL_DOCUMENTATION"),
            ("weak_password_policy_probe", {"status_code": 200, "headers": {}, "body": {"lab_marker": "SHORT_PASSWORD_ACCEPTED", "registered": True, "password_length": 6}}, "WEAK_PASSWORD_POLICY"),
            ("jwt_config_probe", {"status_code": 200, "headers": {}, "body": {"lab_marker": "JWT_ALGORITHM_NONE_ENABLED", "accepted_algorithms": ["none", "HS256"]}}, "INSECURE_JWT_CONFIGURATION"),
            ("ssrf_probe", {"status_code": 200, "headers": {}, "body": {"lab_marker": "SIMULATED_SSRF_INTERNAL_RESOURCE_RESOLVED", "simulated_only": True, "requested_host": "internal.lab"}}, "SIMULATED_SSRF"),
            ("rate_limit_probe", {"status_code": 200, "headers": {}, "body": {"lab_marker": "NO_RATE_LIMIT_ENFORCEMENT_IN_LAB", "rate_limit_enforced": False}}, "MISSING_RATE_LIMITING"),
            ("cache_control_probe", {"status_code": 200, "headers": {"cache-control": "public, max-age=3600"}, "body": {"lab_marker": "SENSITIVE_RESPONSE_PUBLICLY_CACHEABLE", "report": "synthetic"}}, "SENSITIVE_CACHEABLE_RESPONSE"),
        ]
        for action_id, response, expected_category in cases:
            with self.subTest(action=action_id):
                detected = detector.detect(action_id, response)
                self.assertEqual([item["category"] for item in detected], [expected_category])
                self.assertTrue(detected[0]["synthetic_lab"])

    def test_batched_cvss_generation_scores_every_target_with_small_prompts(self):
        fake = FakeOllamaServer()
        try:
            with patch.object(runner, "OLLAMA_URL", fake.url), patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), patch.dict("os.environ", {"PENTELLIGENT_CVSS_BATCH_SIZE": "3", "PENTELLIGENT_CVSS_SINGLE_RETRIES": "1"}):
                profile, interactions, elapsed = runner.generate_cvss_profile_batched(
                    pf, ollama_url=fake.url, model="test-model:latest", timeout_seconds=10
                )
            self.assertEqual(len(profile["assessments"]), 17)
            self.assertEqual(len(profile["priority_order"]), 17)
            self.assertEqual(len(interactions), 6)
            self.assertTrue(all(item["kind"] == "batch" for item in interactions))
            self.assertTrue(all(item["prompt_characters"] < 3000 for item in interactions))
            self.assertEqual(len(fake.requests), 6)
            self.assertEqual(profile["profile_generation_fallback_count"], 0)
            self.assertGreaterEqual(elapsed, 0)
        finally:
            fake.close()

    def test_failed_ollama_preflight_saves_partial_score_traces_and_does_not_pass(self):
        fake = FakeOllamaServer(assessment_limit=0)
        try:
            with tempfile.TemporaryDirectory() as temp_dir, \
                 patch.object(runner, "OLLAMA_URL", fake.url), \
                 patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.object(runner, "RESULTS", Path(temp_dir)), \
                 patch.dict("os.environ", {"OLLAMA_TIMEOUT": "10", "PENTELLIGENT_CVSS_BATCH_SIZE": "3", "PENTELLIGENT_CVSS_SINGLE_RETRIES": "0"}):
                ok, message, profile_path = runner.check_ollama(
                    collect_llm_cvss_proposals=True, collect_llm_risk_profile=True
                )
                self.assertFalse(ok)
                self.assertIsNone(profile_path)
                self.assertIn("readiness failed", message)
                trace_files = list(Path(temp_dir).glob("ollama_preflight_*.json"))
                interaction_files = list(Path(temp_dir).glob("cvss_profile_interactions_*.jsonl"))
                self.assertEqual(len(trace_files), 1)
                self.assertEqual(len(interaction_files), 1)
                trace = json.loads(trace_files[0].read_text(encoding="utf-8"))
                self.assertFalse(trace["passed"])
                self.assertEqual(len(trace["scoring_interactions"]), 23)
                self.assertIn("missing/invalid vectors", trace["error"])
                self.assertEqual(len(interaction_files[0].read_text(encoding="utf-8").splitlines()), 23)
        finally:
            fake.close()

    def test_incomplete_cvss_profile_failure_preserves_all_partial_interaction_traces(self):
        fake = FakeOllamaServer(assessment_limit=0)
        try:
            with patch.dict("os.environ", {"PENTELLIGENT_CVSS_BATCH_SIZE": "3", "PENTELLIGENT_CVSS_SINGLE_RETRIES": "0"}):
                with self.assertRaises(runner.CVSSProfileGenerationError) as caught:
                    runner.generate_cvss_profile_batched(
                        pf, ollama_url=fake.url, model="test-model:latest", timeout_seconds=10
                    )
            self.assertIn("missing/invalid vectors", str(caught.exception))
            traces = caught.exception.interactions
            self.assertEqual(len(traces), 23)  # six batches plus one individual attempt per target
            self.assertEqual(sum(item["kind"] == "batch" for item in traces), 6)
            self.assertEqual(sum(item["kind"] == "single_item_retry" for item in traces), 17)
            self.assertTrue(all("prompt_text_sent" in item for item in traces))
        finally:
            fake.close()

    def test_qualitative_profile_retries_and_splits_repeatedly_truncated_batches(self):
        # Simulate Qwen returning incomplete JSON for every multi-item assessment.
        # The generator must split failed batches to single-target requests, never
        # invent missing labels, and still validate the complete 17-target profile.
        fake = FakeOllamaServer(truncate_risk_batch_multi_only=True)
        try:
            with patch.object(runner, "OLLAMA_URL", fake.url), \
                 patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict("os.environ", {
                     "OLLAMA_TIMEOUT": "10",
                     "PENTELLIGENT_RISK_PROFILE_BATCH_SIZE": "4",
                     "PENTELLIGENT_RISK_PROFILE_RETRIES": "1",
                 }):
                profile, trace, elapsed = runner.generate_llm_risk_profile(
                    pf, ollama_url=fake.url, model="test-model:latest", timeout_seconds=10
                )
            self.assertEqual(len(profile["assessments"]), 17)
            self.assertGreater(elapsed, 0)
            attempt_records = [row for row in trace["interactions"] if row.get("record_type") == "assessment_batch_attempt"]
            failed_multi = [row for row in attempt_records if not row.get("validated") and row.get("batch_size", 1) > 1]
            successful_single = [row for row in attempt_records if row.get("validated") and row.get("batch_size") == 1]
            self.assertTrue(failed_multi, "the test must exercise the truncation/split path")
            self.assertEqual(len(successful_single), 17)
            self.assertEqual(set(profile["assessments"]), set(pf._llm_risk_target_ids()))
            self.assertTrue(any(row.get("raw_model_response") for row in failed_multi))
            self.assertTrue(any(row.get("ollama_metrics", {}).get("done_reason") == "length" for row in failed_multi))
        finally:
            fake.close()

    def test_ollama_generation_error_does_not_trigger_batch_split_cascade(self):
        # Transport/model errors are not malformed JSON. Fail promptly instead of
        # splitting the same failed request into many targets and repeating waits.
        fake = FakeOllamaServer(generation_error=True)
        try:
            with patch.object(runner, "OLLAMA_URL", fake.url), \
                 patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict("os.environ", {"OLLAMA_TIMEOUT": "10", "PENTELLIGENT_RISK_PROFILE_BATCH_SIZE": "4", "PENTELLIGENT_RISK_PROFILE_RETRIES": "1"}):
                with self.assertRaises(runner.LLMRiskProfileGenerationError) as caught:
                    runner.generate_llm_risk_profile(
                        pf, ollama_url=fake.url, model="test-model:latest", timeout_seconds=10
                    )
            self.assertEqual(len(fake.requests), 1)
            interactions = caught.exception.risk_trace["interactions"]
            self.assertEqual(len(interactions), 1)
            self.assertIn("Ollama generation error", interactions[0]["error"])
        finally:
            fake.close()

    def test_qualitative_profile_groups_only_by_band_and_skips_unreliable_global_rank_call(self):
        fake = FakeOllamaServer()
        try:
            with patch.object(runner, "OLLAMA_URL", fake.url), \
                 patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict("os.environ", {"OLLAMA_TIMEOUT": "10", "PENTELLIGENT_RISK_PROFILE_BATCH_SIZE": "4"}):
                profile, trace, _ = runner.generate_llm_risk_profile(
                    pf, ollama_url=fake.url, model="test-model:latest", timeout_seconds=10
                )
            self.assertEqual(len(profile["assessments"]), 17)
            self.assertEqual(profile["ranking_source"], "llm_severity_band_groups")
            self.assertIsNone(profile["ranking_call_validated"])
            self.assertFalse(any(row.get("record_type") == "global_ranking_attempt" for row in trace["interactions"]))
            ordered = [profile["assessments"][action_id] for action_id in profile["severity_order"]]
            group_ranks = [row["severity_group_rank"] for row in ordered]
            self.assertEqual(group_ranks, sorted(group_ranks))
            for row in ordered:
                expected_group = len(pf.LLM_SEVERITY_BANDS) - pf.LLM_SEVERITY_ORDER[row["severity_estimate"]]
                self.assertEqual(row["severity_group_rank"], expected_group)
                self.assertNotIn("relative_rank", row)
            self.assertEqual(sum(1 for req in fake.requests if "independent_qualitative_severity_assessment_batch" in req["prompt"]), 5)
            self.assertEqual(sum(1 for req in fake.requests if "independent_qualitative_severity_global_ranking" in req["prompt"]), 0)
        finally:
            fake.close()

    def test_use_cached_risk_profile_flag_fails_without_generating_when_cache_missing(self):
        fake = FakeOllamaServer()
        try:
            with tempfile.TemporaryDirectory() as temp_dir, \
                 patch.object(runner, "OLLAMA_URL", fake.url), \
                 patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.object(runner, "RESULTS", Path(temp_dir)), \
                 patch.dict("os.environ", {"OLLAMA_TIMEOUT": "10"}):
                ok, message, profile_path = runner.check_ollama(use_cached_llm_risk_profile=True)
                self.assertFalse(ok)
                self.assertIn("no compatible cached profile exists", message.lower())
                self.assertIsNone(profile_path)
                self.assertEqual(list(Path(temp_dir).glob("llm_risk_profile_*.json")), [])
                self.assertEqual(list(Path(temp_dir).glob("llm_risk_profile_interactions_*.jsonl")), [])
        finally:
            fake.close()

    def test_ollama_readiness_generates_cvss_baseline_and_independent_llm_risk_profile(self):
        fake = FakeOllamaServer()
        try:
            with tempfile.TemporaryDirectory() as temp_dir, \
                 patch.object(runner, "OLLAMA_URL", fake.url), \
                 patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.object(runner, "RESULTS", Path(temp_dir)), \
                 patch.dict("os.environ", {"OLLAMA_TIMEOUT": "10", "PENTELLIGENT_CVSS_BATCH_SIZE": "3", "PENTELLIGENT_CVSS_SINGLE_RETRIES": "1"}):
                ok, message, profile_path = runner.check_ollama(collect_llm_cvss_proposals=True, collect_llm_risk_profile=True)
                self.assertTrue(ok, message)
                self.assertIsNotNone(profile_path)
                profile = json.loads(Path(profile_path).read_text(encoding="utf-8"))
                self.assertEqual(len(profile["assessments"]), 17)
                self.assertEqual(profile["profile_generation_fallback_count"], 0)
                trace_files = list(Path(temp_dir).glob("cvss_profile_interactions_*.jsonl"))
                preflight_files = list(Path(temp_dir).glob("ollama_preflight_*.json"))
                self.assertEqual(len(trace_files), 1)
                self.assertEqual(len(preflight_files), 1)
                preflight = json.loads(preflight_files[0].read_text(encoding="utf-8"))
                self.assertTrue(preflight["passed"])
                self.assertEqual(preflight["cvss_assessment_count"], 17)
                self.assertFalse(preflight["selection_preflight_performed"])
                risk_profile_files = list(Path(temp_dir).glob("llm_risk_profile_*.json"))
                risk_trace_files = list(Path(temp_dir).glob("llm_risk_profile_interactions_*.jsonl"))
                self.assertEqual(len(risk_profile_files), 1)
                self.assertEqual(len(risk_trace_files), 1)
                risk_profile = json.loads(risk_profile_files[0].read_text(encoding="utf-8"))
                self.assertEqual(len(risk_profile["assessments"]), 17)
                self.assertNotIn("cvss_vector", risk_profile_files[0].read_text(encoding="utf-8").lower())
                risk_trace_records = [
                    json.loads(line) for line in risk_trace_files[0].read_text(encoding="utf-8").splitlines() if line.strip()
                ]
                risk_summary = risk_trace_records[0]
                assessment_records = [row for row in risk_trace_records if row.get("record_type") == "assessment_batch_attempt"]
                ranking_records = [row for row in risk_trace_records if row.get("record_type") == "global_ranking_attempt"]
                self.assertEqual(risk_summary["record_type"], "generation_summary")
                self.assertEqual(len(ranking_records), 0)
                self.assertEqual(risk_summary["ranking_source"], "llm_severity_band_groups")
                self.assertGreaterEqual(len(assessment_records), 5)
                self.assertTrue(all(row.get("validated") for row in assessment_records))
                all_assessed_ids = [aid for row in assessment_records if row.get("validated") for aid in row["accepted_action_ids"]]
                self.assertEqual(set(all_assessed_ids), set(pf._llm_risk_target_ids()))
                self.assertEqual(len(all_assessed_ids), 17)
                prompts = [row["prompt_text_sent"] for row in assessment_records]
                self.assertTrue(all(len(prompt) < 4000 for prompt in prompts), "each one-time prompt must stay compact for 2K-context models")
                self.assertTrue(all(len(prompt) // 4 < 1000 for prompt in prompts), "heuristic prompt estimate should leave room for structured output")
                for risk_prompt in prompts:
                    self.assertNotIn("CVSS:3.1/", risk_prompt)
                    self.assertNotIn("base_score", risk_prompt.lower())
                assessment_contexts = [row["prompt_context"] for row in assessment_records]
                all_context_targets = [item for ctx in assessment_contexts for item in ctx["targets"]]
                self.assertEqual(len(all_context_targets), 17)
                self.assertTrue(all("impact" in item for item in all_context_targets))
                self.assertFalse(preflight["selection_preflight_performed"])
                self.assertEqual(preflight["risk_profile_count"], 17)
                # Six optional CVSS proposal batches plus five qualitative assessment batches.
                # There is no contradictory global ranking pass or throwaway selection call.
                self.assertEqual(len(fake.requests), 11)
                self.assertEqual(sum(1 for req in fake.requests if "independent_qualitative_severity_assessment_batch" in req["prompt"]), 5)
                self.assertEqual(sum(1 for req in fake.requests if "independent_qualitative_severity_global_ranking" in req["prompt"]), 0)
        finally:
            fake.close()

    def test_incomplete_cvss_batches_retry_each_missing_vector_individually(self):
        # The first response in each batch returns only one vector. The generator
        # must retry the remaining targets as one-item requests rather than fail
        # the whole profile or silently fill the missing data.
        fake = FakeOllamaServer(assessment_limit=1)
        try:
            with patch.object(runner, "OLLAMA_URL", fake.url), patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), patch.dict("os.environ", {"PENTELLIGENT_CVSS_BATCH_SIZE": "3", "PENTELLIGENT_CVSS_SINGLE_RETRIES": "1"}):
                profile, interactions, _ = runner.generate_cvss_profile_batched(
                    pf, ollama_url=fake.url, model="test-model:latest", timeout_seconds=10
                )
            self.assertEqual(len(profile["assessments"]), 17)
            self.assertEqual(len(profile["priority_order"]), 17)
            self.assertEqual(len(fake.requests), 17)  # 6 batches + 11 individual retries
            retries = [item for item in interactions if item["kind"] == "single_item_retry"]
            self.assertEqual(len(retries), 11)
            self.assertTrue(all(len(item["requested_action_ids"]) == 1 for item in retries))
            self.assertTrue(all(not item.get("error") for item in interactions))
        finally:
            fake.close()

    def test_new_detectors_do_not_flag_nonmatching_marker(self):
        detector = VulnerabilityDetector()
        for action_id in (
            "cors_probe", "security_headers_probe", "data_exposure_probe", "error_disclosure_probe",
            "internal_docs_probe", "weak_password_policy_probe", "jwt_config_probe", "ssrf_probe",
            "rate_limit_probe", "cache_control_probe",
        ):
            with self.subTest(action=action_id):
                self.assertEqual(detector.detect(action_id, {"status_code": 200, "headers": {}, "body": {"lab_marker": "UNRELATED"}}), [])




    def test_cached_cvss_profile_is_reused_and_not_rescored(self):
        fake = FakeOllamaServer()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                result_dir = Path(temp_dir)
                raw = []
                for action_id in pf._cvss_action_ids():
                    vector = (
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                        if action_id == "bola_probe"
                        else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                    )
                    raw.append({"action_id": action_id, "vector": vector})
                profile = build_cvss_profile(raw, "test-model:latest")
                profile["profile_generation_elapsed_seconds"] = 987.6
                profile["profile_generation_llm_calls"] = 6
                profile["profile_generation_interactions_file"] = str(result_dir / "cvss_profile_interactions_cached.jsonl")
                profile_path = result_dir / "cvss_profile_cached.json"
                profile_path.write_text(json.dumps(profile), encoding="utf-8")
                (result_dir / "cvss_profile_interactions_cached.jsonl").write_text("{}\n", encoding="utf-8")
                with patch.object(runner, "OLLAMA_URL", fake.url), \
                     patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), \
                     patch.object(runner, "RESULTS", result_dir), \
                     patch.dict("os.environ", {
                         "OLLAMA_TIMEOUT": "10",
                         "PENTELLIGENT_CVSS_PROFILE_FILE": "",
                         "PENTELLIGENT_REFRESH_CVSS": "0",
                     }):
                    ok, message, selected_path = runner.check_ollama(force_refresh=False)
                self.assertTrue(ok, message)
                self.assertEqual(Path(selected_path), profile_path.resolve())
                self.assertIn("loaded 17-item scenario-reference CVSS baseline from cache", message)
                # The compatible CVSS profile avoids scoring calls; normal runs do
                # not pay for the optional qualitative profile unless requested.
                self.assertEqual(len(fake.requests), 0)
                preflight = next(result_dir.glob("ollama_preflight_*.json"))
                record = json.loads(preflight.read_text(encoding="utf-8"))
                self.assertTrue(record["profile_reused_from_cache"])
                self.assertEqual(record["profile_generation_elapsed_this_run_seconds"], 0.0)
                self.assertEqual(record["cvss_profile_llm_calls_this_run"] if "cvss_profile_llm_calls_this_run" in record else 0, 0)
                self.assertFalse(record["selection_preflight_performed"])
                self.assertEqual(record["risk_profile_count"], 0)
                self.assertFalse(record["risk_profile_enabled"])
                self.assertIsNone(record["risk_profile_path"])
                self.assertIn("optional static qualitative profile disabled", message)
                self.assertIsNone(__import__("os").environ.get("PENTELLIGENT_LLM_RISK_PROFILE_FILE"))
        finally:
            fake.close()

    def test_unique_highest_cvss_does_not_filter_out_lower_scored_actions(self):
        # The fake model intentionally picks a lower-scored probe. The selector must
        # honor it when it is in the candidate allowlist rather than applying a CVSS gate.
        fake = FakeOllamaServer(preferred_action="bola_probe")
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"):
                selector = ActionSelector()
                action, trace = asyncio.run(selector.select(ContextManager(), []))
            self.assertEqual(action, "bola_probe")
            self.assertEqual(trace["selection_source"], "llm")
            self.assertTrue(trace["llm_request_made"])
            self.assertLess(
                selector.cvss_assessments["bola_probe"]["base_score"],
                selector.cvss_assessments["ssrf_probe"]["base_score"],
            )
            self.assertIn("ssrf_probe", trace["candidate_action_ids_sent_to_model"])
            self.assertIn("bola_probe", trace["candidate_action_ids_sent_to_model"])
            self.assertFalse(trace["cvss_priority_guard_applied"])
            self.assertEqual(len(fake.requests), 1)
        finally:
            fake.close()

    def test_llm_risk_profile_is_complete_band_grouped_and_model_bound(self):
        raw = {"assessments": [
            {
                "action_id": action_id,
                "severity_estimate": "critical" if action_id == "ssrf_probe" else "medium",
                "confidence": "high",
                "rationale": "Independent qualitative assessment for this scenario.",
            }
            for action_id in pf._llm_risk_target_ids()
        ]}
        profile = pf.build_llm_risk_profile(raw, "test-model:latest")
        self.assertEqual(len(profile["assessments"]), 17)
        self.assertEqual(profile["severity_order"][0], "ssrf_probe")
        self.assertEqual(profile["assessments"]["ssrf_probe"]["severity_group_rank"], 1)
        self.assertEqual(profile["ranking_source"], "llm_severity_band_groups")
        medium_ranks = {profile["assessments"][aid]["severity_group_rank"] for aid in pf._llm_risk_target_ids() if aid != "ssrf_probe"}
        self.assertEqual(medium_ranks, {3})
        self.assertNotIn("base_score", json.dumps(profile).lower())
        self.assertNotIn("cvss:3.1", json.dumps(profile).lower())
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "risk.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            loaded = pf.load_llm_risk_profile(path, "test-model:latest")
            self.assertEqual(len(loaded["assessments"]), 17)
            with self.assertRaisesRegex(ValueError, "does not match"):
                pf.load_llm_risk_profile(path, "different-model:latest")
            broken = dict(profile)
            broken["assessments"] = dict(profile["assessments"])
            broken["assessments"].pop("ssrf_probe")
            path.write_text(json.dumps(broken), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Incomplete or invalid"):
                pf.load_llm_risk_profile(path, "test-model:latest")

    def test_cached_risk_profile_preserves_band_groups_and_ties(self):
        fake = FakeOllamaServer()
        try:
            with tempfile.TemporaryDirectory() as temp_dir, \
                 patch.object(runner, "OLLAMA_URL", fake.url), \
                 patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), \
                 patch.dict("os.environ", {"OLLAMA_TIMEOUT": "10", "PENTELLIGENT_RISK_PROFILE_BATCH_SIZE": "4"}):
                profile, _, _ = runner.generate_llm_risk_profile(
                    pf, ollama_url=fake.url, model="test-model:latest", timeout_seconds=10
                )
                order = list(profile["severity_order"])
                ranks_before = {aid: profile["assessments"][aid]["severity_group_rank"] for aid in order}
                path = Path(temp_dir) / "risk_profile.json"
                path.write_text(json.dumps(profile), encoding="utf-8")
                loaded = pf.load_llm_risk_profile(path, "test-model:latest")
                self.assertEqual(loaded["severity_order"], order)
                self.assertEqual(
                    {aid: loaded["assessments"][aid]["severity_group_rank"] for aid in order},
                    ranks_before,
                )
                self.assertLess(order.index("injection_probe"), order.index("bola_probe"))
                self.assertEqual(loaded["assessments"]["injection_probe"]["severity_group_rank"], 2)
                self.assertEqual(loaded["assessments"]["bola_probe"]["severity_group_rank"], 3)
        finally:
            fake.close()

    def test_llm_risk_profile_fingerprint_includes_impact_context(self):
        original = pf._llm_risk_catalog_fingerprint()
        original_context = pf.LLM_RISK_SCENARIO_CONTEXT["bola_probe"]
        try:
            pf.LLM_RISK_SCENARIO_CONTEXT["bola_probe"] = "A materially changed scenario assumption invalidates the cache."
            self.assertNotEqual(pf._llm_risk_catalog_fingerprint(), original)
        finally:
            pf.LLM_RISK_SCENARIO_CONTEXT["bola_probe"] = original_context
        self.assertEqual(pf._llm_risk_catalog_fingerprint(), original)

    def test_profiled_selector_prompt_shows_all_unresolved_probes_without_cvss_anchoring(self):
        fake = FakeOllamaServer()
        critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        try:
            with tempfile.TemporaryDirectory() as temp_dir, \
                 patch.dict(pf.CVSS_REFERENCE_VECTORS, {"bola_probe": critical, "admin_access_probe": critical}):
                profile = pf.build_cvss_reference_profile("test-model:latest")
                profile_path = Path(temp_dir) / "profile.json"
                profile_path.write_text(json.dumps(profile), encoding="utf-8")
                risk_profile = pf.build_llm_risk_profile({"assessments": [
                    {
                        "action_id": action_id,
                        "severity_estimate": "critical" if action_id == "ssrf_probe" else "medium",
                        "confidence": "high" if action_id == "ssrf_probe" else "medium",
                        "rationale": "Risk-profile test estimate from impact assumptions.",
                    }
                    for action_id in pf._llm_risk_target_ids()
                ]}, "test-model:latest")
                risk_path = Path(temp_dir) / "llm_risk_profile.json"
                risk_path.write_text(json.dumps(risk_profile), encoding="utf-8")
                with patch.object(pf, "OLLAMA_URL", fake.url), \
                     patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), \
                     patch.dict("os.environ", {
                         "PENTELLIGENT_CVSS_PROFILE_FILE": str(profile_path),
                         "PENTELLIGENT_LLM_RISK_PROFILE_FILE": str(risk_path),
                         "PENTELLIGENT_ALLOW_FALLBACK": "0",
                     }):
                    selector = ActionSelector()
                    action, trace = asyncio.run(selector.select(ContextManager(), []))
                self.assertIsNotNone(action)
                self.assertLess(len(trace["prompt_text_sent"]), 7500)
                ctx = trace["prompt_context"]
                self.assertIn("candidate_actions", ctx)
                self.assertNotIn("action_catalog", ctx)
                context_candidate_ids = {row["id"] for row in ctx["candidate_actions"]}
                self.assertTrue(set(pf._cvss_action_ids()).issubset(context_candidate_ids))
                self.assertIn("bola_probe", trace["candidate_action_ids_sent_to_model"])
                self.assertIn("ssrf_probe", trace["candidate_action_ids_sent_to_model"])
                ssrf_candidate = next(row for row in ctx["candidate_actions"] if row["id"] == "ssrf_probe")
                self.assertNotIn("cvss_base", ssrf_candidate)
                self.assertNotIn("cvss_vector", ssrf_candidate)
                self.assertNotIn("top_reference_cvss", ctx)
                self.assertNotIn("CVSS:3.1", trace["prompt_text_sent"])
                self.assertFalse(trace["cvss_scoring_required"])
                self.assertFalse(trace["cvss_scores_disclosed_to_selector"])
                self.assertTrue(trace["llm_risk_profile_available"])
                self.assertEqual(ssrf_candidate["severity"], "critical")
                self.assertEqual(ssrf_candidate["confidence"], "high")
                self.assertIn("risk_basis", ssrf_candidate)
                self.assertNotIn("rank", ssrf_candidate)
                self.assertNotIn("relative_rank", trace["prompt_text_sent"])
                self.assertEqual(len(fake.requests), 1)
        finally:
            fake.close()


    def test_selector_prompt_has_complete_compact_impact_cues_without_cvss_anchoring(self):
        fake = FakeOllamaServer()
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), patch.dict(
                "os.environ", {"PENTELLIGENT_ALLOW_FALLBACK": "0"}
            ):
                selector = ActionSelector()
                action_id, trace = asyncio.run(selector.select(ContextManager(), []))
            self.assertIsNotNone(action_id)
            self.assertLess(trace["prompt_characters"], 6500)
            self.assertLess(trace["prompt_estimated_tokens"], 1625)
            prompt = trace["prompt_text_sent"]
            self.assertIn("Real SQLi may expose or alter data", prompt)
            self.assertIn("Privilege escalation", prompt)
            self.assertIn("Prefer direct finding probes", prompt)
            self.assertNotIn("CVSS:3.1", prompt)
            self.assertNotIn("cvss_base", prompt)
            self.assertNotIn("top_reference_cvss", prompt)
            ssrf = next(row for row in trace["prompt_context"]["candidate_actions"] if row["id"] == "ssrf_probe")
            self.assertIn("SSRF", ssrf["impact"])
            self.assertLessEqual(len(ssrf["impact"]), 58)
        finally:
            fake.close()

    def test_local_plan_policy_keeps_recon_last_and_drops_stale_tail(self):
        fake = FakeOllamaServer(forced_plan=["bola_probe", "schema_control", "admin_access_probe"])
        try:
            with patch.object(pf, "OLLAMA_URL", fake.url), patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), patch.dict(
                "os.environ", {"PENTELLIGENT_ALLOW_FALLBACK": "0"}
            ):
                selector = ActionSelector()
                selected, trace = asyncio.run(selector.select(ContextManager(), []))
            self.assertEqual(selected, "bola_probe")
            self.assertEqual(
                [item["action_id"] for item in trace["planned_actions"]],
                ["bola_probe", "schema_control"],
            )
            self.assertEqual(trace["plan_items_removed_by_local_policy"], 1)
            self.assertEqual(trace["plan_policy_adjustments"][0]["action_id"], "admin_access_probe")
        finally:
            fake.close()

    def test_reconnaissance_only_invalidates_plan_for_unexpected_context(self):
        normal_responses = {
            "api_info_control": {
                "status_code": 200,
                "body": {
                    "service": "Pentelligent Synthetic Web API",
                    "purpose": "Local security-testing laboratory",
                    "health": "/health",
                },
            },
            "schema_control": {
                "status_code": 200,
                "body": {
                    "api": "Pentelligent Synthetic Web API",
                    "resource_types": ["users", "profiles", "catalog", "reports"],
                    "conventions": {"pagination": "page/limit", "content_type": "application/json"},
                    "lab_marker": "SAFE_SCHEMA_CONTROL",
                },
            },
            "users_list_control": {
                "status_code": 200,
                "body": {
                    "users": [
                        {"id": 1, "username": "alice", "role": "user"},
                        {"id": 2, "username": "bob", "role": "user"},
                    ],
                    "page": 1, "limit": 10, "total": 2,
                },
            },
        }
        for action_id, response in normal_responses.items():
            self.assertFalse(pf._reconnaissance_response_is_material(action_id, response))
        altered = dict(normal_responses["users_list_control"])
        altered["body"] = json.loads(json.dumps(altered["body"]))
        altered["body"]["users"].append({"id": 3, "username": "admin", "role": "admin"})
        altered["body"]["total"] = 3
        self.assertTrue(pf._reconnaissance_response_is_material("users_list_control", altered))
        self.assertTrue(pf._reconnaissance_response_is_material("schema_control", {"status_code": 503, "body": {}}))

    def test_selector_prompt_stays_compact_when_all_seventeen_scores_tie(self):
        fake = FakeOllamaServer()
        tied_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        try:
            with tempfile.TemporaryDirectory() as temp_dir, \
                 patch.dict(pf.CVSS_REFERENCE_VECTORS, {aid: tied_vector for aid in pf._cvss_action_ids()}):
                profile = pf.build_cvss_reference_profile("test-model:latest")
                profile_path = Path(temp_dir) / "all_tied_profile.json"
                profile_path.write_text(json.dumps(profile), encoding="utf-8")
                with patch.object(pf, "OLLAMA_URL", fake.url), \
                     patch.object(pf, "OLLAMA_MODEL", "test-model:latest"), \
                     patch.dict("os.environ", {
                         "PENTELLIGENT_CVSS_PROFILE_FILE": str(profile_path),
                         "PENTELLIGENT_ALLOW_FALLBACK": "0",
                     }):
                    selector = ActionSelector()
                    action_id, trace = asyncio.run(selector.select(ContextManager(), []))
                self.assertIsNotNone(action_id)
                candidate_ids = set(trace["candidate_action_ids_sent_to_model"])
                self.assertTrue(set(pf._cvss_action_ids()).issubset(candidate_ids))
                self.assertGreater(len(candidate_ids), 17)  # three useful reconnaissance intents also remain eligible
                self.assertLess(trace["prompt_characters"], 6500)
                self.assertLess(trace["prompt_estimated_tokens"], 1625)
                self.assertNotIn("action_catalog", trace["prompt_context"])
                self.assertNotIn("cvss_targets", trace["prompt_context"])
                self.assertNotIn("cvss_vector", trace["prompt_text_sent"])
                self.assertEqual(trace["ollama_context_window"], 2048)
        finally:
            fake.close()

    def test_blocked_dependency_intent_is_valid_audit_event_not_executed_action(self):
        blocked = {
            "action_id": "mass_assignment_probe",
            "selection_source": "dependency_planner",
            "selection_role": "blocked_intent",
            "status": "blocked_unrecoverable_prerequisite",
        }
        self.assertTrue(pf.selection_event_action_role_is_valid(blocked))
        self.assertFalse(pf.selection_event_action_role_is_valid({
            **blocked, "action_id": "invented_action"
        }))
        self.assertFalse(pf.selection_event_action_role_is_valid({
            **blocked, "status": "executed"
        }))
        self.assertFalse(pf.selection_event_action_role_is_valid({
            **blocked, "selection_source": "llm"
        }))
        self.assertTrue(pf.selection_event_action_role_is_valid({
            "action_id": "health_check",
            "selection_source": "dependency_planner",
            "selection_role": "prerequisite",
            "status": "executed",
        }))
        self.assertFalse(pf.selection_event_action_role_is_valid({
            "action_id": "health_check",
            "selection_source": "llm",
            "selection_role": "prerequisite",
            "status": "executed",
        }))


    def test_short_horizon_runner_executes_queued_actions_and_replans(self):
        """Integration regression: a three-item plan must execute followers without another LLM call."""
        fake = FakeOllamaServer(preferred_action="mass_assignment_probe")
        try:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = int(probe.getsockname()[1])
            with tempfile.TemporaryDirectory(prefix="pentelligent_horizon_test_") as temp_dir:
                child_env = os.environ.copy()
                for key in (
                    "PENTELLIGENT_CVSS_PROFILE_FILE",
                    "PENTELLIGENT_LLM_RISK_PROFILE_FILE",
                    "PENTELLIGENT_REFRESH_CVSS",
                    "PENTELLIGENT_REFRESH_LLM_RISK_PROFILE",
                    "PENTELLIGENT_ALLOW_FALLBACK",
                    "PENTELLIGENT_LLM_RISK_PROFILE_GENERATION_SECONDS",
                    "PENTELLIGENT_LLM_RISK_PROFILE_REUSED",
                    "PENTELLIGENT_CVSS_PROFILE_REUSED",
                    "PENTELLIGENT_CVSS_PROFILE_GENERATION_THIS_RUN_SECONDS",
                    "PENTELLIGENT_ACTION_SELECTION_PREFLIGHT_SECONDS",
                ):
                    child_env.pop(key, None)
                child_env.update({
                    "OLLAMA_TIMEOUT": "10",
                    "OLLAMA_NUM_CTX": "2048",
                    "PENTELLIGENT_PLAN_HORIZON": "3",
                    "PENTELLIGENT_ACTION_BUDGET": "35",
                    "PENTELLIGENT_SCENARIO": "default",
                    "PENTELLIGENT_RUN_HOST": "127.0.0.1",
                    "PENTELLIGENT_RUN_PORT": str(port),
                    "PENTELLIGENT_RESULTS": temp_dir,
                })
                output = io.StringIO()
                with patch.dict(os.environ, child_env, clear=True), \
                     patch.object(runner, "OLLAMA_URL", fake.url), \
                     patch.object(runner, "OLLAMA_MODEL", "test-model:latest"), \
                     patch.object(runner, "HOST", "127.0.0.1"), \
                     patch.object(runner, "PORT", port), \
                     patch.object(runner, "BASE_URL", f"http://127.0.0.1:{port}"), \
                     patch.object(runner, "RESULTS", Path(temp_dir)), \
                     patch.object(runner, "BUDGET", 35), \
                     patch.object(runner, "SCENARIO", "default"), \
                     patch.object(sys, "argv", ["run_experiment.py", "--single-scenario"]), \
                     contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    exit_code = runner.main()
                self.assertEqual(exit_code, 0, output.getvalue()[-4000:])
                adaptive_files = list(Path(temp_dir).glob("adaptive_*.json"))
                fixed_files = list(Path(temp_dir).glob("fixed_*.json"))
                self.assertEqual(len(adaptive_files), 1)
                self.assertEqual(len(fixed_files), 1)
                adaptive = json.loads(adaptive_files[0].read_text(encoding="utf-8"))
                fixed = json.loads(fixed_files[0].read_text(encoding="utf-8"))
                metrics = adaptive["metrics"]
                self.assertEqual(adaptive["stop_reason"], "all_target_findings_confirmed")
                self.assertEqual(metrics["target_findings_detected"], 17)
                self.assertEqual(fixed["metrics"]["target_findings_detected"], 17)
                self.assertEqual(fixed["metrics"]["test_actions"], 28)
                self.assertLess(metrics["test_actions"], fixed["metrics"]["test_actions"])
                self.assertLess(metrics["llm_request_attempts"], metrics["test_actions"])
                self.assertGreater(metrics["llm_plan_followup_intents_executed"], 0)
                self.assertGreater(metrics["llm_plan_replan_count"], 0)
                self.assertEqual(metrics["llm_error_count"], 0)
                self.assertEqual(metrics["fallback_selection_count"], 0)
                self.assertEqual(metrics["selected_action_role_validity_percent"], 100.0)
                self.assertEqual(metrics["llm_anticipated_resource_prerequisites_preserved"], 1)
                self.assertEqual(metrics["reference_critical_scenario_category_count"], 4)
                self.assertEqual(metrics["reference_critical_scenario_categories_detected"], 4)
                self.assertIsNotNone(metrics["mean_reference_critical_detection_request_position"])
                event_path = Path(temp_dir) / adaptive["artifacts"]["events_file"] if isinstance(adaptive.get("artifacts"), dict) and adaptive["artifacts"].get("events_file") else None
                if event_path is None or not event_path.exists():
                    run_id = adaptive.get("run_id")
                    matching = list(Path(temp_dir).glob(f"events_{run_id}.jsonl")) if run_id else []
                    self.assertEqual(len(matching), 1)
                    event_path = matching[0]
                event_rows = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
                queued_executions = [
                    row for row in event_rows
                    if row.get("selection_source") == "llm_plan"
                    and row.get("action_id") == row.get("intent_action_id")
                ]
                self.assertEqual(len(queued_executions), metrics["llm_plan_followup_intents_executed"])
                plan_positions = {
                    row.get("plan_position")
                    for row in event_rows
                    if row.get("plan_id") and row.get("plan_position")
                    and row.get("selection_role") in {"finding_probe", "reconnaissance"}
                }
                self.assertIn(2, plan_positions)
        finally:
            fake.close()


class CVSSReportClarityTests(unittest.TestCase):
    """Keep the illustrative baseline separate from optional historical model-vector audits."""

    def _render(self, show_audit: bool) -> str:
        report = {
            "mode": "adaptive",
            "scenario": "report-test",
            "stop_reason": "all_target_findings_confirmed",
            "metrics": {"ollama_selection_count": 1},
            "events": [],
            "findings": [],
            "cvss_prioritization": {
                "show_model_proposal_audit": show_audit,
                "assessments": [{
                    "action_id": "injection_probe",
                    "finding": "SIMULATED_SQLI",
                    "base_score": 9.8,
                    "severity": "Critical",
                    "reference_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "model_proposal_status": "differs_from_scenario_reference",
                    "model_proposed_base_score": 7.5,
                }],
            },
            "llm_risk_assessment": {"assessments": []},
            "dependency_audit": {},
            "saved_files": {},
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runner.print_report(report)
        return output.getvalue()

    def test_normal_report_hides_cached_llm_vector_audit(self) -> None:
        output = self._render(show_audit=False)
        self.assertIn("ILLUSTRATIVE SCENARIO-REFERENCE BASELINE", output)
        self.assertIn("Illustrative score", output)
        self.assertIn("not the adaptive engine's decision order", output)
        self.assertIn("selector does not receive the scores or vectors", output)
        self.assertNotIn("Stored LLM-vector audit", output)
        self.assertNotIn("differs (7.5)", output)

    def test_optional_report_marks_stored_llm_vector_audit_as_separate(self) -> None:
        output = self._render(show_audit=True)
        self.assertIn("Stored LLM-vector audit*", output)
        self.assertIn("may be loaded from an earlier cached profile", output)
        self.assertIn("not action-selection inputs", output)



if __name__ == "__main__":
    unittest.main(verbosity=2)
