#!/usr/bin/env python3
"""One-command, reproducible Fixed-vs-Adaptive Pentelligent synthetic-lab runner.

Starts the bundled API on loopback, runs both modes from a reset state, prints
metrics/action/dependency/finding tables, and saves JSON/JSONL reports.
By default, the runner requires Ollama to be reachable and the configured model
available. Pass --allow-fallback only for diagnostics when LLM use is unavailable.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import httpx
from typing import Any
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
HOST = os.getenv("PENTELLIGENT_RUN_HOST", "127.0.0.1")


def find_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _configured_integer(name: str, default: int) -> int:
    """Parse an integer environment setting without an import-time traceback."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return -1  # main() reports a controlled configuration error.


_port_raw = os.getenv("PENTELLIGENT_RUN_PORT")
if _port_raw is None:
    PORT = find_free_loopback_port()
else:
    PORT = _configured_integer("PENTELLIGENT_RUN_PORT", 0)
BASE_URL = f"http://{HOST}:{PORT}"
RESULTS = Path(os.getenv("PENTELLIGENT_RESULTS", str(HERE / "results"))).expanduser().resolve()
SCENARIO = os.getenv("PENTELLIGENT_SCENARIO", "default")
BUDGET = _configured_integer("PENTELLIGENT_ACTION_BUDGET", 35)
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")


def request_json(
    url: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            content = response.read().decode("utf-8", errors="replace")
            if not content:
                return {}
            parsed = json.loads(content)
            if not isinstance(parsed, dict):
                raise ValueError(f"Expected JSON object from {url}")
            return parsed
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body}") from exc


def wait_for_health(proc: subprocess.Popen[bytes], timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not checked yet"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"Local API server exited with code {proc.returncode}. "
                "Inspect the synthetic API server log."
            )
        try:
            health = request_json(f"{BASE_URL}/health", timeout=1.0)
            if health.get("status") != "ok":
                raise RuntimeError("/health returned an unexpected payload")
            root = request_json(f"{BASE_URL}/", timeout=1.0)
            if root.get("service") != "Pentelligent Synthetic Web API":
                raise RuntimeError("Port responds, but it is not the bundled Pentelligent synthetic API")
            return
        except Exception as exc:
            last_error = str(exc)
            time.sleep(0.2)
    raise TimeoutError(f"Local synthetic API did not become healthy: {last_error}")


def line(char: str = "─", width: int = 106) -> None:
    print(char * width)


def table(headers: list[str], rows: list[list[Any]]) -> None:
    values = [[str(value if value is not None else "—") for value in headers]]
    values.extend([[str(value if value is not None else "—") for value in row] for row in rows])
    widths = [max(len(row[index]) for row in values) for index in range(len(headers))]
    fmt = " | ".join("{: <" + str(width) + "}" for width in widths)
    print(fmt.format(*values[0]))
    print("-+-".join("-" * width for width in widths))
    for row in values[1:]:
        print(fmt.format(*row))


def _round_metric(value: Any, digits: int = 3) -> Any:
    return round(value, digits) if isinstance(value, (float, int)) else value


def print_report(report: dict[str, Any]) -> None:
    mode = str(report.get("mode", "unknown"))
    metrics = report.get("metrics", {})
    print(f"\n{mode.upper()} ENGINE | scenario={report.get('scenario')} | stop_reason={report.get('stop_reason')}")
    line()
    metric_rows = [
        ["Elapsed testing time (s)", metrics.get("testing_time_seconds")],
        ["Action catalogue size", metrics.get("action_catalog_size")],
        ["Target categories in scope", metrics.get("target_finding_count")],
        ["Control actions in catalogue", metrics.get("control_action_count")],
        ["Reconnaissance actions in catalogue", metrics.get("reconnaissance_action_count")],
        ["Actions in executed sequence", metrics.get("test_actions")],
        ["Action slots handled", metrics.get("handled_action_slots")],
        ["Actions skipped for unmet prerequisites", metrics.get("skipped_actions")],
        ["Preflight errors", metrics.get("preflight_errors")],
        ["Rejected actions", metrics.get("rejected_actions")],
        ["HTTP requests started", metrics.get("http_requests")],
        ["HTTP responses received", metrics.get("completed_http_responses")],
        ["Confirmed synthetic findings", f"{metrics.get('target_findings_detected')}/{metrics.get('target_finding_count')}"],
        ["Target finding coverage (%)", metrics.get("target_finding_coverage_percent")],
        ["Goal-relevant probes (%)", metrics.get("goal_relevant_probe_percent")],
        ["Schema-valid LLM decisions (%)", metrics.get("llm_decision_validity_percent")],
        ["Selection event action/role validity (%)", metrics.get("selected_action_role_validity_percent")],
        ["Ollama-selected actions", metrics.get("ollama_selection_count", 0)],
        ["LLM intent decisions (%)", metrics.get("llm_intent_decision_share_percent")],
        ["Planning horizon", metrics.get("llm_planning_horizon")],
        ["LLM plan calls", metrics.get("llm_plan_calls", 0)],
        ["Mean proposed plan length", metrics.get("llm_mean_proposed_plan_length")],
        ["Queued plan intents attempted", metrics.get("llm_plan_followup_intents_attempted", 0)],
        ["Queued plan intents completed", metrics.get("llm_plan_followup_intents_completed", 0)],
        ["Queued plan items discarded", metrics.get("llm_plan_items_discarded", 0)],
        ["Plan items removed by local policy", metrics.get("llm_plan_items_removed_by_local_policy", 0)],
        ["Anticipated resource prerequisites preserved", metrics.get("llm_anticipated_resource_prerequisites_preserved", 0)],
        ["Replan triggers / plan-end events", metrics.get("llm_plan_replan_count", 0)],
        ["Mean candidates per LLM request", metrics.get("mean_candidates_considered_per_llm_request")],
        ["Reference-critical categories detected (CVSS audit)", f"{metrics.get('reference_critical_scenario_categories_detected', 0)}/{metrics.get('reference_critical_scenario_category_count', 0)}"],
        ["Mean request position for reference-critical findings", metrics.get("mean_reference_critical_detection_request_position")],
        ["Reference-critical coverage after 5 requests (%)", metrics.get("reference_critical_coverage_after_5_requests_percent")],
        ["Reference-critical coverage after 10 requests (%)", metrics.get("reference_critical_coverage_after_10_requests_percent")],
        ["Reference-critical coverage after 15 requests (%)", metrics.get("reference_critical_coverage_after_15_requests_percent")],
        ["Selections below highest reference CVSS (audit only)", metrics.get("llm_lower_score_probe_selections", 0)],
        ["CVSS hard-gate overrides (should be 0)", metrics.get("cvss_priority_guard_selection_count", 0)],
        ["Reference CVSS estimates (separate baseline)", metrics.get("cvss_assessment_count", 0)],
        ["LLM qualitative risk profile loaded", metrics.get("llm_risk_profile_loaded", False)],
        ["LLM qualitative severity estimates", metrics.get("llm_risk_assessment_count", 0)],
        ["Progress-guard overrides", metrics.get("progress_guard_selection_count", 0)],
        ["Prerequisite-planner selections", metrics.get("dependency_planner_selection_count", 0)],
        ["Single-candidate selections", metrics.get("single_candidate_selection_count", 0)],
        ["Fallback-selected actions", metrics.get("fallback_selection_count", 0)],
        ["LLM request errors", metrics.get("llm_error_count", 0)],
        ["Recovered truncated LLM outputs", metrics.get("llm_response_recovery_count", 0)],
        ["LLM request attempts", metrics.get("llm_request_attempts", 0)],
        ["LLM request wall time (s)", metrics.get("llm_request_wall_time_seconds", 0)],
        ["Ollama-measured calls", metrics.get("llm_measured_calls", 0)],
        ["Ollama-reported duration (s)", metrics.get("llm_total_duration_seconds", 0)],
        ["LLM prompt tokens", metrics.get("llm_prompt_tokens", 0)],
        ["LLM generated tokens", metrics.get("llm_generated_tokens", 0)],
        ["Rejected selections", metrics.get("rejected_actions", 0)],
    ]
    table(["Metric", "Value"], [[label, _round_metric(value)] for label, value in metric_rows])

    events = report.get("events", [])
    print("\nACTION TRACE")
    action_rows = []
    for event in events:
        response = event.get("response", {}) or {}
        action_rows.append([
            event.get("step", "—"),
            event.get("intent_action_id") or event.get("requested_action_id") or event.get("action_id", "—"),
            event.get("action_id", "—"),
            event.get("selection_source", "fixed"),
            event.get("selection_role", "fixed_sequence"),
            response.get("status_code", event.get("status", "—")),
            ", ".join(f.get("category", "") for f in event.get("new_findings", [])) or "—",
        ])
    if action_rows:
        table(["#", "Requested intent / fixed target", "Action actually executed", "Decision source", "Selection role", "HTTP/status", "New finding(s)"], action_rows)
    else:
        print("No actions executed.")

    print("\nCONFIRMED SYNTHETIC-LAB FINDINGS")
    print("Benchmark tier is fixture metadata; LLM severity is a qualitative model estimate; CVSS is a separate scenario-reference calculation.")
    findings = report.get("findings", [])
    if findings:
        table(["Category", "Benchmark tier", "LLM potential severity", "LLM confidence", "Reference CVSS", "CVSS band", "Action", "Evidence"], [
            [item.get("category"), item.get("benchmark_severity"),
             (item.get("llm_risk_assessment") or {}).get("severity_estimate"),
             (item.get("llm_risk_assessment") or {}).get("confidence"),
             (item.get("cvss_estimate") or {}).get("base_score"),
             (item.get("cvss_estimate") or {}).get("severity"),
             item.get("action_id"), item.get("evidence")]
            for item in findings
        ])
    else:
        print("No target findings confirmed.")

    cvss_info = report.get("cvss_prioritization", {})
    cvss_rows = cvss_info.get("assessments", [])
    show_model_proposal_audit = bool(cvss_info.get("show_model_proposal_audit", False))
    print("\nCVSS v3.1 ILLUSTRATIVE SCENARIO-REFERENCE BASELINE (LOCAL CALCULATION; POST-RUN AUDIT ONLY)")
    if cvss_rows:
        def model_proposal_label(item: dict[str, Any]) -> str:
            status = item.get("model_proposal_status", "not_collected")
            proposal_score = item.get("model_proposed_base_score")
            if status == "matches_scenario_reference":
                return f"matches ({proposal_score})"
            if status == "differs_from_scenario_reference":
                return f"differs ({proposal_score})"
            return "not collected"

        headers = ["Rank", "Action", "Finding", "Illustrative score", "CVSS band"]
        if show_model_proposal_audit:
            headers.append("Stored LLM-vector audit*")
        headers.append("Illustrative scenario vector")
        rows = []
        for rank, item in enumerate(cvss_rows, 1):
            row = [rank, item.get("action_id"), item.get("finding"), item.get("base_score"), item.get("severity")]
            if show_model_proposal_audit:
                row.append(model_proposal_label(item))
            row.append(item.get("reference_vector", item.get("vector")))
            rows.append(row)
        table(headers, rows)
        print("NOTE: these scores are calculated from study-defined hypothetical analogue vectors; they are not validated severity ratings of the synthetic markers.")
        print("This is a post-run comparison baseline sorted by the illustrative score, not the adaptive engine's decision order.")
        print("The adaptive selector does not receive the scores or vectors. CVSS measures vulnerability severity, not the optimal order in which a testing agent should probe.")
        if show_model_proposal_audit:
            print("* Stored LLM-vector comparisons belong to the separate optional CVSS-vector audit and may be loaded from an earlier cached profile; they are not action-selection inputs.")
    else:
        print("No scenario-reference CVSS estimates available for this run.")

    risk_info = report.get("llm_risk_assessment", {})
    risk_rows = risk_info.get("assessments", [])
    print("\nLLM QUALITATIVE POTENTIAL-SEVERITY ASSESSMENT (NOT CVSS; MODEL JUDGMENT)")
    if risk_rows:
        table(["Severity group", "Action", "Finding", "LLM severity band", "Confidence", "Assessment rationale"], [
            [item.get("severity_group_rank"), item.get("action_id"), item.get("finding"),
             item.get("severity_estimate"), item.get("confidence"), item.get("rationale")]
            for item in risk_rows
        ])
        print("Group 1=critical, 2=high, 3=medium, 4=low, 5=informational. Rows in the same group are tied; catalogue order is display-only, not an additional LLM ranking.")
        print("These are uncalibrated qualitative estimates of a plausible analogue if confirmed. They are not CVSS or proof of the synthetic marker's real-world impact.")
    else:
        print("No validated LLM qualitative risk profile was available.")

    print("\nPREREQUISITE / RESOURCE AUDIT")
    audit = report.get("dependency_audit", {})
    audit_rows = []
    for action, item in audit.items():
        check = item.get("preflight_check") or item.get("dependency_check_at_execution") or {}
        dep_satisfied = check.get("satisfied_before_execution")
        if item.get("skipped"):
            deps_state = "BLOCKED / SKIPPED"
        elif dep_satisfied is None:
            deps_state = "not checked"
        elif all(dep_satisfied.values()):
            deps_state = "PASS"
        else:
            deps_state = "FAIL"
        resource = item.get("resource_id_available_at_execution")
        resource_text = "required / present" if item.get("resource_id_required") and resource else (
            "required / MISSING" if item.get("resource_id_required") and resource is False else
            "not required" if not item.get("resource_id_required") else "not executed"
        )
        audit_rows.append([
            action,
            ", ".join(item.get("requires", [])) or "none",
            deps_state,
            item.get("executed"),
            item.get("skipped"),
            item.get("succeeded"),
            resource_text,
        ])
    table(["Action", "Prerequisites", "Preflight check", "HTTP executed", "Skipped", "Succeeded", "Resource ID"], audit_rows)

    print("\nSAVED ARTIFACTS")
    for key, value in report.get("saved_files", {}).items():
        print(f"  {key}: {value}")

    if mode == "adaptive":
        print("\nLLM EXECUTION ASSESSMENT")
        if metrics.get("ollama_selection_count", 0) > 0:
            print("  PASS: at least one action was selected directly from the Ollama proposal.")
        else:
            print("  FAIL: no action was selected directly from Ollama.")
        if metrics.get("fallback_selection_count", 0):
            print("  WARNING: fallback selections occurred; this run is not LLM-only.")
        if metrics.get("progress_guard_selection_count", 0):
            print("  NOTE: progress guard overrode one or more original model proposals.")
        if metrics.get("llm_error_count", 0):
            print("  WARNING: LLM errors occurred; inspect prompts, partial stream output, and error details in JSONL.")
        if metrics.get("llm_response_recovery_count", 0):
            print(
                "  NOTE: one or more truncated model responses were recovered only because a complete, "
                "allowlisted action_id was emitted first; the incomplete rationale was discarded. "
                "Inspect model_response_recovery_note in the interaction trace."
            )
        if report.get("stop_reason") == "llm_selection_failed_strict_mode":
            print("  STOPPED SAFELY: strict mode did not substitute a fallback action after the LLM failure.")
        if metrics.get("llm_decision_validity_percent") is None:
            print("  NOTE: no completed LLM decisions were available for schema/allowlist validity measurement.")


async def _ollama_generate_stream_json(
    prompt_text: str,
    *,
    model: str,
    ollama_url: str,
    timeout_seconds: float,
    num_predict: int,
    response_format: str | dict[str, Any] = "json",
) -> tuple[dict[str, Any], str, dict[str, Any], float]:
    """Read one Ollama /api/generate JSON-mode response from its NDJSON stream."""
    started = time.perf_counter()
    fragments: list[str] = []
    metrics: dict[str, Any] = {}
    done_seen = False
    timeout = httpx.Timeout(
        timeout=timeout_seconds,
        connect=min(10.0, timeout_seconds),
        read=timeout_seconds,
        write=min(30.0, timeout_seconds),
        pool=min(10.0, timeout_seconds),
    )
    payload = {
        "model": model,
        "prompt": prompt_text,
        "stream": True,
        "format": response_format,
        "keep_alive": os.getenv("OLLAMA_KEEP_ALIVE", "30m"),
        "options": {"temperature": 0, "num_predict": num_predict, "num_ctx": int(os.getenv("OLLAMA_NUM_CTX", "2048"))},
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            async with client.stream("POST", f"{ollama_url.rstrip('/')}/api/generate", json=payload) as response:
                response.raise_for_status()
                async for line_text in response.aiter_lines():
                    if not line_text.strip():
                        continue
                    chunk = json.loads(line_text)
                    if not isinstance(chunk, dict):
                        raise ValueError("Ollama stream chunk must be a JSON object")
                    if chunk.get("error"):
                        raise ValueError(f"Ollama generation error: {chunk['error']}")
                    fragment = chunk.get("response", "")
                    if isinstance(fragment, str) and fragment:
                        fragments.append(fragment)
                    for key in ("total_duration", "load_duration", "prompt_eval_count", "eval_count", "done_reason"):
                        if key in chunk:
                            metrics[key] = chunk[key]
                    if chunk.get("done") is True:
                        done_seen = True
    except Exception as exc:
        # Preserve partial stream data even if the model stalls, disconnects, or
        # returns an error record. This is diagnostics only; incomplete data is
        # never parsed as a successful profile or selector result.
        try:
            exc.raw_model_response = "".join(fragments) or None
            exc.ollama_metrics = dict(metrics)
            exc.elapsed_seconds = time.perf_counter() - started
        except Exception:
            pass
        raise
    raw = "".join(fragments)
    elapsed = time.perf_counter() - started
    if not done_seen:
        raise ValueError("Ollama stream ended without a final done=true chunk")
    if not raw.strip():
        raise ValueError("Ollama returned an empty JSON response")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        # Preserve the model's partial generation so profile batch retry/split
        # logic and audit logs can distinguish truncation from an empty response.
        exc.raw_model_response = raw
        exc.ollama_metrics = dict(metrics)
        exc.elapsed_seconds = elapsed
        raise
    if not isinstance(parsed, dict):
        error = ValueError("Ollama output must be a JSON object")
        error.raw_model_response = raw
        error.ollama_metrics = dict(metrics)
        error.elapsed_seconds = elapsed
        raise error
    return parsed, raw, metrics, elapsed



class CVSSProfileGenerationError(RuntimeError):
    """Failure to create a complete profile, preserving partial LLM traces."""

    def __init__(self, message: str, interactions: list[dict[str, Any]]) -> None:
        super().__init__(message)
        self.interactions = interactions


class LLMRiskProfileGenerationError(RuntimeError):
    """Failure to create the qualitative profile, preserving the exact request trace."""

    def __init__(self, message: str, trace: dict[str, Any]) -> None:
        super().__init__(message)
        self.risk_trace = trace

def generate_cvss_profile_batched(
    engine_module: Any,
    *,
    ollama_url: str | None = None,
    model: str | None = None,
    timeout_seconds: float | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], float]:
    """Ask Ollama for CVSS vectors in small batches; retry any omitted items individually.

    The model proposes metric vectors, while ``calculate_cvss_v31_base`` and
    ``build_cvss_profile`` validate inputs and calculate all numeric scores locally.
    Partial batch responses are not treated as complete profiles.
    """
    ollama_url = (ollama_url or OLLAMA_URL).rstrip("/")
    model = model or OLLAMA_MODEL
    if timeout_seconds is None:
        timeout_seconds = float(os.getenv("OLLAMA_TIMEOUT", "270"))
    if not 5 <= timeout_seconds <= 600:
        raise ValueError("OLLAMA_TIMEOUT must be between 5 and 600 seconds.")
    try:
        batch_size = int(os.getenv("PENTELLIGENT_CVSS_BATCH_SIZE", "3"))
    except ValueError as exc:
        raise ValueError("PENTELLIGENT_CVSS_BATCH_SIZE must be an integer from 1 to 5.") from exc
    if not 1 <= batch_size <= 5:
        raise ValueError("PENTELLIGENT_CVSS_BATCH_SIZE must be between 1 and 5.")
    try:
        single_retries = int(os.getenv("PENTELLIGENT_CVSS_SINGLE_RETRIES", "1"))
    except ValueError as exc:
        raise ValueError("PENTELLIGENT_CVSS_SINGLE_RETRIES must be an integer from 0 to 3.") from exc
    if not 0 <= single_retries <= 3:
        raise ValueError("PENTELLIGENT_CVSS_SINGLE_RETRIES must be between 0 and 3.")

    expected_ids = list(engine_module._cvss_action_ids())
    targets = [
        {
            "action_id": action_id,
            "finding": engine_module.ACTION_CATALOG[action_id]["finding"],
            "assumption": engine_module.CVSS_SCENARIO_ASSUMPTIONS[action_id],
        }
        for action_id in expected_ids
    ]
    vectors: dict[str, str] = {}
    interactions: list[dict[str, Any]] = []
    generation_started = time.monotonic()

    def assess(request_targets: list[dict[str, Any]], *, kind: str, batch_index: int, attempt: int) -> None:
        target_ids = [item["action_id"] for item in request_targets]
        prompt_context = {
            "cvss_version": "3.1",
            "cvss_scoring_required": True,
            "cvss_targets": request_targets,
            "rules": [
                "Return one assessment for EACH supplied action_id, exactly once.",
                "Return valid CVSS:3.1 Base vectors with AV, AC, PR, UI, S, C, I, A.",
                "Do not return numeric scores. The program computes them exactly from the vectors.",
                "Assess only the supplied hypothetical scenario assumptions; do not infer real-world exploitability.",
                'Return JSON only: {"cvss_assessments":[{"action_id":"...","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}',
            ],
        }
        system_prompt = (
            "You are estimating CVSS v3.1 Base metric vectors for a controlled synthetic Web API lab. "
            "Assess only the listed scenarios. Keep output minimal; include every requested action ID once, "
            "and output no explanation outside the JSON. Numeric scores are calculated by the program.\n\n"
        )
        prompt_text = system_prompt + json.dumps(prompt_context, ensure_ascii=False, separators=(",", ":"))
        record: dict[str, Any] = {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kind": kind,
            "batch_index": batch_index,
            "attempt": attempt,
            "requested_action_ids": target_ids,
            "prompt_text_sent": prompt_text,
            "prompt_characters": len(prompt_text),
            "prompt_estimated_tokens": max(1, (len(prompt_text) + 3) // 4),
            "model": model,
            "request_made": False,
        }
        try:
            record["request_made"] = True
            parsed, raw, metrics, elapsed = asyncio.run(_ollama_generate_stream_json(
                prompt_text,
                model=model,
                ollama_url=ollama_url,
                timeout_seconds=timeout_seconds,
                num_predict=260 if len(request_targets) > 1 else 120,
            ))
            record.update({
                "raw_model_response": raw,
                "parsed_model_response": parsed,
                "ollama_metrics": metrics,
                "elapsed_seconds": round(elapsed, 3),
            })
            raw_assessments = parsed.get("cvss_assessments")
            if isinstance(raw_assessments, dict):
                raw_assessments = [
                    ({"action_id": aid, "vector": value} if isinstance(value, str)
                     else {"action_id": aid, **value} if isinstance(value, dict) else
                     {"action_id": aid, "vector": None})
                    for aid, value in raw_assessments.items()
                ]
            if not isinstance(raw_assessments, list):
                record["validation_errors"] = ["Response did not contain a cvss_assessments list/object."]
                return
            accepted: list[str] = []
            errors: list[str] = []
            for assessment in raw_assessments:
                if not isinstance(assessment, dict):
                    errors.append("Non-object assessment item ignored.")
                    continue
                action_id = assessment.get("action_id")
                vector = assessment.get("vector") or assessment.get("cvss_vector")
                if action_id not in target_ids:
                    errors.append(f"Unexpected action_id ignored: {action_id!r}.")
                    continue
                if action_id in vectors or action_id in accepted:
                    errors.append(f"Duplicate action_id ignored: {action_id!r}.")
                    continue
                try:
                    engine_module.calculate_cvss_v31_base(vector)
                except (TypeError, ValueError) as exc:
                    errors.append(f"Invalid vector for {action_id}: {exc}")
                    continue
                vectors[action_id] = vector
                accepted.append(action_id)
            record["accepted_action_ids"] = accepted
            record["missing_action_ids_after_response"] = [aid for aid in target_ids if aid not in vectors]
            record["validation_errors"] = errors
        except Exception as exc:
            record.update({
                "error": f"{type(exc).__name__}: {exc}",
                "raw_model_response": None,
                "accepted_action_ids": [],
                "missing_action_ids_after_response": [aid for aid in target_ids if aid not in vectors],
            })
        finally:
            interactions.append(record)

    # The last observed failure showed the small model returned only the vector
    # for its selected action instead of all 17 requested vectors. Small batches
    # limit output complexity, and any missing vector is retried alone.
    batch_index = 0
    for offset in range(0, len(targets), batch_size):
        batch_index += 1
        batch = targets[offset:offset + batch_size]
        assess(batch, kind="batch", batch_index=batch_index, attempt=1)

    for action_id in expected_ids:
        if action_id in vectors:
            continue
        target = next(item for item in targets if item["action_id"] == action_id)
        for attempt in range(1, single_retries + 2):
            if action_id in vectors:
                break
            assess([target], kind="single_item_retry", batch_index=batch_index + 1, attempt=attempt)

    missing = [action_id for action_id in expected_ids if action_id not in vectors]
    if missing:
        raise CVSSProfileGenerationError(
            "CVSS profile incomplete after batched assessment and individual retries; "
            "missing/invalid vectors for: " + ", ".join(missing),
            interactions,
        )

    raw_assessments = [{"action_id": action_id, "vector": vectors[action_id]} for action_id in expected_ids]
    profile = engine_module.build_cvss_profile(raw_assessments, model)
    elapsed_total = time.monotonic() - generation_started
    profile["profile_generation_elapsed_seconds"] = round(elapsed_total, 3)
    profile["profile_generation_method"] = "LLM CVSS v3.1 vectors in small batches; incomplete batch items retried individually; scores calculated locally"
    profile["profile_generation_llm_calls"] = len(interactions)
    profile["profile_generation_batch_size"] = batch_size
    profile["profile_generation_fallback_count"] = 0
    return profile, interactions, elapsed_total


def _load_compatible_cached_profile(engine_module: Any, model: str, results_dir: Path, explicit_path: str | None = None) -> tuple[dict[str, Any] | None, Path | None, str | None]:
    """Return a validated profile for this model/catalogue, newest first.

    An explicitly configured profile is authoritative: if invalid, fail loudly.
    Otherwise scan prior profile files so costly CVSS assessment is not repeated
    on every experiment launch. Profiles are checked against model, exact target IDs,
    the current per-target assumptions, and the local CVSS calculator.
    """
    if explicit_path:
        candidate = Path(explicit_path).expanduser().resolve()
        profile = engine_module.load_cvss_profile(candidate, model)
        return profile, candidate, "explicit"
    candidates = sorted(
        results_dir.glob("cvss_profile_*.json"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    invalid_reasons: list[str] = []
    for candidate in candidates:
        try:
            profile = engine_module.load_cvss_profile(candidate, model)
            return profile, candidate.resolve(), "cache"
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            invalid_reasons.append(f"{candidate.name}: {exc}")
    note = "; ".join(invalid_reasons[:3]) if invalid_reasons else None
    return None, None, note


def _load_compatible_llm_risk_profile(
    engine_module: Any, model: str, results_dir: Path, explicit_path: str | None = None
) -> tuple[dict[str, Any] | None, Path | None, str | None]:
    """Find the newest qualitative risk profile compatible with the model and catalogue."""
    if explicit_path:
        candidate = Path(explicit_path).expanduser().resolve()
        return engine_module.load_llm_risk_profile(candidate, model), candidate, "explicit"
    invalid: list[str] = []
    candidates = sorted(
        results_dir.glob("llm_risk_profile_*.json"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    for candidate in candidates:
        try:
            profile = engine_module.load_llm_risk_profile(candidate, model)
            return profile, candidate.resolve(), "cache"
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            invalid.append(f"{candidate.name}: {exc}")
    return None, None, "; ".join(invalid[:3]) or None


def generate_llm_risk_profile(
    engine_module: Any,
    *,
    ollama_url: str | None = None,
    model: str | None = None,
    timeout_seconds: float | None = None,
) -> tuple[dict[str, Any], dict[str, Any], float]:
    """Generate a complete qualitative risk profile in small validated batches.

    Severity/confidence/rationale assessments are generated in small groups so a
    small local model cannot consume its entire output budget on a 17-item JSON
    document. A separate compact pass orders all IDs globally. Bad assessment
    batches are retried, then recursively split; no missing estimate is invented.
    If only the optional global ordering pass fails, the validated severity bands
    remain usable and a clearly marked catalogue-order tie-break is used.
    """
    ollama_url = (ollama_url or OLLAMA_URL).rstrip("/")
    model = model or OLLAMA_MODEL
    timeout_seconds = float(timeout_seconds if timeout_seconds is not None else os.getenv("OLLAMA_TIMEOUT", "270"))
    if not 5 <= timeout_seconds <= 600:
        raise ValueError("OLLAMA_TIMEOUT must be between 5 and 600 seconds.")
    try:
        batch_size = int(os.getenv("PENTELLIGENT_RISK_PROFILE_BATCH_SIZE", "4"))
    except ValueError as exc:
        raise ValueError("PENTELLIGENT_RISK_PROFILE_BATCH_SIZE must be an integer from 1 to 6.") from exc
    if not 1 <= batch_size <= 6:
        raise ValueError("PENTELLIGENT_RISK_PROFILE_BATCH_SIZE must be between 1 and 6.")
    try:
        retries = int(os.getenv("PENTELLIGENT_RISK_PROFILE_RETRIES", "1"))
    except ValueError as exc:
        raise ValueError("PENTELLIGENT_RISK_PROFILE_RETRIES must be an integer from 0 to 2.") from exc
    if not 0 <= retries <= 2:
        raise ValueError("PENTELLIGENT_RISK_PROFILE_RETRIES must be between 0 and 2.")

    target_ids = list(engine_module._llm_risk_target_ids())
    targets = [
        {
            "action_id": action_id,
            # Keep the full authored caveat. Batching, rather than truncating the
            # impact description, is what keeps this request small.
            "impact": str(engine_module.LLM_RISK_SCENARIO_CONTEXT.get(action_id, "")),
        }
        for action_id in target_ids
    ]
    target_by_id = {item["action_id"]: item for item in targets}
    all_interactions: list[dict[str, Any]] = []
    assessments_by_id: dict[str, dict[str, Any]] = {}
    call_counter = 0
    started = time.monotonic()

    def schema_for(batch_ids: list[str]) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "assessments": {
                    "type": "array", "minItems": len(batch_ids), "maxItems": len(batch_ids),
                    "items": {
                        "type": "object",
                        "properties": {
                            "action_id": {"type": "string", "enum": batch_ids},
                            "severity_estimate": {"type": "string", "enum": list(engine_module.LLM_SEVERITY_BANDS)},
                            "confidence": {"type": "string", "enum": list(engine_module.LLM_CONFIDENCE_BANDS)},
                            "rationale": {"type": "string", "minLength": 1, "maxLength": 70},
                        },
                        "required": ["action_id", "severity_estimate", "confidence", "rationale"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["assessments"],
            "additionalProperties": False,
        }

    def validate_batch(parsed: dict[str, Any], batch_ids: list[str]) -> dict[str, dict[str, Any]]:
        rows = parsed.get("assessments")
        if not isinstance(rows, list):
            raise ValueError("Response did not contain an assessments list")
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Assessment entry was not an object")
            action_id = row.get("action_id")
            if action_id not in batch_ids:
                raise ValueError(f"Unexpected action_id in batch: {action_id!r}")
            if action_id in result:
                raise ValueError(f"Duplicate action_id in batch: {action_id!r}")
            severity = row.get("severity_estimate")
            confidence = row.get("confidence")
            rationale = row.get("rationale")
            if severity not in engine_module.LLM_SEVERITY_BANDS:
                raise ValueError(f"Invalid severity estimate for {action_id!r}: {severity!r}")
            if confidence not in engine_module.LLM_CONFIDENCE_BANDS:
                raise ValueError(f"Invalid confidence for {action_id!r}: {confidence!r}")
            if not isinstance(rationale, str) or not rationale.strip() or len(rationale.strip()) > 70:
                raise ValueError(f"Invalid rationale for {action_id!r}; expected 1-70 characters")
            result[action_id] = {
                "action_id": action_id,
                "severity_estimate": severity,
                "confidence": confidence,
                "rationale": " ".join(rationale.split()),
            }
        missing = [action_id for action_id in batch_ids if action_id not in result]
        if missing:
            raise ValueError("Missing batch assessments: " + ", ".join(missing))
        return result

    def assess_batch(batch: list[dict[str, str]], depth: int = 0) -> None:
        nonlocal call_counter
        batch_ids = [item["action_id"] for item in batch]
        prompt_context = {
            "task": "independent_qualitative_severity_assessment_batch",
            "severity_scale": {
                "informational": "No meaningful security consequence is plausible from the stated weakness.",
                "low": "Limited direct impact; mainly hardening or minor disclosure, often needing other weaknesses.",
                "medium": "Meaningful but bounded data exposure, unauthorized access, or abuse is plausible.",
                "high": "Serious data exposure, privilege escalation, or significant compromise is plausible.",
                "critical": "Broad/severe compromise is plausible, such as major system control or widespread sensitive data impact.",
            },
            "confidence_scale": {
                "low": "Key impact or precondition details are unknown.",
                "medium": "The scenario supports the estimate but important conditions remain unknown.",
                "high": "The described impact is strongly supported by the stated assumptions.",
            },
            "targets": batch,
            "rules": [
                "Estimate severity IF the hypothesized weakness is confirmed in a production analogue.",
                "Do not lower the severity merely because the local lab uses a synthetic marker; reflect that uncertainty in confidence.",
                "Do not assume worst-case impact unless the scenario supports it; state key caveats briefly.",
                "Keep potential impact severity separate from confidence that the scenario is exploitable.",
                "Assess only the supplied IDs; return each exactly once.",
                "No CVSS metrics, vectors, or numeric scores.",
                "Rationale at most 70 characters; output only schema-conforming JSON.",
            ],
        }
        system_prompt = (
            "Estimate the plausible technical impact of each weakness IF a real analogue is confirmed. "
            "The synthetic marker is not proof; use confidence to express uncertainty about conditions, not to erase conditional impact. "
            "Use the defined severity scale consistently. Output schema-conforming JSON only.\n\n"
        )
        prompt_text = system_prompt + json.dumps(prompt_context, ensure_ascii=False, separators=(",", ":"))
        final_error: Exception | None = None
        for attempt in range(1, retries + 2):
            call_counter += 1
            record: dict[str, Any] = {
                "record_type": "assessment_batch_attempt",
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "batch_call_index": call_counter,
                "batch_depth": depth,
                "batch_size": len(batch),
                "attempt": attempt,
                "requested_action_ids": batch_ids,
                "model": model,
                "prompt_text_sent": prompt_text,
                "prompt_context": prompt_context,
                "prompt_characters": len(prompt_text),
                "prompt_estimated_tokens": max(1, (len(prompt_text) + 3) // 4),
                "request_made": True,
            }
            try:
                parsed, raw, metrics, elapsed = asyncio.run(_ollama_generate_stream_json(
                    prompt_text,
                    model=model,
                    ollama_url=ollama_url,
                    timeout_seconds=timeout_seconds,
                    num_predict=220 if len(batch) >= 3 else 140,
                    response_format=schema_for(batch_ids),
                ))
                record.update({
                    "raw_model_response": raw,
                    "parsed_model_response": parsed,
                    "ollama_metrics": metrics,
                    "elapsed_seconds": round(elapsed, 3),
                })
                accepted = validate_batch(parsed, batch_ids)
                record["accepted_action_ids"] = list(accepted)
                record["validated"] = True
                all_interactions.append(record)
                assessments_by_id.update(accepted)
                return
            except Exception as exc:
                final_error = exc
                raw_partial = getattr(exc, "raw_model_response", None)
                exception_metrics = getattr(exc, "ollama_metrics", None)
                record.update({
                    "error": f"{type(exc).__name__}: {exc}",
                    "raw_model_response": raw_partial if raw_partial is not None else record.get("raw_model_response"),
                    "ollama_metrics": exception_metrics if exception_metrics is not None else record.get("ollama_metrics"),
                    "elapsed_seconds": getattr(exc, "elapsed_seconds", record.get("elapsed_seconds")),
                    "validated": False,
                })
                all_interactions.append(record)
                # Network and timeout errors are not improved by making the prompt
                # smaller; fail promptly instead of multiplying a long timeout.
                if isinstance(exc, httpx.HTTPError) or (
                    isinstance(exc, ValueError) and str(exc).startswith("Ollama generation error:")
                ):
                    raise
                # Retry malformed/truncated/invalid structured output once, if configured.
                if attempt <= retries:
                    continue
                break

        # If the model repeatedly truncates or omits entries, split only the failed
        # output batch and reassess those items. Never guess missing severity values.
        if len(batch) > 1 and isinstance(final_error, (json.JSONDecodeError, ValueError, TypeError, KeyError)):
            midpoint = len(batch) // 2
            assess_batch(batch[:midpoint], depth + 1)
            assess_batch(batch[midpoint:], depth + 1)
            return
        raise ValueError(
            f"Risk profile batch failed for {batch_ids!r} after {retries + 1} attempt(s): "
            f"{type(final_error).__name__}: {final_error}"
        ) from final_error

    try:
        for offset in range(0, len(targets), batch_size):
            assess_batch(targets[offset:offset + batch_size])

        # Do not ask the small model for a second, supposedly exact global order.
        # The previous pass contradicted the model's own severity bands and could
        # leak that contradiction into every action-selection prompt. The profile
        # is now ordered by qualitative band only; same-band findings are ties.
        profile = engine_module.build_llm_risk_profile(
            {"assessments": [assessments_by_id[action_id] for action_id in target_ids]},
            model,
        )
        ranking_source = "llm_severity_band_groups"
        profile["ranking_source"] = ranking_source
        profile["ranking_call_validated"] = None  # no standalone ordinal ranking call is made
        profile["ranking_error"] = None
        elapsed_total = time.monotonic() - started
        retry_count = sum(1 for record in all_interactions if int(record.get("attempt", 1)) > 1)
        split_batch_attempt_count = sum(
            1 for record in all_interactions
            if record.get("record_type") == "assessment_batch_attempt" and int(record.get("batch_depth", 0)) > 0
        )
        profile.update({
            "generation_elapsed_seconds": round(elapsed_total, 3),
            "generation_method": "Ollama qualitative estimates in validated small batches with local validation and split-on-truncation; no separate global rank pass",
            "generation_llm_calls": sum(1 for record in all_interactions if record.get("request_made")),
            "generation_batch_size": batch_size,
            "generation_batch_count": sum(1 for record in all_interactions if record.get("record_type") == "assessment_batch_attempt" and record.get("validated")),
            "generation_retry_count": retry_count,
            "generation_split_batch_attempt_count": split_batch_attempt_count,
            "ranking_source": ranking_source,
            "ranking_call_validated": None,
            "ranking_error": None,
        })
        summary_trace = {
            "record_type": "generation_summary",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "model": model,
            "task": "independent_qualitative_severity_band_assessment",
            "target_action_ids": target_ids,
            "batch_size_configured": batch_size,
            "targets_assessed": len(assessments_by_id),
            "generation_llm_calls": profile["generation_llm_calls"],
            "generation_retry_count": retry_count,
            "generation_split_batch_attempt_count": split_batch_attempt_count,
            "generation_elapsed_seconds": round(elapsed_total, 3),
            "ranking_source": ranking_source,
            "ranking_note": "Bands are ordered; items within a band are tied. No global ordinal ranking call was made.",
            "error": None,
        }
        trace = {"summary": summary_trace, "interactions": all_interactions}
        return profile, trace, round(elapsed_total, 3)
    except Exception as exc:
        elapsed_total = time.monotonic() - started
        summary_trace = {
            "record_type": "generation_summary",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "model": model,
            "task": "independent_qualitative_severity_band_assessment",
            "target_action_ids": target_ids,
            "batch_size_configured": batch_size,
            "targets_assessed": len(assessments_by_id),
            "generation_elapsed_seconds": round(elapsed_total, 3),
            "error": f"{type(exc).__name__}: {exc}",
        }
        trace = {"summary": summary_trace, "interactions": all_interactions}
        raise LLMRiskProfileGenerationError(
            f"Qualitative risk-profile generation/validation failed: {type(exc).__name__}: {exc}", trace
        ) from exc


def _write_llm_risk_interaction_trace(path: Path, trace: dict[str, Any]) -> None:
    """Write true JSONL: one summary record followed by every model attempt."""
    records: list[dict[str, Any]] = []
    summary = trace.get("summary")
    if isinstance(summary, dict):
        records.append(summary)
    interactions = trace.get("interactions")
    if isinstance(interactions, list):
        records.extend(item for item in interactions if isinstance(item, dict))
    if not records:
        records = [trace]
    path.write_text(
        "".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in records),
        encoding="utf-8",
    )

def check_ollama(
    force_refresh: bool | None = None,
    collect_llm_cvss_proposals: bool = False,
    force_refresh_risk_profile: bool = False,
    collect_llm_risk_profile: bool = False,
    use_cached_llm_risk_profile: bool = False,
) -> tuple[bool, str, str | None]:
    """Check Ollama and prepare the deterministic CVSS audit baseline.

    The expensive qualitative risk profile is optional. The normal experiment
    uses compact authored impact context plus live evidence; a profile is loaded
    or generated only when explicitly requested or an explicit profile path is set.
    """
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime('%Y%m%d_%H%M%S')
    readiness_path = RESULTS / f"ollama_preflight_{stamp}.json"
    proposed_cvss_path = RESULTS / f"cvss_profile_{stamp}.json"
    proposed_cvss_trace_path = RESULTS / f"cvss_profile_interactions_{stamp}.jsonl"
    proposed_risk_path = RESULTS / f"llm_risk_profile_{stamp}.json"
    proposed_risk_trace_path = RESULTS / f"llm_risk_profile_interactions_{stamp}.jsonl"
    cvss_path: Path | None = None
    risk_path: Path | None = None
    cvss_profile: dict[str, Any] | None = None
    risk_profile: dict[str, Any] | None = None
    cvss_interactions: list[dict[str, Any]] = []
    risk_trace: dict[str, Any] | None = None
    cvss_generation_seconds = 0.0
    risk_generation_seconds = 0.0
    profile_source = "scenario_reference"
    risk_profile_source = "qualitative_llm_generated"
    error_text: str | None = None
    refresh_cvss = force_refresh if force_refresh is not None else os.getenv("PENTELLIGENT_REFRESH_CVSS", "0").strip().lower() in {"1", "true", "yes", "on"}
    explicit_cvss_path = os.getenv("PENTELLIGENT_CVSS_PROFILE_FILE")
    explicit_risk_path = os.getenv("PENTELLIGENT_LLM_RISK_PROFILE_FILE")
    readiness_started = time.monotonic()

    try:
        tags = request_json(f"{OLLAMA_URL}/api/tags", timeout=5.0)
        models = [str(item.get("name", "")) for item in tags.get("models", []) if isinstance(item, dict)]
        if not any(name == OLLAMA_MODEL or name.startswith(OLLAMA_MODEL + ":") for name in models):
            raise RuntimeError(
                f"Ollama is reachable but configured model {OLLAMA_MODEL!r} was not listed. "
                f"Available: {', '.join(models) or '(none)'}"
            )
        timeout_value = float(os.getenv("OLLAMA_TIMEOUT", "270"))
        if not 5 <= timeout_value <= 600:
            raise ValueError("OLLAMA_TIMEOUT must be between 5 and 600 seconds.")
        try:
            num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "2048"))
        except ValueError as exc:
            raise ValueError("OLLAMA_NUM_CTX must be an integer from 1024 to 8192.") from exc
        if not 1024 <= num_ctx <= 8192:
            raise ValueError("OLLAMA_NUM_CTX must be between 1024 and 8192.")

        import pentelligent as engine_module
        engine_module.OLLAMA_URL = OLLAMA_URL
        engine_module.OLLAMA_MODEL = OLLAMA_MODEL
        engine_module.OLLAMA_TIMEOUT = timeout_value
        cache_note = None

        # CVSS remains a deterministic comparison baseline. Its reference vectors
        # come from an explicit rubric and are scored locally, never by the LLM.
        if not refresh_cvss:
            cvss_profile, cached_cvss_path, profile_source = _load_compatible_cached_profile(
                engine_module, OLLAMA_MODEL, RESULTS, explicit_cvss_path or None
            )
            if cvss_profile is not None and cached_cvss_path is not None:
                cvss_path = cached_cvss_path
            elif explicit_cvss_path:
                raise ValueError("Explicit PENTELLIGENT_CVSS_PROFILE_FILE was not loadable")
            else:
                cache_note = profile_source
                profile_source = "scenario_reference"
        else:
            profile_source = "scenario_reference_refresh"

        proposal_count = int(((cvss_profile or {}).get("model_proposal_summary") or {}).get("collected_count", 0))
        collect_new_cvss_proposals = collect_llm_cvss_proposals and (
            cvss_profile is None or refresh_cvss or proposal_count < len(engine_module._cvss_action_ids())
        )
        if cvss_profile is None or refresh_cvss:
            if collect_new_cvss_proposals:
                cvss_profile, cvss_interactions, cvss_generation_seconds = generate_cvss_profile_batched(
                    engine_module, ollama_url=OLLAMA_URL, model=OLLAMA_MODEL, timeout_seconds=timeout_value,
                )
                profile_source = "scenario_reference_with_llm_proposals"
                cvss_profile["model_proposal_collection_elapsed_seconds"] = round(cvss_generation_seconds, 3)
                cvss_profile["model_proposal_collection_llm_calls"] = len(cvss_interactions)
            else:
                cvss_profile = engine_module.build_cvss_reference_profile(OLLAMA_MODEL)
                profile_source = "scenario_reference"
                cvss_generation_seconds = 0.0
                cvss_profile["profile_generation_elapsed_seconds"] = 0.0
                cvss_profile["profile_generation_method"] = "local scenario-reference rubric; no LLM vector calls"
                cvss_profile["profile_generation_llm_calls"] = 0
                cvss_profile["profile_generation_batch_size"] = None
                cvss_profile["profile_generation_fallback_count"] = 0
            cvss_path = proposed_cvss_path
        elif collect_new_cvss_proposals:
            cvss_profile, cvss_interactions, cvss_generation_seconds = generate_cvss_profile_batched(
                engine_module, ollama_url=OLLAMA_URL, model=OLLAMA_MODEL, timeout_seconds=timeout_value,
            )
            profile_source = "scenario_reference_with_llm_proposals"
            cvss_path = proposed_cvss_path
            cvss_profile["model_proposal_collection_elapsed_seconds"] = round(cvss_generation_seconds, 3)
            cvss_profile["model_proposal_collection_llm_calls"] = len(cvss_interactions)

        assert cvss_profile is not None and cvss_path is not None
        cvss_profile["profile_file"] = str(cvss_path)
        cvss_profile["catalog_fingerprint"] = engine_module._cvss_catalog_fingerprint()
        if cvss_interactions:
            cvss_profile["model_proposal_interactions_file"] = str(proposed_cvss_trace_path)
            proposed_cvss_trace_path.write_text(
                "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in cvss_interactions),
                encoding="utf-8",
            )
        elif not cvss_profile.get("model_proposal_interactions_file"):
            cvss_profile["model_proposal_interactions_file"] = None
        if profile_source not in {"cache", "explicit"} or cvss_profile.get("profile_migrated_from_legacy"):
            cvss_path.write_text(json.dumps(cvss_profile, ensure_ascii=False, indent=2), encoding="utf-8")
        elif cvss_profile.get("schema_version") != 2:
            cvss_path.write_text(json.dumps(cvss_profile, ensure_ascii=False, indent=2), encoding="utf-8")

        # The static qualitative profile is an optional research artifact, not a
        # required normal-run precondition. The live planner always receives concise
        # authored impact caveats and current response evidence. Use this profile
        # only when the user opts in to profile collection/cache reuse, or supplies
        # an explicit profile path.
        if force_refresh_risk_profile and explicit_risk_path:
            raise ValueError("Cannot use --refresh-llm-risk-profile with explicit PENTELLIGENT_LLM_RISK_PROFILE_FILE")
        risk_requested = bool(
            explicit_risk_path or collect_llm_risk_profile or use_cached_llm_risk_profile
            or force_refresh_risk_profile
        )
        if explicit_risk_path:
            risk_profile, risk_path, risk_profile_source = _load_compatible_llm_risk_profile(
                engine_module, OLLAMA_MODEL, RESULTS, explicit_risk_path
            )
            if risk_profile is None or risk_path is None:
                raise ValueError("Explicit PENTELLIGENT_LLM_RISK_PROFILE_FILE was not loadable")
        elif risk_requested:
            if not force_refresh_risk_profile:
                risk_profile, cached_risk_path, risk_profile_source = _load_compatible_llm_risk_profile(
                    engine_module, OLLAMA_MODEL, RESULTS, None
                )
                if risk_profile is not None and cached_risk_path is not None:
                    risk_path = cached_risk_path
            if (risk_profile is None and use_cached_llm_risk_profile
                    and not collect_llm_risk_profile and not force_refresh_risk_profile):
                raise FileNotFoundError(
                    "--use-cached-llm-risk-profile was requested, but no compatible cached profile exists. "
                    "Run once with --collect-llm-risk-profile to generate it, or omit the optional profile."
                )
            if risk_profile is None:
                risk_profile, risk_trace, risk_generation_seconds = generate_llm_risk_profile(
                    engine_module, ollama_url=OLLAMA_URL, model=OLLAMA_MODEL, timeout_seconds=timeout_value,
                )
                risk_profile_source = "qualitative_llm_generated"
                risk_path = proposed_risk_path
                risk_profile["profile_file"] = str(risk_path)
                risk_profile["generation_interactions_file"] = str(proposed_risk_trace_path)
                risk_trace["summary"]["elapsed_seconds_total"] = round(risk_generation_seconds, 3)
                _write_llm_risk_interaction_trace(proposed_risk_trace_path, risk_trace)
                risk_profile["generation_trace_file"] = str(proposed_risk_trace_path)
                risk_path.write_text(json.dumps(risk_profile, ensure_ascii=False, indent=2), encoding="utf-8")
            else:
                risk_generation_seconds = 0.0
                risk_profile["profile_file"] = str(risk_path)
        else:
            risk_profile_source = "disabled_optional"
            risk_profile = None
            risk_path = None
            risk_generation_seconds = 0.0

        if risk_profile is not None and risk_path is not None:
            os.environ["PENTELLIGENT_LLM_RISK_PROFILE_FILE"] = str(risk_path)
        else:
            os.environ.pop("PENTELLIGENT_LLM_RISK_PROFILE_FILE", None)
        os.environ["PENTELLIGENT_CVSS_PROFILE_GENERATION_THIS_RUN_SECONDS"] = str(round(cvss_generation_seconds, 3))
        os.environ["PENTELLIGENT_CVSS_PROFILE_REUSED"] = "1" if profile_source in {"cache", "explicit"} else "0"
        os.environ["PENTELLIGENT_ACTION_SELECTION_PREFLIGHT_SECONDS"] = "0"
        os.environ["PENTELLIGENT_LLM_RISK_PROFILE_GENERATION_SECONDS"] = str(round(risk_generation_seconds, 3))
        os.environ["PENTELLIGENT_LLM_RISK_PROFILE_REUSED"] = "1" if risk_profile_source in {"cache", "explicit"} else "0"

        audit_summary = cvss_profile.get("model_proposal_summary", {})
        ready_record = {
            "passed": True,
            "model": OLLAMA_MODEL,
            "ollama_url": OLLAMA_URL,
            "model_was_listed_by_ollama_tags": True,
            "selection_preflight_performed": False,
            "note": "No throwaway action-selection request is made. The first real adaptive decision is the selection protocol test.",
            "cvss_profile_source": profile_source,
            "cvss_profile_path": str(cvss_path),
            "cvss_profile_count": len(cvss_profile.get("assessments", {})),
            "cvss_assessment_count": len(cvss_profile.get("assessments", {})),
            "cvss_profile_llm_calls_this_run": len(cvss_interactions),
            "profile_reused_from_cache": profile_source in {"cache", "explicit"},
            "profile_generation_elapsed_this_run_seconds": round(cvss_generation_seconds, 3),
            "cvss_profile_generation_elapsed_this_run_seconds": round(cvss_generation_seconds, 3),
            "risk_profile_enabled": risk_profile is not None,
            "risk_profile_source": risk_profile_source,
            "risk_profile_path": str(risk_path) if risk_path else None,
            "risk_profile_count": len(risk_profile.get("assessments", {})) if risk_profile else 0,
            "risk_profile_generation_elapsed_this_run_seconds": round(risk_generation_seconds, 3),
            "risk_profile_generation_trace": str(proposed_risk_trace_path) if risk_trace else (risk_profile.get("generation_trace_file") if risk_profile else None),
            "model_proposal_summary": audit_summary,
            "cache_validation_note": cache_note,
            "total_readiness_elapsed_seconds": round(time.monotonic() - readiness_started, 3),
        }
        readiness_path.write_text(json.dumps(ready_record, ensure_ascii=False, indent=2), encoding="utf-8")

        cvss_summary = (
            f"loaded {len(cvss_profile['assessments'])}-item scenario-reference CVSS baseline from {profile_source}"
        )
        if risk_profile is not None and risk_path is not None:
            risk_summary = (
                f"{risk_profile_source} qualitative profile with {len(risk_profile['assessments'])} findings "
                f"({risk_generation_seconds:.1f}s this run)"
            )
            risk_location_summary = f"Risk profile: {risk_path}; "
        else:
            risk_summary = "optional static qualitative profile disabled; live selector will use authored impact context and observed evidence"
            risk_location_summary = ""
        return True, (
            f"Ollama READY for {OLLAMA_MODEL!r} (model listed; no dummy action-selection call). "
            f"{cvss_summary}; {risk_summary}. CVSS scores are withheld from the adaptive selector and used as a separate comparison baseline. "
            f"{risk_location_summary}Readiness record: {readiness_path}."
        ), str(cvss_path)

    except Exception as exc:
        error_text = f"{type(exc).__name__}: {exc}"
        preserved_risk_trace = getattr(exc, "risk_trace", None)
        if isinstance(preserved_risk_trace, dict):
            risk_trace = preserved_risk_trace
            try:
                _write_llm_risk_interaction_trace(proposed_risk_trace_path, risk_trace)
            except OSError:
                pass
        preserved_interactions = getattr(exc, "interactions", None)
        if isinstance(preserved_interactions, list):
            cvss_interactions = preserved_interactions
            try:
                proposed_cvss_trace_path.write_text(
                    "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in cvss_interactions),
                    encoding="utf-8",
                )
            except OSError:
                pass
        try:
            failure_record = {
                "passed": False,
                "model": OLLAMA_MODEL,
                "ollama_url": OLLAMA_URL,
                "error": error_text,
                "cvss_profile_source": profile_source,
                "cvss_profile_path": str(cvss_path) if cvss_path else None,
                "cvss_profile_generation_elapsed_this_run_seconds": round(cvss_generation_seconds, 3),
                "cvss_assessment_count": len((cvss_profile or {}).get("assessments", {})),
                "cvss_profile_llm_calls_this_run": len(cvss_interactions),
                "scoring_interactions": cvss_interactions,
                "risk_profile_enabled": risk_profile is not None,
                "risk_profile_source": risk_profile_source,
                "risk_profile_path": str(risk_path) if risk_path else None,
                "risk_profile_generation_elapsed_this_run_seconds": round(risk_generation_seconds, 3),
                "risk_generation_trace": risk_trace,
                "selection_preflight_performed": False,
                "total_readiness_elapsed_seconds": round(time.monotonic() - readiness_started, 3),
            }
            readiness_path.write_text(json.dumps(failure_record, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass
        return False, f"Ollama/risk-profile readiness failed: {error_text}. Trace: {readiness_path}", None

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-fallback", action="store_true",
        help="Run for diagnostics even if Ollama/model is unavailable; resulting data is not proof of LLM-driven adaptivity.",
    )
    parser.add_argument(
        "--single-scenario", action="store_true",
        help="Compatibility option: run only the configured scenario pair (this is now the default).",
    )
    parser.add_argument(
        "--all-scenarios", action="store_true",
        help="Run the configured scenario plus the other supported scenarios; this can take considerably longer with a local LLM.",
    )
    parser.add_argument(
        "--refresh-cvss", action="store_true",
        help="Rebuild the local scenario-reference CVSS profile instead of reusing a cached profile; no LLM vector calls are made.",
    )
    parser.add_argument(
        "--collect-llm-cvss-proposals", action="store_true",
        help="Optional research audit: ask Ollama for CVSS vectors separately (can be very slow); never used for authoritative scores or adaptive selection.",
    )
    parser.add_argument(
        "--collect-llm-risk-profile", action="store_true",
        help="Optional research run: generate or reuse the separate qualitative severity profile. Disabled in normal runs to save startup time.",
    )
    parser.add_argument(
        "--use-cached-llm-risk-profile", action="store_true",
        help="Optional: load a compatible cached qualitative profile without generating one if absent.",
    )
    parser.add_argument(
        "--refresh-llm-risk-profile", action="store_true",
        help="Optional research run: regenerate the separate qualitative severity profile instead of reusing its validated cache.",
    )
    return parser.parse_args()


def main() -> int:
    program_started = time.monotonic()
    args = parse_args()
    if HOST not in {"127.0.0.1", "localhost"}:
        print("ERROR: PENTELLIGENT_RUN_HOST must be 127.0.0.1 or localhost.", file=sys.stderr)
        return 2
    if not 1 <= PORT <= 65535:
        print("ERROR: PENTELLIGENT_RUN_PORT must be an integer between 1 and 65535.", file=sys.stderr)
        return 2
    if not 1 <= BUDGET <= 100:
        print("ERROR: PENTELLIGENT_ACTION_BUDGET must be an integer between 1 and 100.", file=sys.stderr)
        return 2
    if SCENARIO not in {"default", "single_user_context", "unavailable_user_context"}:
        print("ERROR: PENTELLIGENT_SCENARIO must be default, single_user_context, or unavailable_user_context.", file=sys.stderr)
        return 2
    if not OLLAMA_MODEL.strip():
        print("ERROR: OLLAMA_MODEL cannot be empty.", file=sys.stderr)
        return 2
    try:
        plan_horizon = int(os.getenv("PENTELLIGENT_PLAN_HORIZON", "3"))
    except ValueError:
        print("ERROR: PENTELLIGENT_PLAN_HORIZON must be an integer from 1 to 3.", file=sys.stderr)
        return 2
    if not 1 <= plan_horizon <= 3:
        print("ERROR: PENTELLIGENT_PLAN_HORIZON must be between 1 and 3.", file=sys.stderr)
        return 2

    RESULTS.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PENTELLIGENT_API_BASE"] = BASE_URL
    env["PENTELLIGENT_RESULTS"] = str(RESULTS)
    env["OLLAMA_URL"] = OLLAMA_URL
    env["OLLAMA_MODEL"] = OLLAMA_MODEL
    env.setdefault("OLLAMA_TIMEOUT", "270")
    # Strict by default: never silently turn an LLM error into a fallback action.
    # --allow-fallback is only for diagnostic runs.
    env["PENTELLIGENT_ALLOW_FALLBACK"] = "1" if args.allow_fallback else "0"
    # Historical model-vector proposals in a reused CVSS cache are hidden from
    # ordinary experiment output. Show them only when the separate audit was requested.
    env["PENTELLIGENT_SHOW_LLM_CVSS_AUDIT"] = "1" if args.collect_llm_cvss_proposals else "0"

    print("=" * 106)
    print("PENTELLIGENT — FIXED VS ADAPTIVE EXPERIMENT")
    print(f"Target: {BASE_URL} (bundled local synthetic API)")
    print(f"Scenario: {SCENARIO} | action budget per mode: {BUDGET}")
    print(f"Planner: LLM proposes up to {os.getenv('PENTELLIGENT_PLAN_HORIZON', '3')} ordered intents; local validator/dependency planner controls execution. Replan on material evidence changes. CVSS is audit-only; static risk profile is optional.")
    print(f"Results directory: {RESULTS}")
    print("=" * 106)
    if args.refresh_cvss:
        os.environ["PENTELLIGENT_REFRESH_CVSS"] = "1"
    else:
        os.environ.pop("PENTELLIGENT_REFRESH_CVSS", None)
    os.environ["PENTELLIGENT_CVSS_PROFILE_GENERATION_THIS_RUN_SECONDS"] = "0"
    os.environ["PENTELLIGENT_CVSS_PROFILE_REUSED"] = "0"
    os.environ["PENTELLIGENT_ACTION_SELECTION_PREFLIGHT_SECONDS"] = "0"
    ollama_ok, ollama_message, cvss_profile_path = check_ollama(
        force_refresh=args.refresh_cvss,
        collect_llm_cvss_proposals=args.collect_llm_cvss_proposals,
        force_refresh_risk_profile=args.refresh_llm_risk_profile,
        collect_llm_risk_profile=args.collect_llm_risk_profile,
        use_cached_llm_risk_profile=args.use_cached_llm_risk_profile,
    )
    print(ollama_message)
    if not ollama_ok and not args.allow_fallback:
        print("\nABORTED BEFORE EXPERIMENT: fix OLLAMA_URL / OLLAMA_MODEL, or rerun with --allow-fallback for diagnostics.", file=sys.stderr)
        return 2
    if not ollama_ok:
        print("WARNING: --allow-fallback is enabled. Adaptive results may use the fallback selector.")
    if cvss_profile_path:
        env["PENTELLIGENT_CVSS_PROFILE_FILE"] = cvss_profile_path
    else:
        env.pop("PENTELLIGENT_CVSS_PROFILE_FILE", None)
    risk_profile_path = os.getenv("PENTELLIGENT_LLM_RISK_PROFILE_FILE")
    if risk_profile_path:
        env["PENTELLIGENT_LLM_RISK_PROFILE_FILE"] = risk_profile_path
    else:
        env.pop("PENTELLIGENT_LLM_RISK_PROFILE_FILE", None)
    env["PENTELLIGENT_LLM_RISK_PROFILE_GENERATION_SECONDS"] = os.getenv(
        "PENTELLIGENT_LLM_RISK_PROFILE_GENERATION_SECONDS", "0"
    )
    env["PENTELLIGENT_LLM_RISK_PROFILE_REUSED"] = os.getenv(
        "PENTELLIGENT_LLM_RISK_PROFILE_REUSED", "0"
    )

    log_path = RESULTS / "synthetic_api_server.log"
    log_handle = log_path.open("a", encoding="utf-8")
    proc: subprocess.Popen[bytes] | None = None
    reports: list[dict[str, Any]] = []
    result_code = 0
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "pentelligent:app",
             "--host", HOST, "--port", str(PORT), "--log-level", "warning"],
            cwd=str(HERE), env=env, stdout=log_handle, stderr=subprocess.STDOUT,
        )
        wait_for_health(proc)
        print("\nLocal synthetic API: READY (health payload and service identity verified)")

        scenarios = [SCENARIO]
        if args.all_scenarios:
            scenarios.extend(
                scenario for scenario in ("default", "single_user_context", "unavailable_user_context")
                if scenario != SCENARIO
            )
        runs_by_scenario: dict[str, dict[str, dict[str, Any]]] = {}
        # A full adaptive run may use one generation per genuine choice. Bound the
        # HTTP wait to a generous but finite budget rather than multiplying by an
        # unnecessarily large action cap (the catalogue has a finite size).
        timeout = max(300.0, float(os.getenv("OLLAMA_TIMEOUT", "90")) * min(BUDGET, 22) + 60.0)

        for scenario in scenarios:
            runs_by_scenario[scenario] = {}
            for mode in ("fixed", "adaptive"):
                print(f"\nRunning {mode} experiment | scenario={scenario}...")
                url = f"{BASE_URL}/benchmark/{mode}?scenario={quote(scenario)}&max_actions={BUDGET}"
                report = request_json(url, method="POST", timeout=timeout)
                reports.append(report)
                runs_by_scenario[scenario][mode] = report
                print_report(report)

        print("\n" + "=" * 106)
        print("FIXED VS ADAPTIVE COMPARISON (MATCHED INITIAL STATE)")
        line()
        comparison_metrics = [
            ("Actions executed", "test_actions"),
            ("HTTP requests started", "http_requests"),
            ("HTTP responses received", "completed_http_responses"),
            ("Engine wall-clock incl. LLM (s)", "testing_time_seconds"),
            ("LLM request wall time (s)", "llm_request_wall_time_seconds"),
            ("Target findings detected", "target_findings_detected"),
            ("Target coverage (%)", "target_finding_coverage_percent"),
            ("Selection event action/role validity (%)", "selected_action_role_validity_percent"),
            ("Ollama selections", "ollama_selection_count"),
            ("LLM intent decisions (%)", "llm_intent_decision_share_percent"),
            ("LLM plan calls", "llm_plan_calls"),
            ("Mean proposed plan length", "llm_mean_proposed_plan_length"),
            ("Queued plan intents attempted", "llm_plan_followup_intents_attempted"),
            ("Queued plan intents completed", "llm_plan_followup_intents_completed"),
            ("Queued plan items discarded", "llm_plan_items_discarded"),
            ("Plan items removed by local policy", "llm_plan_items_removed_by_local_policy"),
            ("Anticipated resource prerequisites preserved", "llm_anticipated_resource_prerequisites_preserved"),
            ("Replan triggers / plan-end events", "llm_plan_replan_count"),
            ("Mean candidates per LLM request", "mean_candidates_considered_per_llm_request"),
            ("Reference-critical categories detected", "reference_critical_scenario_categories_detected"),
            ("Mean request position for reference-critical findings", "mean_reference_critical_detection_request_position"),
            ("Reference-critical coverage after 5 requests (%)", "reference_critical_coverage_after_5_requests_percent"),
            ("Reference-critical coverage after 10 requests (%)", "reference_critical_coverage_after_10_requests_percent"),
            ("LLM selections below top reference CVSS (audit only)", "llm_lower_score_probe_selections"),
            ("CVSS hard-gate overrides", "cvss_priority_guard_selection_count"),
            ("CVSS estimates available", "cvss_assessment_count"),
            ("Progress-guard overrides", "progress_guard_selection_count"),
            ("Fallback selections", "fallback_selection_count"),
            ("LLM errors", "llm_error_count"),
            ("Recovered truncated LLM outputs", "llm_response_recovery_count"),
        ]
        for scenario in scenarios:
            print(f"\nScenario: {scenario}")
            fixed_report = runs_by_scenario[scenario]["fixed"]
            adaptive_report = runs_by_scenario[scenario]["adaptive"]
            fixed = fixed_report.get("metrics", {})
            adaptive = adaptive_report.get("metrics", {})
            table(["Metric", "Fixed", "Adaptive", "Adaptive − Fixed"], [
                [label, fixed.get(key), adaptive.get(key),
                 _round_metric(float(adaptive.get(key) or 0) - float(fixed.get(key) or 0), 3)]
                for label, key in comparison_metrics
            ])

        cvss_profile_generation_seconds = float(os.getenv("PENTELLIGENT_CVSS_PROFILE_GENERATION_THIS_RUN_SECONDS", "0") or 0)
        risk_profile_generation_seconds = float(os.getenv("PENTELLIGENT_LLM_RISK_PROFILE_GENERATION_SECONDS", "0") or 0)
        cvss_profile_was_reused = os.getenv("PENTELLIGENT_CVSS_PROFILE_REUSED", "0") == "1"
        risk_profile_was_reused = os.getenv("PENTELLIGENT_LLM_RISK_PROFILE_REUSED", "0") == "1"
        risk_profile_path = os.getenv("PENTELLIGENT_LLM_RISK_PROFILE_FILE")
        if not risk_profile_path:
            print("\nLLM qualitative severity profile: disabled for normal run; live planner uses authored impact context and current evidence.")
        elif risk_profile_was_reused:
            print(
                f"\nLLM qualitative severity profile: reused validated cache ({risk_profile_path}); "
                "no profile-generation call this run."
            )
        else:
            print(
                f"\nLLM qualitative severity profile: generated once in {risk_profile_generation_seconds:.3f}s "
                f"and saved to {risk_profile_path}; subsequent opt-in runs can reuse it."
            )
        print(
            "CVSS scenario-reference baseline: locally calculated and used for post-run comparison only; "
            "CVSS numbers/vectors are not included in the LLM's action-selection prompt."
        )

        primary_adaptive = runs_by_scenario[SCENARIO]["adaptive"]
        primary_sequence = primary_adaptive.get("action_sequence", [])
        primary_findings = primary_adaptive.get("final_observations", {}).get("confirmed_findings", [])
        scenario_variations = []
        for scenario in scenarios:
            if scenario == SCENARIO:
                continue
            other = runs_by_scenario[scenario]["adaptive"]
            other_sequence = other.get("action_sequence", [])
            other_findings = other.get("final_observations", {}).get("confirmed_findings", [])
            sequence_changed = primary_sequence != other_sequence
            findings_changed = primary_findings != other_findings
            scenario_variations.append({
                "primary_scenario": SCENARIO,
                "alternate_scenario": scenario,
                "primary_adaptive_run_id": primary_adaptive.get("run_id"),
                "alternate_adaptive_run_id": other.get("run_id"),
                "primary_action_sequence": primary_sequence,
                "alternate_action_sequence": other_sequence,
                "primary_confirmed_findings": primary_findings,
                "alternate_confirmed_findings": other_findings,
                "adaptive_action_sequence_changed": sequence_changed,
                "adaptive_findings_changed": findings_changed,
                "interpretation": (
                    "Adaptive action order changed between these scenario outcomes. Inspect decision traces to explain the change."
                    if sequence_changed else
                    "Adaptive action order did not change between these scenario outcomes. Do not claim outcome-driven reordering from this pair alone; the findings/stop conditions may still differ."
                ),
            })

        if scenario_variations:
            print("\n" + "=" * 106)
            print("ADAPTIVITY / SCENARIO-VARIATION CHECK")
            table(["Scenario vs primary", "Sequence changed?", "Findings changed?", "Coverage (primary → alternate)"], [
                [
                    item["alternate_scenario"],
                    item["adaptive_action_sequence_changed"],
                    item["adaptive_findings_changed"],
                    f"{primary_adaptive.get('metrics', {}).get('target_finding_coverage_percent')}% → "
                    f"{runs_by_scenario[item['alternate_scenario']]['adaptive'].get('metrics', {}).get('target_finding_coverage_percent')}%",
                ]
                for item in scenario_variations
            ])
            for item in scenario_variations:
                print(f"\n{item['primary_scenario']} adaptive sequence:")
                print("  " + " → ".join(item["primary_action_sequence"]))
                print(f"{item['alternate_scenario']} adaptive sequence:")
                print("  " + " → ".join(item["alternate_action_sequence"]))
                print("  " + item["interpretation"])

        runner_wall_clock_seconds = round(time.monotonic() - program_started, 3)
        print(
            f"\nEnd-to-end runner wall-clock: {runner_wall_clock_seconds:.3f}s "
            "(includes readiness checks, any uncached qualitative risk-profile generation, Fixed, Adaptive and reporting; compare separately from per-engine timers)."
        )
        comparison_path = RESULTS / "comparison_latest.json"
        comparison = {
            "configured_primary_scenario": SCENARIO,
            "scenarios_run": scenarios,
            "action_budget_per_mode_and_scenario": BUDGET,
            "runs": [
                {
                    "scenario": scenario,
                    "mode": mode,
                    "run_id": report.get("run_id"),
                    "report_path": report.get("saved_files", {}).get("report"),
                    "metrics": report.get("metrics", {}),
                }
                for scenario in scenarios
                for mode, report in runs_by_scenario[scenario].items()
            ],
            "adaptive_scenario_variations": scenario_variations,
            "llm_endpoint_check": {"passed": ollama_ok, "message": ollama_message},
            "cvss_profile_generation_elapsed_seconds": cvss_profile_generation_seconds,
            "llm_risk_profile_generation_elapsed_seconds": risk_profile_generation_seconds,
            "llm_risk_profile_path": risk_profile_path,
            "runner_wall_clock_elapsed_seconds_through_experiment": runner_wall_clock_seconds,
            "cvss_profile_generation_timing_note": (
                "The reference CVSS profile is constructed locally; optional LLM vector proposals are audit-only. "
                "CVSS values are withheld from adaptive selection and used only as a post-run comparative baseline. "
                "A separate qualitative LLM severity profile is generated once per model/catalogue version and cached. "
                "The throwaway action-selection preflight was removed; the first real adaptive choice validates selection in context."
            ),
            "interpretation_note": (
                "Findings come from the bundled synthetic API and use explicit lab markers. "
                "Only claim LLM-driven adaptivity when direct Ollama selections and decision traces support it. Report fallbacks, uncorrected LLM errors, and recovered truncated responses separately. "
                "A changed sequence across scenarios is direct evidence of outcome-sensitive ordering; an unchanged sequence is not."
            ),
        }
        comparison_path.write_text(json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nComparison saved: {comparison_path}")
        print(f"Server log: {log_path}")
        print(f"All reports/logs: {RESULTS}")

        if not args.allow_fallback:
            failed_llm_runs = [
                (scenario, report.get("mode"), report.get("metrics", {}))
                for scenario in scenarios
                for report in runs_by_scenario[scenario].values()
                if report.get("mode") == "adaptive" and (
                    report.get("metrics", {}).get("llm_error_count", 0)
                    or report.get("metrics", {}).get("fallback_selection_count", 0)
                    or report.get("metrics", {}).get("ollama_selection_count", 0) == 0
                )
            ]
            if failed_llm_runs:
                print("\nFAIL: at least one adaptive run had LLM errors, fallback selections, or no direct Ollama selections. Reports were saved, but those runs are not successful LLM-backed thesis evidence.", file=sys.stderr)
                result_code = 3
    except KeyboardInterrupt:
        print("\nInterrupted.")
        result_code = 130
    except Exception as exc:
        print(f"\nERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"Check the server log: {log_path}", file=sys.stderr)
        result_code = 1
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        log_handle.close()
    return result_code


if __name__ == "__main__":
    raise SystemExit(main())
