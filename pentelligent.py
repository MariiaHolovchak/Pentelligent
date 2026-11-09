
from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING, localcontext
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse
import ipaddress

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, RedirectResponse

try:
    from app.experiments.console_report import print_experiment_report
    from app.experiments.console_ui import show_banner, show_action, show_summary
except ImportError:  # Keep the engine usable when optional presentation helpers are absent.
    def show_banner(mode: str, scenario: str, budget: int) -> None:
        print(f"\nPentelligent | mode={mode} | scenario={scenario} | budget={budget}")

    def show_action(step: int, budget: int, action_id: str, status: str) -> None:
        print(f"[{step:02d}/{budget:02d}] {action_id:<24} {status}")

    def show_summary(metrics: dict[str, Any], mode: str, scenario: str) -> None:
        print(f"\nSummary: {mode=} {scenario=} actions={metrics.get('test_actions')} "
              f"requests={metrics.get('http_requests')} "
              f"findings={metrics.get('target_findings_detected')}/"
              f"{metrics.get('target_finding_count')}")

    def print_experiment_report(report: dict[str, Any]) -> None:
        print(json.dumps(report, ensure_ascii=False, indent=2))



def is_positive_integer(value: Any) -> bool:
    """True only for a positive Python int, never a bool or coercible string."""
    return type(value) is int and value > 0


# ============================================================
# CONFIGURATION
# ============================================================

API_BASE = os.getenv("PENTELLIGENT_API_BASE", "http://127.0.0.1:8000").rstrip("/")
ALLOWED_TARGET_HOSTS = {h.strip().lower() for h in os.getenv("PENTELLIGENT_ALLOWED_HOSTS", "127.0.0.1,localhost,::1").split(",") if h.strip()}
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "270"))
try:
    OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "2048"))
except ValueError:
    OLLAMA_NUM_CTX = 2048
if not 1024 <= OLLAMA_NUM_CTX <= 8192:
    OLLAMA_NUM_CTX = 2048
CVSS_VERSION = "3.1"
RESULTS_DIR = Path(os.getenv("PENTELLIGENT_RESULTS", "results"))

TARGET_FINDINGS = {
    "BOLA",
    "BROKEN_ADMIN_AUTH",
    "MASS_ASSIGNMENT",
    "SIMULATED_SQLI",
    "SECRET_DISCLOSURE",
    "SIMULATED_PATH_TRAVERSAL",
    "OPEN_REDIRECT",
    "CORS_MISCONFIGURATION",
    "MISSING_SECURITY_HEADERS",
    "EXCESSIVE_DATA_EXPOSURE",
    "VERBOSE_ERROR_DISCLOSURE",
    "EXPOSED_INTERNAL_DOCUMENTATION",
    "WEAK_PASSWORD_POLICY",
    "INSECURE_JWT_CONFIGURATION",
    "SIMULATED_SSRF",
    "MISSING_RATE_LIMITING",
    "SENSITIVE_CACHEABLE_RESPONSE",
}

# Every action is a pre-declared, local-lab-only operation. The LLM chooses an
# intended action from the catalogue; the engine schedules prerequisites and
# ActionValidator remains the hard execution gate.
ACTION_CATALOG: dict[str, dict[str, Any]] = {
    "health_check": {
        "description": "Verify that the API is responding and its health payload is valid.",
        "finding": None, "action_type": "prerequisite", "adaptive_candidate": True,
        "method": "GET", "path": "/health", "params": {}, "body": None, "requires": [],
    },
    "api_info_control": {
        "description": "Read the service identity and high-level API purpose for initial reconnaissance.",
        "finding": None, "action_type": "reconnaissance", "adaptive_candidate": True,
        "method": "GET", "path": "/", "params": {}, "body": None, "requires": ["health_check"],
    },
    "user_control": {
        "description": "Read the ordinary synthetic user and capture its valid resource ID for dependent operations.",
        "finding": None, "action_type": "prerequisite", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/users/1", "params": {}, "body": None, "requires": ["health_check"],
    },
    "users_list_control": {
        "description": "Enumerate synthetic user IDs and roles to understand available resources.",
        "finding": None, "action_type": "reconnaissance", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/users", "params": {"page": 1, "limit": 10}, "body": None, "requires": ["health_check"],
    },
    "pagination_control": {
        "description": "Check that ordinary user listing supports bounded pagination.",
        "finding": None, "action_type": "control", "adaptive_candidate": False,
        "method": "GET", "path": "/lab/users", "params": {"page": 2, "limit": 1}, "body": None, "requires": ["health_check"],
    },
    "search_control": {
        "description": "Run a benign search query as a baseline for the search endpoint.",
        "finding": None, "action_type": "control", "adaptive_candidate": False,
        "method": "GET", "path": "/lab/search", "params": {"q": "alice"}, "body": None, "requires": ["health_check"],
    },
    "files_control": {
        "description": "Read a permitted synthetic public file as a baseline for file handling.",
        "finding": None, "action_type": "control", "adaptive_candidate": False,
        "method": "GET", "path": "/lab/files", "params": {"path": "public/readme.txt"}, "body": None, "requires": ["health_check"],
    },
    "schema_control": {
        "description": "Retrieve the safe lab route schema to understand API operations before probing them.",
        "finding": None, "action_type": "reconnaissance", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/schema", "params": {}, "body": None, "requires": ["health_check"],
    },
    "catalog_control": {
        "description": "Read the ordinary synthetic product catalogue as a non-security control operation.",
        "finding": None, "action_type": "control", "adaptive_candidate": False,
        "method": "GET", "path": "/lab/catalog", "params": {}, "body": None, "requires": ["health_check"],
    },
    "valid_input_control": {
        "description": "Submit valid registration fields to establish baseline input-validation behavior.",
        "finding": None, "action_type": "control", "adaptive_candidate": False,
        "method": "POST", "path": "/lab/validate", "params": {},
        "body": {"email": "student@lab.invalid", "age": 24}, "requires": ["health_check"],
    },
    "bola_probe": {
        "description": "Check whether requester user 1 can read user 2's profile without object-level authorization.",
        "finding": "BOLA", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/users/2/profile", "params": {"requester_id": 1}, "body": None, "requires": ["health_check"],
    },
    "admin_access_probe": {
        "description": "Check whether an ordinary user role can read administrator metrics.",
        "finding": "BROKEN_ADMIN_AUTH", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/admin/metrics", "params": {"role": "user"}, "body": None, "requires": ["health_check"],
    },
    "mass_assignment_probe": {
        "description": "Check whether a profile update accepts the privileged role field; requires a discovered primary user ID.",
        "finding": "MASS_ASSIGNMENT", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "POST", "path": "/lab/users/{user_id}/profile", "resource_id_key": "user_id",
        "params": {}, "body": {"display_name": "Alice", "role": "admin"}, "requires": ["health_check", "user_control"],
    },
    "injection_probe": {
        "description": "Check the synthetic search endpoint for a simulated SQL-injection marker.",
        "finding": "SIMULATED_SQLI", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/search", "params": {"q": "' OR '1'='1"}, "body": None, "requires": ["health_check"],
    },
    "debug_probe": {
        "description": "Check whether the debug endpoint discloses the synthetic lab secret.",
        "finding": "SECRET_DISCLOSURE", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/debug", "params": {}, "body": None, "requires": ["health_check"],
    },
    "traversal_probe": {
        "description": "Check for simulated path traversal using a synthetic path payload; no real files are accessed.",
        "finding": "SIMULATED_PATH_TRAVERSAL", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/files", "params": {"path": "../../etc/passwd"}, "body": None, "requires": ["health_check"],
    },
    "redirect_probe": {
        "description": "Check whether the synthetic API accepts an external redirect destination.",
        "finding": "OPEN_REDIRECT", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/redirect", "params": {"next": "https://example.invalid/"}, "body": None, "requires": ["health_check"],
    },
    "cors_probe": {
        "description": "Check whether the API reflects an untrusted origin while allowing credentials.",
        "finding": "CORS_MISCONFIGURATION", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/cors", "params": {"origin": "https://attacker.invalid"}, "body": None, "requires": ["health_check"],
    },
    "security_headers_probe": {
        "description": "Check the API response for missing baseline browser security headers.",
        "finding": "MISSING_SECURITY_HEADERS", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/security-headers", "params": {}, "body": None, "requires": ["health_check"],
    },
    "data_exposure_probe": {
        "description": "Check whether a bulk user export exposes synthetic secrets and internal-only fields.",
        "finding": "EXCESSIVE_DATA_EXPOSURE", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/users/export", "params": {}, "body": None, "requires": ["health_check"],
    },
    "error_disclosure_probe": {
        "description": "Check whether a controlled synthetic error response discloses internal stack details.",
        "finding": "VERBOSE_ERROR_DISCLOSURE", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/errors", "params": {"trigger": "synthetic"}, "body": None, "requires": ["health_check"],
    },
    "internal_docs_probe": {
        "description": "Check whether internal-only API documentation is publicly exposed in the synthetic lab.",
        "finding": "EXPOSED_INTERNAL_DOCUMENTATION", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/internal/docs", "params": {}, "body": None, "requires": ["health_check"],
    },
    "weak_password_policy_probe": {
        "description": "Check whether a short weak password is accepted by synthetic registration validation.",
        "finding": "WEAK_PASSWORD_POLICY", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "POST", "path": "/lab/register", "params": {}, "body": {"email": "weak@lab.invalid", "password": "123456"}, "requires": ["health_check"],
    },
    "jwt_config_probe": {
        "description": "Check the synthetic authentication configuration for an unsafe JWT algorithm setting.",
        "finding": "INSECURE_JWT_CONFIGURATION", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/auth/config", "params": {}, "body": None, "requires": ["health_check"],
    },
    "ssrf_probe": {
        "description": "Check a simulated webhook preview for an internal destination marker; no network request is made.",
        "finding": "SIMULATED_SSRF", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/webhook/preview", "params": {"url": "http://internal.lab/admin"}, "body": None, "requires": ["health_check"],
    },
    "rate_limit_probe": {
        "description": "Inspect the synthetic public endpoint's explicit rate-limit simulation marker.",
        "finding": "MISSING_RATE_LIMITING", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/rate-limit/status", "params": {}, "body": None, "requires": ["health_check"],
    },
    "cache_control_probe": {
        "description": "Check whether a synthetic sensitive response is incorrectly marked as publicly cacheable.",
        "finding": "SENSITIVE_CACHEABLE_RESPONSE", "action_type": "finding_probe", "adaptive_candidate": True,
        "method": "GET", "path": "/lab/private/report", "params": {}, "body": None, "requires": ["health_check"],
    },
    "transfer_control": {
        "description": "Perform a harmless synthetic transfer validation control using the discovered primary user ID.",
        "finding": None, "action_type": "control", "adaptive_candidate": False,
        "method": "POST", "path": "/lab/transfer", "resource_id_key": "user_id",
        "params": {}, "body": {"from_user": "{user_id}", "to_user": 2, "amount": 1}, "requires": ["health_check", "user_control"],
    },
}

# The fixed baseline intentionally walks the entire catalogue in this published
# order. All required actions appear before their dependents.
FIXED_SEQUENCE = list(ACTION_CATALOG.keys())

# CVSS v3.1 reference vectors are explicit study assumptions for the synthetic
# training lab and are scored locally using FIRST's published Base Score equations.
# Optional LLM-proposed vectors are collected only for audit/comparison; they do
# not set the authoritative reference score or action-priority order. These are
# hypothetical analog scenarios, not ratings of real vulnerabilities, and require
# analyst review before being presented as vulnerability CVSS ratings.
CVSS_SCENARIO_ASSUMPTIONS: dict[str, str] = {
    "bola_probe": "A low-privilege network user can read another user's confidential profile; no integrity or availability impact.",
    "admin_access_probe": "An ordinary authenticated user can read admin metrics; high confidentiality impact only.",
    "mass_assignment_probe": "A low-privilege network user can set a privileged role; assume high confidentiality, integrity, and availability impact after escalation.",
    "injection_probe": "Assume a real remotely exploitable SQL injection requiring no privileges or user interaction, with high confidentiality, integrity, and availability impact.",
    "debug_probe": "An unauthenticated network user can retrieve a secret from a debug endpoint; high confidentiality impact only.",
    "traversal_probe": "Assume a real unauthenticated network path-traversal flaw that discloses highly sensitive files; confidentiality impact only.",
    "redirect_probe": "An unauthenticated network attacker can redirect a victim; victim interaction is required and the assumed impacts are low confidentiality and integrity in another security authority.",
    "cors_probe": "An unauthenticated network attacker can abuse credentialed CORS reflection after victim-browser interaction; high confidentiality and low integrity impact across a security-authority boundary.",
    "security_headers_probe": "For scoring only, assume missing anti-framing/content-security headers enable victim-assisted UI redress with low confidentiality and integrity impact across a security-authority boundary; the lab marker alone does not prove that exploit.",
    "data_exposure_probe": "An unauthenticated network user can read a bulk export containing sensitive API-key fields; high confidentiality impact only.",
    "error_disclosure_probe": "An unauthenticated network user can retrieve stack-trace details; low confidentiality impact only.",
    "internal_docs_probe": "An unauthenticated network user can read internal route documentation; low confidentiality impact only.",
    "weak_password_policy_probe": "For scoring only, assume the weak policy enables remote compromise of accounts with high confidentiality/integrity and low availability impact; accepting a short password alone does not prove account compromise.",
    "jwt_config_probe": "For scoring only, assume a remotely exploitable JWT alg=none flaw permits unauthenticated full compromise within the same application security authority; high confidentiality, integrity, and availability impact.",
    "ssrf_probe": "Assume a real SSRF flaw lets a low-privilege network attacker reach a separate internal service, with high confidentiality/integrity and low availability impact.",
    "rate_limit_probe": "For scoring only, assume an unauthenticated network attacker can exhaust a service resource and cause high availability impact; an explicit disabled-rate-limit marker alone does not prove denial of service.",
    "cache_control_probe": "A low-privilege network user can obtain another user's sensitive cached report within the same application security authority; high confidentiality impact only.",
}

# Scenario-reference vectors define the *hypothetical impact assumptions* used to
# prioritize the synthetic benchmark. They are explicit study-rubric choices, not
# facts inferred from a response and not CVSS scores for real vulnerabilities.
# The CVSS implementation computes every Base Score locally from these vectors.
# Model-proposed vectors are retained separately for audit/comparison only; they
# cannot silently override the reproducible reference score used by the planner.
CVSS_RUBRIC_VERSION = "pentelligent-scenario-rubric-2026-10-22-v2"
CVSS_REFERENCE_VECTORS: dict[str, str] = {
    "bola_probe": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "admin_access_probe": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "mass_assignment_probe": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "injection_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "debug_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "traversal_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "redirect_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "cors_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "security_headers_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "data_exposure_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "error_disclosure_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "internal_docs_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "weak_password_policy_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "jwt_config_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssrf_probe": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L",
    "rate_limit_probe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "cache_control_probe": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
}

# This is the pre-rubric fingerprint format used by cached profiles. Keeping it
# allows safe migration: action IDs and model are checked, while stale vectors
# and scores are replaced with the current scenario-reference rubric.
_LEGACY_CVSS_SCENARIO_ASSUMPTIONS = {
    "bola_probe": "Network; low-privilege user; no interaction; unchanged scope; high confidentiality impact only.",
    "admin_access_probe": "Network; no privileges or interaction; unchanged scope; high confidentiality impact only.",
    "mass_assignment_probe": "Network; low privileges; no interaction; unchanged scope; role escalation may impact confidentiality, integrity and availability highly.",
    "injection_probe": "Assume real SQL injection: network, no privileges or interaction, unchanged scope; high confidentiality, integrity and availability impacts.",
    "debug_probe": "Network; no privileges or interaction; unchanged scope; high confidentiality impact only.",
    "traversal_probe": "Assume real path traversal: network, no privileges or interaction, unchanged scope; high confidentiality impact only.",
    "redirect_probe": "Unauthenticated network redirect; victim interaction required; changed scope; low confidentiality/integrity impact, no availability impact.",
    "cors_probe": "Network CORS credential reflection; victim browser interaction required; changed scope; high confidentiality, low integrity impact.",
    "security_headers_probe": "Missing browser headers; network, victim interaction required, changed scope; low confidentiality/integrity impact.",
    "data_exposure_probe": "Network bulk export; no privileges or interaction; unchanged scope; high confidentiality impact only.",
    "error_disclosure_probe": "Network stack-trace disclosure; no privileges or interaction; unchanged scope; low confidentiality impact only.",
    "internal_docs_probe": "Network internal documentation exposure; no privileges or interaction; unchanged scope; low confidentiality impact only.",
    "weak_password_policy_probe": "Assume real account compromise via weak policy: network, no privileges or interaction, unchanged scope; high confidentiality/integrity, low availability impact.",
    "jwt_config_probe": "Assume real JWT alg=none privilege forgery: network, no privileges or interaction, changed scope; high confidentiality/integrity/availability impacts.",
    "ssrf_probe": "Assume real SSRF to a separate internal service: network, low privileges, no interaction, changed scope; high confidentiality/integrity and low availability impacts.",
    "rate_limit_probe": "Unauthenticated network resource exhaustion; no interaction; unchanged scope; high availability impact only.",
    "cache_control_probe": "Assume shared-cache disclosure across users: network, low privileges, no interaction, changed scope; high confidentiality impact only.",
}

CVSS_BASE_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
CVSS_METRIC_VALUES: dict[str, dict[str, Decimal]] = {
    "AV": {"N": Decimal("0.85"), "A": Decimal("0.62"), "L": Decimal("0.55"), "P": Decimal("0.20")},
    "AC": {"L": Decimal("0.77"), "H": Decimal("0.44")},
    "PR": {"N": Decimal("0.85"), "L": Decimal("0.62"), "H": Decimal("0.27")},
    "UI": {"N": Decimal("0.85"), "R": Decimal("0.62")},
    "C": {"N": Decimal("0"), "L": Decimal("0.22"), "H": Decimal("0.56")},
    "I": {"N": Decimal("0"), "L": Decimal("0.22"), "H": Decimal("0.56")},
    "A": {"N": Decimal("0"), "L": Decimal("0.22"), "H": Decimal("0.56")},
}


def _cvss_roundup(value: Decimal) -> Decimal:
    """CVSS Roundup: smallest one-decimal value not less than input."""
    rounded = (value * Decimal("10")).to_integral_value(rounding=ROUND_CEILING) / Decimal("10")
    return rounded.quantize(Decimal("0.1"))


def calculate_cvss_v31_base(vector: str) -> dict[str, Any]:
    """Validate a CVSS v3.1 Base vector and calculate its official Base Score.

    Temporal/environmental metrics are intentionally not accepted because this
    prototype estimates only Base metrics. The returned score is mathematically
    derived from the vector; it does not imply the LLM's metric assessment is true.
    """
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        raise ValueError("CVSS vector must start with 'CVSS:3.1/'")
    parsed: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if part.count(":") != 1:
            raise ValueError(f"Malformed CVSS metric component: {part!r}")
        key, value = part.split(":", 1)
        if key not in CVSS_BASE_METRIC_ORDER:
            raise ValueError(f"Unsupported CVSS v3.1 Base metric: {key!r}")
        if key in parsed:
            raise ValueError(f"Duplicate CVSS metric: {key!r}")
        allowed = CVSS_METRIC_VALUES.get(key)
        if key == "S":
            if value not in {"U", "C"}:
                raise ValueError("CVSS Scope must be U or C")
        elif allowed is None or value not in allowed:
            raise ValueError(f"Invalid CVSS value for {key}: {value!r}")
        parsed[key] = value
    missing = set(CVSS_BASE_METRIC_ORDER) - set(parsed)
    if missing:
        raise ValueError("CVSS Base vector is missing metrics: " + ", ".join(sorted(missing)))

    canonical_vector = "CVSS:3.1/" + "/".join(f"{key}:{parsed[key]}" for key in CVSS_BASE_METRIC_ORDER)
    with localcontext() as ctx:
        ctx.prec = 40
        c = CVSS_METRIC_VALUES["C"][parsed["C"]]
        i = CVSS_METRIC_VALUES["I"][parsed["I"]]
        a = CVSS_METRIC_VALUES["A"][parsed["A"]]
        impact_subscore = Decimal("1") - ((Decimal("1") - c) * (Decimal("1") - i) * (Decimal("1") - a))
        if parsed["S"] == "U":
            impact = Decimal("6.42") * impact_subscore
        else:
            impact = Decimal("7.52") * (impact_subscore - Decimal("0.029")) - Decimal("3.25") * (impact_subscore - Decimal("0.02")) ** 15

        pr_weights = {
            "U": {"N": Decimal("0.85"), "L": Decimal("0.62"), "H": Decimal("0.27")},
            "C": {"N": Decimal("0.85"), "L": Decimal("0.68"), "H": Decimal("0.50")},
        }
        exploitability = (
            Decimal("8.22")
            * CVSS_METRIC_VALUES["AV"][parsed["AV"]]
            * CVSS_METRIC_VALUES["AC"][parsed["AC"]]
            * pr_weights[parsed["S"]][parsed["PR"]]
            * CVSS_METRIC_VALUES["UI"][parsed["UI"]]
        )
        if impact <= 0:
            score = Decimal("0.0")
        elif parsed["S"] == "U":
            score = _cvss_roundup(min(impact + exploitability, Decimal("10")))
        else:
            score = _cvss_roundup(min(Decimal("1.08") * (impact + exploitability), Decimal("10")))
    numeric_score = float(score)
    if numeric_score == 0:
        severity = "None"
    elif numeric_score <= 3.9:
        severity = "Low"
    elif numeric_score <= 6.9:
        severity = "Medium"
    elif numeric_score <= 8.9:
        severity = "High"
    else:
        severity = "Critical"
    return {
        "cvss_version": "3.1",
        "vector": canonical_vector,
        "base_score": numeric_score,
        "severity": severity,
    }


def _cvss_action_ids() -> list[str]:
    return [action_id for action_id, action in ACTION_CATALOG.items() if action.get("finding") in TARGET_FINDINGS]


def _cvss_catalog_fingerprint() -> str:
    """Fingerprint the benchmark actions, assumptions, and reference vectors."""
    payload = [
        {
            "action_id": action_id,
            "finding": ACTION_CATALOG[action_id].get("finding"),
            "assumption": CVSS_SCENARIO_ASSUMPTIONS[action_id],
            "reference_vector": CVSS_REFERENCE_VECTORS[action_id],
        }
        for action_id in _cvss_action_ids()
    ]
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _legacy_cvss_catalog_fingerprint() -> str:
    """Recreate the original profile fingerprint so old caches can be migrated."""
    payload = [
        {
            "action_id": action_id,
            "finding": ACTION_CATALOG[action_id].get("finding"),
            "assumption": _LEGACY_CVSS_SCENARIO_ASSUMPTIONS[action_id],
        }
        for action_id in _cvss_action_ids()
    ]
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_proposed_assessments(assessments_raw: Any) -> dict[str, str]:
    """Validate and return raw model-proposed vectors keyed by target action ID."""
    expected = _cvss_action_ids()
    items: list[dict[str, Any]] = []
    if isinstance(assessments_raw, dict):
        for action_id, value in assessments_raw.items():
            if isinstance(value, str):
                items.append({"action_id": action_id, "vector": value})
            elif isinstance(value, dict):
                items.append({"action_id": action_id, **value})
            else:
                raise ValueError(f"CVSS assessment for {action_id!r} must be an object or vector string")
    elif isinstance(assessments_raw, list):
        items = assessments_raw
    else:
        raise ValueError("LLM response must include cvss_assessments as a list or object")

    proposals: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Each CVSS assessment must be a JSON object")
        action_id = item.get("action_id")
        # Prefer the original proposal when reloading a profile that already holds
        # both the authoritative reference vector and the raw model proposal.
        vector = item.get("model_proposed_vector") or item.get("vector") or item.get("cvss_vector")
        if not isinstance(action_id, str) or action_id not in expected:
            raise ValueError(f"Unknown CVSS assessment action_id: {action_id!r}")
        if action_id in proposals:
            raise ValueError(f"Duplicate CVSS assessment for {action_id!r}")
        scored = calculate_cvss_v31_base(vector)
        proposals[action_id] = scored["vector"]
    missing = [action_id for action_id in expected if action_id not in proposals]
    if missing:
        raise ValueError("LLM did not propose a vector for every target finding action: " + ", ".join(missing))
    return proposals


def _assemble_cvss_reference_profile(model: str, model_proposals: dict[str, str] | None = None) -> dict[str, Any]:
    """Build scores from the study rubric; preserve LLM proposals only for audit."""
    expected = _cvss_action_ids()
    proposals = model_proposals or {}
    output: dict[str, dict[str, Any]] = {}
    for action_id in expected:
        action = ACTION_CATALOG[action_id]
        reference = calculate_cvss_v31_base(CVSS_REFERENCE_VECTORS[action_id])
        proposed_vector = proposals.get(action_id)
        proposal_score = calculate_cvss_v31_base(proposed_vector) if proposed_vector else None
        matches_reference = bool(proposed_vector and proposal_score and proposal_score["vector"] == reference["vector"])
        output[action_id] = {
            "action_id": action_id,
            "finding": action["finding"],
            **reference,
            "reference_vector": reference["vector"],
            "model_proposed_vector": proposal_score["vector"] if proposal_score else None,
            "model_proposed_base_score": proposal_score["base_score"] if proposal_score else None,
            "model_proposal_status": (
                "matches_scenario_reference" if matches_reference else
                "differs_from_scenario_reference" if proposed_vector else
                "not_collected"
            ),
            "assessment_type": "scenario_reference_vector",
            "vector_source": "study_defined_synthetic_scenario_rubric",
            "status": "illustrative_scenario_estimate_requires_analyst_review",
            "scenario_assumption": CVSS_SCENARIO_ASSUMPTIONS[action_id],
        }

    priority_order = sorted(expected, key=lambda action_id: (-output[action_id]["base_score"], expected.index(action_id)))
    proposal_count = sum(1 for item in output.values() if item["model_proposed_vector"])
    agreement_count = sum(1 for item in output.values() if item["model_proposal_status"] == "matches_scenario_reference")
    return {
        "schema_version": 2,
        "cvss_version": "3.1",
        "rubric_version": CVSS_RUBRIC_VERSION,
        "model": model,
        "catalog_fingerprint": _cvss_catalog_fingerprint(),
        "scoring_method": (
            "The study-defined scenario-reference vectors determine the prioritization scores. "
            "The program calculates CVSS v3.1 Base Scores locally using FIRST's published equations. "
            "Any LLM-proposed vectors are retained for comparison only and cannot determine the priority score."
        ),
        "interpretation_warning": (
            "These are illustrative CVSS v3.1 Base estimates for explicitly assumed analog scenarios, "
            "not validated scores for the synthetic responses or real vulnerabilities. Generic configuration "
            "markers such as missing headers or disabled rate limiting do not by themselves prove the assumed impact. "
            "A qualified analyst must verify applicability and impact before using the vector as a vulnerability rating."
        ),
        "model_proposal_summary": {
            "collected_count": proposal_count,
            "matches_reference_count": agreement_count,
            "differs_from_reference_count": proposal_count - agreement_count,
            "scores_are_driven_by_model_proposals": False,
        },
        "assessments": output,
        "priority_order": priority_order,
    }


def build_cvss_reference_profile(model: str) -> dict[str, Any]:
    """Create the fast deterministic profile used for normal experiment runs."""
    profile = _assemble_cvss_reference_profile(model, None)
    profile["profile_generation_elapsed_seconds"] = 0.0
    profile["profile_generation_method"] = "local scenario-reference rubric; no CVSS vector-generation calls"
    profile["profile_generation_llm_calls"] = 0
    profile["profile_generation_batch_size"] = None
    profile["profile_generation_fallback_count"] = 0
    return profile


def build_cvss_profile(assessments_raw: Any, model: str) -> dict[str, Any]:
    """Validate LLM vectors for audit and score from scenario-reference vectors.

    LLM output is never the source of the priority score: small models may emit a
    generic vector for unrelated findings. The proposal is retained explicitly,
    its independently calculated score is recorded, and any disagreement with
    the rubric is visible in ``model_proposal_status``.
    """
    proposals = _normalize_proposed_assessments(assessments_raw)
    return _assemble_cvss_reference_profile(model, proposals)


def load_cvss_profile(path: str | Path | None, model: str) -> dict[str, Any]:
    """Load a profile, migrate legacy model-scored caches, and recalculate locally.

    Stored numeric scores and vectors never drive prioritization. If all 17 target
    IDs are present, the current scenario-reference rubric replaces old scores and
    vectors. This allows a previously cached generic LLM profile to be repaired
    without another expensive model-scoring pass.
    """
    if not path:
        return {}
    profile_path = Path(path).expanduser()
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read CVSS profile {str(profile_path)!r}: {exc}") from exc
    if not isinstance(profile, dict) or profile.get("schema_version") not in {1, 2} or profile.get("cvss_version") != "3.1":
        raise ValueError("CVSS profile has an unsupported or malformed schema")
    if profile.get("model") != model:
        raise ValueError(f"CVSS profile model {profile.get('model')!r} does not match configured model {model!r}")
    raw = profile.get("assessments")
    expected_ids = set(_cvss_action_ids())
    if not isinstance(raw, dict) or set(raw) != expected_ids:
        raise ValueError("CVSS profile action IDs do not match the current target catalogue")
    if any(not isinstance(item, dict) for item in raw.values()):
        raise ValueError("CVSS profile contains a malformed assessment")

    stored_fingerprint = profile.get("catalog_fingerprint")
    current_fingerprint = _cvss_catalog_fingerprint()
    migrated = stored_fingerprint != current_fingerprint or profile.get("schema_version") != 2

    # Preserve a prior model proposal from either the new schema or old cached
    # profiles, but always regenerate authoritative scores/vectors from the rubric.
    proposals: dict[str, str] = {}
    for action_id, item in raw.items():
        # A present-but-null field means this is a local rubric profile with no
        # LLM proposal. Only old schema-1 entries (where the key did not exist)
        # are interpreted as archived model proposals.
        if "model_proposed_vector" in item:
            candidate = item.get("model_proposed_vector")
        else:
            candidate = item.get("vector") or item.get("cvss_vector")
        if isinstance(candidate, str):
            try:
                proposals[action_id] = calculate_cvss_v31_base(candidate)["vector"]
            except (TypeError, ValueError):
                # A damaged historical proposal should not invalidate the study
                # rubric profile; it is excluded from the model-comparison summary.
                continue

    proposals_are_complete = len(proposals) == len(_cvss_action_ids())
    rebuilt = _assemble_cvss_reference_profile(model, proposals if proposals_are_complete else None)
    rebuilt["loaded_from"] = str(profile_path.resolve())
    rebuilt["profile_migrated_from_legacy"] = migrated
    rebuilt["legacy_catalog_fingerprint"] = stored_fingerprint if migrated else None
    rebuilt["profile_generation_elapsed_seconds"] = 0.0
    rebuilt["profile_generation_method"] = "local scenario-reference rubric; no CVSS vector-generation calls in this run"
    rebuilt["profile_generation_llm_calls"] = 0
    rebuilt["profile_generation_batch_size"] = None
    rebuilt["profile_generation_fallback_count"] = 0
    if profile.get("profile_generation_elapsed_seconds") is not None:
        rebuilt["historical_model_proposal_generation_elapsed_seconds"] = profile.get("profile_generation_elapsed_seconds")
    if profile.get("profile_generation_llm_calls") is not None:
        rebuilt["historical_model_proposal_generation_llm_calls"] = profile.get("profile_generation_llm_calls")
    old_interactions = profile.get("profile_generation_interactions_file")
    if old_interactions:
        rebuilt["model_proposal_interactions_file"] = old_interactions
    return rebuilt


# ============================================================
# INDEPENDENT LLM QUALITATIVE RISK ASSESSMENT (NOT CVSS)
# ============================================================

LLM_RISK_PROFILE_VERSION = "pentelligent-qualitative-risk-profile-v6-banded"
LLM_SEVERITY_BANDS = ("informational", "low", "medium", "high", "critical")
LLM_CONFIDENCE_BANDS = ("low", "medium", "high")
LLM_SEVERITY_ORDER = {name: index for index, name in enumerate(LLM_SEVERITY_BANDS)}

# Short, human-authored descriptions of plausible impact and important caveats.
# They deliberately avoid CVSS metric values/vectors and are separate from the
# scenario-reference CVSS assumptions, so the qualitative LLM judgment is not
# merely a restatement of that rubric. These descriptions also enter the profile
# fingerprint: changing the study assumptions invalidates a stale cached profile.
LLM_RISK_SCENARIO_CONTEXT: dict[str, str] = {
    "bola_probe": "Cross-account profile reads may expose private records; impact depends on exposed fields and authorization boundaries.",
    "admin_access_probe": "An ordinary account reading administrator-only metrics can disclose operational or sensitive data; write impact is not shown by this probe.",
    "mass_assignment_probe": "Acceptance of a privileged role field may enable privilege escalation if the value persists and affects authorization.",
    "injection_probe": "The lab returns an injection marker only; a real injection flaw could expose or modify data depending on query context and privileges.",
    "debug_probe": "A public debug endpoint exposes a synthetic secret; severity depends on whether an analogue exposes valid credentials or sensitive internals.",
    "traversal_probe": "The lab returns a simulated traversal marker and reads no files; a real flaw may disclose sensitive files if reachable.",
    "redirect_probe": "An external redirect can support phishing or trust abuse; direct confidentiality or integrity impact is not established by the redirect alone.",
    "cors_probe": "Credentialed cross-origin access may expose authenticated responses when browser, origin, and endpoint conditions align.",
    "security_headers_probe": "Missing headers are a hardening weakness; the marker alone does not establish a working framing, script, or content attack.",
    "data_exposure_probe": "The lab export includes synthetic key-like fields; impact depends on whether equivalent real fields are secret, valid, and reusable.",
    "error_disclosure_probe": "Stack details may reveal implementation information that enables follow-on attacks; direct impact may otherwise be limited.",
    "internal_docs_probe": "Public internal route documentation reveals attack-surface information; it does not by itself prove access to protected operations.",
    "weak_password_policy_probe": "A short password is accepted in the lab; account compromise depends on other controls and is not demonstrated by acceptance alone.",
    "jwt_config_probe": "The lab advertises an unsafe JWT algorithm; impact depends on whether a real verifier accepts forged tokens and which claims it trusts.",
    "ssrf_probe": "The lab returns an internal-destination marker without network access; a real SSRF impact depends on reachable services and the response data.",
    "rate_limit_probe": "The lab states rate limiting is disabled; service exhaustion depends on resource costs, capacity, and other controls and is not demonstrated here.",
    "cache_control_probe": "A sensitive-looking report is marked publicly cacheable; exposure depends on cache behavior, cache keys, and the confidentiality of the content.",
}

# Compact action-specific impact cues for repeated live planning prompts. Unlike the
# longer profile-generation descriptions above, these are deliberately concise and
# phrased as plausible consequences plus the key uncertainty. They are not CVSS
# metrics, score-derived tiers, or a fixed priority order. The model receives these
# cues with every unresolved candidate so it does not see sentence fragments caused
# by crude character truncation.
LLM_ACTION_IMPACT_HINTS: dict[str, str] = {
    "bola_probe": "Cross-account private-data exposure; field sensitivity matters.",
    "admin_access_probe": "Ordinary user accesses admin-only data across an authorization boundary.",
    "mass_assignment_probe": "Privilege escalation if the role persists and controls authorization.",
    "injection_probe": "Real SQLi may expose or alter data; the lab marker is not proof.",
    "debug_probe": "Unauthenticated secret exposure; secret validity and scope matter.",
    "traversal_probe": "Potential sensitive-file disclosure; no real file is read here.",
    "redirect_probe": "Victim-assisted phishing/trust abuse; direct data impact is limited.",
    "cors_probe": "Credentialed cross-origin reads may expose private data.",
    "security_headers_probe": "Hardening weakness; a concrete browser-side exploit is not proven.",
    "data_exposure_probe": "Sensitive export exposure; secret validity and reuse matter.",
    "error_disclosure_probe": "Stack details may aid follow-on attacks; impact varies.",
    "internal_docs_probe": "Route disclosure aids reconnaissance; it does not bypass authorization.",
    "weak_password_policy_probe": "Weak policy raises account risk; short acceptance is not compromise.",
    "jwt_config_probe": "Unsafe JWT verification may enable token forgery or auth bypass.",
    "ssrf_probe": "SSRF may reach internal services; the lab made no network call.",
    "rate_limit_probe": "Missing limits may enable resource exhaustion; DoS is not proven.",
    "cache_control_probe": "Shared-cache behavior may expose another user's sensitive report.",
}

LLM_RECON_DECISION_HINTS: dict[str, str] = {
    "api_info_control": "Identity only; low value after health check.",
    "users_list_control": "Useful if unknown users/roles change authorization tests.",
    "schema_control": "Useful if schema reveals unmodelled routes or resources.",
}


def _compact_prompt_text(value: Any, max_chars: int = 78) -> str:
    """Collapse whitespace and truncate at a word boundary with an ellipsis."""
    text = " ".join(str(value or "").split())
    if len(text) <= max_chars:
        return text
    if max_chars <= 1:
        return text[:max_chars]
    prefix = text[:max_chars - 1]
    if " " in prefix:
        prefix = prefix.rsplit(" ", 1)[0]
    return prefix.rstrip(" ,;:-") + "…"


def _reconnaissance_response_is_material(action_id: str, response: dict[str, Any]) -> bool:
    """Return true only when reconnaissance reveals unexpected actionable context.

    The bundled synthetic target has known safe baseline responses. Routine identity,
    route-schema, or known-user output does not invalidate already-validated finding
    intents: the candidate catalogue and their request templates already cover them.
    Unexpected structure, new roles/resources, or non-success responses do invalidate
    the plan so the LLM can react to genuinely novel evidence.
    """
    status = response.get("status_code")
    if type(status) is not int or not 200 <= status < 300:
        return True
    body = response.get("body")
    if not isinstance(body, dict):
        return True

    if action_id == "api_info_control":
        expected = {
            "service": "Pentelligent Synthetic Web API",
            "purpose": "Local security-testing laboratory",
            "health": "/health",
        }
        return body != expected

    if action_id == "schema_control":
        expected = {
            "api": "Pentelligent Synthetic Web API",
            "resource_types": ["users", "profiles", "catalog", "reports"],
            "conventions": {"pagination": "page/limit", "content_type": "application/json"},
            "lab_marker": "SAFE_SCHEMA_CONTROL",
        }
        return body != expected

    if action_id == "users_list_control":
        users = body.get("users")
        if not isinstance(users, list):
            return True
        if not all(isinstance(row, dict) for row in users):
            return True
        signature = sorted(
            (type(row.get("id")).__name__, repr(row.get("id")), str(row.get("username")), str(row.get("role")), tuple(sorted(row)))
            for row in users
        )
        expected_users = sorted([
            ("int", "1", "alice", "user", ("id", "role", "username")),
            ("int", "2", "bob", "user", ("id", "role", "username")),
        ])
        return (
            signature != expected_users
            or body.get("total") != 2
            or body.get("page") != 1
            or body.get("limit") != 10
            or set(body) != {"users", "page", "limit", "total"}
        )

    # Any new reconnaissance action should be treated conservatively until its
    # expected baseline response is explicitly defined and tested.
    return True


def _llm_risk_target_ids() -> list[str]:
    """Return the target probe IDs assessed by the independent qualitative profile."""
    return _cvss_action_ids()


def _llm_risk_catalog_fingerprint() -> str:
    payload = {
        "version": LLM_RISK_PROFILE_VERSION,
        "targets": [
            {
                "action_id": action_id,
                "finding": ACTION_CATALOG[action_id].get("finding"),
                "description": ACTION_CATALOG[action_id].get("description", ""),
                "scenario_context": LLM_RISK_SCENARIO_CONTEXT.get(action_id, ""),
            }
            for action_id in _llm_risk_target_ids()
        ],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def normalize_llm_risk_assessments(raw: Any) -> dict[str, dict[str, Any]]:
    """Validate all qualitative estimates; preserve catalogue order for stable ties."""
    if isinstance(raw, dict) and isinstance(raw.get("assessments"), list):
        items = raw["assessments"]
    elif isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = [({"action_id": action_id, **value} if isinstance(value, dict) else {})
                 for action_id, value in raw.items()]
    else:
        raise ValueError("LLM risk profile must contain an assessments list or object")

    expected = _llm_risk_target_ids()
    catalogue_order = {action_id: index for index, action_id in enumerate(expected)}
    result: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            errors.append("non-object risk assessment")
            continue
        action_id = item.get("action_id")
        if action_id not in catalogue_order:
            errors.append(f"unknown action_id {action_id!r}")
            continue
        if action_id in result:
            errors.append(f"duplicate action_id {action_id!r}")
            continue
        severity = str(item.get("severity_estimate", item.get("severity", ""))).strip().lower()
        confidence = str(item.get("confidence", "")).strip().lower()
        rationale_value = item.get("rationale", item.get("basis", ""))
        if severity not in LLM_SEVERITY_BANDS:
            errors.append(f"invalid severity_estimate for {action_id!r}: {severity!r}")
            continue
        if confidence not in LLM_CONFIDENCE_BANDS:
            errors.append(f"invalid confidence for {action_id!r}: {confidence!r}")
            continue
        if not isinstance(rationale_value, str) or not rationale_value.strip():
            errors.append(f"missing rationale for {action_id!r}")
            continue
        rationale = " ".join(rationale_value.split())[:70]
        result[action_id] = {
            "action_id": action_id,
            "finding": ACTION_CATALOG[action_id].get("finding"),
            "severity_estimate": severity,
            # Severity group is a direct mapping of a qualitative band, not a
            # unique ordinal ranking of individual findings. Items in the same
            # band intentionally tie; catalogue order is display-only.
            "severity_group_rank": len(LLM_SEVERITY_BANDS) - LLM_SEVERITY_ORDER[severity],
            "catalogue_order": catalogue_order[action_id],
            "confidence": confidence,
            "rationale": rationale,
            "scenario_context": LLM_RISK_SCENARIO_CONTEXT.get(action_id, ""),
            "assessment_kind": "llm_qualitative_hypothetical_severity_not_cvss",
        }

    missing = [action_id for action_id in expected if action_id not in result]
    if errors or missing:
        details = []
        if errors:
            details.append("errors: " + "; ".join(errors[:6]))
        if missing:
            details.append("missing: " + ", ".join(missing))
        raise ValueError("Incomplete or invalid LLM qualitative risk profile (" + " | ".join(details) + ")")
    return result


def _order_llm_risk_by_band(assessments: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Order by qualitative band only; same-band items are ties, not ranked."""
    return sorted(
        assessments.values(),
        key=lambda item: (
            -LLM_SEVERITY_ORDER[item["severity_estimate"]],
            int(item.get("catalogue_order", _llm_risk_target_ids().index(item["action_id"]))),
        ),
    )


def build_llm_risk_profile(raw: Any, model: str) -> dict[str, Any]:
    """Build a qualitative band profile without inventing a fragile global ranking.

    Qwen's previous global ordering pass contradicted its own severity bands. This
    profile therefore ranks only the bands, with ties inside each band. The
    catalogue order is used for reproducible display and is not a severity claim.
    """
    assessments = normalize_llm_risk_assessments(raw)
    ordered = _order_llm_risk_by_band(assessments)
    for item in ordered:
        item["severity_group_rank"] = len(LLM_SEVERITY_BANDS) - LLM_SEVERITY_ORDER[item["severity_estimate"]]
    return {
        "schema_version": 1,
        "profile_version": LLM_RISK_PROFILE_VERSION,
        "model": model,
        "catalog_fingerprint": _llm_risk_catalog_fingerprint(),
        "profile_method": "LLM qualitative severity bands; independent of CVSS vectors/scores; analyst review required",
        "ranking_source": "llm_severity_band_groups",
        "ranking_semantics": (
            "Only qualitative bands are ordered: critical > high > medium > low > informational. "
            "Findings in the same band are tied; catalogue order is used only for stable display, not a second model ranking."
        ),
        "interpretation_warning": (
            "These are uncalibrated model judgments about plausible technical severity if a real-world analogue were confirmed. "
            "They are not CVSS scores, ground truth, calibrated probabilities, or proof that a synthetic marker demonstrates real exploitability. "
            "Validate against an expert-reviewed benchmark before making accuracy claims."
        ),
        "severity_order": [item["action_id"] for item in ordered],
        "assessments": assessments,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def load_llm_risk_profile(path: str | Path | None, model: str) -> dict[str, Any]:
    """Load a fresh-format qualitative profile and recompute its stable band order."""
    if not path:
        raise ValueError("No LLM risk profile path supplied")
    profile_path = Path(path).expanduser()
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read LLM risk profile {str(profile_path)!r}: {exc}") from exc
    if not isinstance(profile, dict) or profile.get("schema_version") != 1:
        raise ValueError("Unsupported or malformed LLM risk profile schema")
    if profile.get("profile_version") != LLM_RISK_PROFILE_VERSION:
        raise ValueError("LLM risk profile version is stale")
    if profile.get("model") != model:
        raise ValueError(f"LLM risk profile model {profile.get('model')!r} does not match {model!r}")
    if profile.get("catalog_fingerprint") != _llm_risk_catalog_fingerprint():
        raise ValueError("LLM risk profile does not match the current target catalogue")

    assessments = normalize_llm_risk_assessments(profile.get("assessments"))
    ordered = _order_llm_risk_by_band(assessments)
    for item in ordered:
        item["severity_group_rank"] = len(LLM_SEVERITY_BANDS) - LLM_SEVERITY_ORDER[item["severity_estimate"]]
    normalized = dict(profile)
    normalized["assessments"] = assessments
    normalized["severity_order"] = [item["action_id"] for item in ordered]
    normalized["ranking_source"] = "llm_severity_band_groups"
    normalized["ranking_semantics"] = (
        "Only qualitative bands are ordered; same-band findings are tied. Catalogue order is display-only."
    )
    normalized["loaded_from"] = str(profile_path.resolve())
    return normalized


# ============================================================
# SYNTHETIC TEST API
# ============================================================

app = FastAPI(
    title="Pentelligent Synthetic Web API",
    description="Intentionally vulnerable local training API.",
    version="1.0.0",
)

LAB_SECRET = "PENTELLIGENT_SYNTHETIC_LAB_SECRET"
LAB_STATE: dict[str, Any] = {"profile_updates": []}


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "service": "Pentelligent Synthetic Web API",
        "purpose": "Local security-testing laboratory",
        "health": "/health",
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/lab/users")
async def list_users(page: int = Query(default=1, ge=1), limit: int = Query(default=10, ge=1, le=50)) -> dict[str, Any]:
    users = [
        {"id": 1, "username": "alice", "role": "user"},
        {"id": 2, "username": "bob", "role": "user"},
    ]
    start = (page - 1) * limit
    return {"users": users[start:start + limit], "page": page, "limit": limit, "total": len(users)}


@app.get("/lab/schema")
async def safe_schema() -> dict[str, Any]:
    return {
        "api": "Pentelligent Synthetic Web API",
        "resource_types": ["users", "profiles", "catalog", "reports"],
        "conventions": {"pagination": "page/limit", "content_type": "application/json"},
        "lab_marker": "SAFE_SCHEMA_CONTROL",
    }


@app.get("/lab/catalog")
async def catalog() -> dict[str, Any]:
    return {"items": [{"id": "P-1", "name": "Synthetic product", "price": 12.5}], "total": 1}


@app.post("/lab/validate")
async def validate_input(payload: dict[str, Any]) -> dict[str, Any]:
    email = payload.get("email")
    age = payload.get("age")
    if not isinstance(email, str) or "@" not in email or type(age) is not int or not 0 <= age <= 130:
        raise HTTPException(status_code=422, detail="Input validation failed")
    return {"valid": True, "lab_marker": "VALIDATION_CONTROL"}


@app.get("/lab/cors")
async def cors_probe_response(origin: str = Query(default="null")) -> JSONResponse:
    # Intentionally insecure *within this local synthetic lab*: reflect any origin
    # and allow credentials. No browser or remote target is contacted by the lab.
    return JSONResponse(
        {"status": "ok", "lab_marker": "CORS_REFLECTS_UNTRUSTED_ORIGIN", "origin": origin},
        headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        },
    )


@app.get("/lab/security-headers")
async def security_headers_probe_response() -> dict[str, Any]:
    # Intentionally lacks common browser security response headers for detection tests.
    return {"status": "ok", "lab_marker": "MISSING_SECURITY_HEADERS_SIMULATION"}


@app.get("/lab/users/export")
async def data_export_probe_response() -> dict[str, Any]:
    # Synthetic records only; values are non-usable training markers.
    return {
        "records": [
            {"id": 1, "username": "alice", "email": "alice@lab.invalid", "api_key": "SYNTHETIC_KEY_ALICE"},
            {"id": 2, "username": "bob", "email": "bob@lab.invalid", "api_key": "SYNTHETIC_KEY_BOB"},
        ],
        "lab_marker": "EXCESSIVE_SYNTHETIC_DATA_EXPOSURE",
    }


@app.get("/lab/errors")
async def verbose_error_response(trigger: str = Query(default="synthetic")) -> JSONResponse:
    if trigger != "synthetic":
        raise HTTPException(status_code=400, detail="Only the synthetic error trigger is supported")
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Synthetic lab exception",
            "stack_trace": "Traceback (synthetic): app.lab.handlers.process_request -> demo.py:42",
            "lab_marker": "VERBOSE_SYNTHETIC_ERROR_DISCLOSURE",
        },
    )


@app.get("/lab/internal/docs")
async def exposed_internal_docs_response() -> dict[str, Any]:
    return {
        "internal_routes": ["/lab/admin/metrics", "/lab/users/export", "/lab/auth/config"],
        "deployment_note": "synthetic training only",
        "lab_marker": "INTERNAL_DOCUMENTATION_EXPOSED",
    }


@app.post("/lab/register")
async def synthetic_register(payload: dict[str, Any]) -> dict[str, Any]:
    password = payload.get("password")
    if not isinstance(password, str):
        raise HTTPException(status_code=422, detail="Password is required")
    if len(password) < 8:
        return {"registered": True, "password_length": len(password), "lab_marker": "SHORT_PASSWORD_ACCEPTED"}
    return {"registered": True, "password_length": len(password), "lab_marker": "REGISTRATION_CONTROL"}


@app.get("/lab/auth/config")
async def auth_config_response() -> dict[str, Any]:
    return {"token_type": "JWT", "accepted_algorithms": ["none", "HS256"], "lab_marker": "JWT_ALGORITHM_NONE_ENABLED"}


@app.get("/lab/webhook/preview")
async def synthetic_webhook_preview(url: str = Query(default="http://internal.lab/admin")) -> dict[str, Any]:
    # Crucially, this endpoint does NOT make any outbound network request. It only
    # returns a synthetic marker representing a vulnerable URL-preview decision.
    return {
        "requested_url": url,
        "requested_host": urlparse(url).hostname or "unknown",
        "simulated_only": True,
        "lab_marker": "SIMULATED_SSRF_INTERNAL_RESOURCE_RESOLVED",
    }


@app.get("/lab/rate-limit/status")
async def rate_limit_status_response() -> dict[str, Any]:
    return {"rate_limit_enforced": False, "request_count": 1, "lab_marker": "NO_RATE_LIMIT_ENFORCEMENT_IN_LAB"}


@app.get("/lab/private/report")
async def sensitive_cache_response() -> JSONResponse:
    return JSONResponse(
        {"report": "synthetic confidential report", "owner_id": 1, "lab_marker": "SENSITIVE_RESPONSE_PUBLICLY_CACHEABLE"},
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.post("/lab/reset")
async def lab_reset(
    scenario: str = Query(default="default"),
) -> dict[str, Any]:
    if scenario not in {"default", "single_user_context", "unavailable_user_context"}:
        raise HTTPException(status_code=400, detail="Unknown scenario")

    LAB_STATE["profile_updates"] = []
    LAB_STATE["scenario"] = scenario

    return {"reset": True, "scenario": scenario}


@app.get("/lab/users/{user_id}")
async def get_user(user_id: int) -> dict[str, Any]:
    if LAB_STATE.get("scenario") == "unavailable_user_context" and user_id == 1:
        raise HTTPException(status_code=503, detail="Primary user context unavailable in this synthetic scenario")
    users = {
        1: {"id": 1, "username": "alice", "role": "user"},
        2: {"id": 2, "username": "bob", "role": "user"},
    }
    user = users.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/lab/users/{user_id}/profile")
async def get_profile(
    user_id: int,
    requester_id: int = Query(default=1),
) -> dict[str, Any]:
    if user_id not in {1, 2}:
        raise HTTPException(status_code=404, detail="Profile not found")
    if LAB_STATE.get("scenario") == "single_user_context" and user_id == 2:
        raise HTTPException(status_code=404, detail="Profile not found in single-user scenario")

    # Intentional lab flaw: requester identity is not authorized
    # against the requested profile.
    return {
        "finding": "BOLA",
        "user_id": user_id,
        "requester_id": requester_id,
        "username": "alice" if user_id == 1 else "bob",
        "email": "alice@lab.invalid" if user_id == 1 else "bob@lab.invalid",
        "lab_marker": "BOLA_CROSS_USER_PROFILE_ACCESS",
    }


@app.get("/lab/admin/metrics")
async def admin_metrics(
    role: str = Query(default="user"),
) -> dict[str, Any]:
    # Intentional lab flaw: role is trusted directly from the request.
    return {
        "finding": "BROKEN_ADMIN_AUTH",
        "requested_role": role,
        "metrics": {"users": 2, "admin_events": 3},
        "lab_marker": "ADMIN_METRICS_ACCESS_WITHOUT_AUTHORIZATION",
    }


@app.post("/lab/users/{user_id}/profile")
async def update_profile(
    user_id: int,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if user_id not in {1, 2}:
        raise HTTPException(status_code=404, detail="User not found")
    if LAB_STATE.get("scenario") == "single_user_context" and user_id == 2:
        raise HTTPException(status_code=404, detail="User not found in single-user scenario")

    # Intentional lab flaw: privileged fields are mass-assigned.
    LAB_STATE["profile_updates"].append(
        {"user_id": user_id, "payload": payload}
    )
    return {
        "finding": "MASS_ASSIGNMENT",
        "user_id": user_id,
        "updated_fields": payload,
        "role_after_update": payload.get("role", "user"),
        "lab_marker": (
            "MASS_ASSIGNMENT_PRIVILEGED_ROLE_ACCEPTED"
            if "role" in payload
            else "PROFILE_UPDATED"
        ),
    }


@app.get("/lab/search")
async def search(q: str = Query(default="")) -> dict[str, Any]:
    suspicious = any(
        token in q.lower()
        for token in ("' or ", " or '1'='1", "union select", ";--")
    )
    if suspicious:
        # This is a simulation marker, not a real SQL query.
        return {
            "finding": "SIMULATED_SQLI",
            "query": q,
            "rows": [{"id": 1}, {"id": 2}],
            "lab_marker": "SIMULATED_SQL_INJECTION_PATTERN_ACCEPTED",
        }

    return {
        "query": q,
        "results": [{"id": 1, "username": "alice"}] if q else [],
    }


@app.get("/lab/debug")
async def debug() -> dict[str, Any]:
    # Intentional lab flaw: synthetic secret is exposed.
    return {
        "debug": True,
        "environment": "lab",
        "secret": LAB_SECRET,
        "lab_marker": "DEBUG_SECRET_DISCLOSURE",
    }


@app.get("/lab/files")
async def get_file(
    path: str = Query(default="public/readme.txt"),
) -> dict[str, Any]:
    if ".." in path or path.startswith("/"):
        # Never accesses the real filesystem.
        return {
            "finding": "SIMULATED_PATH_TRAVERSAL",
            "requested_path": path,
            "simulated_content": "root:x:0:0:synthetic-lab",
            "lab_marker": "SIMULATED_PATH_TRAVERSAL_ACCEPTED",
        }

    return {
        "path": path,
        "content": "Pentelligent public laboratory readme.",
    }


@app.get("/lab/redirect")
async def redirect(next: str = Query(default="/")) -> RedirectResponse:
    # Intentional lab flaw: arbitrary redirect target accepted.
    # This route is only exposed on the local synthetic lab.
    return RedirectResponse(url=next, status_code=307)


@app.post("/lab/transfer")
async def transfer(payload: dict[str, Any]) -> dict[str, Any]:
    amount = payload.get("amount", 0)
    if type(amount) not in (int, float) or amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount")

    return {
        "status": "validated",
        "amount": amount,
        "lab_marker": "TRANSFER_CONTROL_ONLY",
    }


# ============================================================
# HTTP EXECUTOR AND ACTION VALIDATOR
# ============================================================

def selection_event_action_role_is_valid(event: dict[str, Any]) -> bool:
    """Validate the event shape without confusing blocked intents with executed actions.

    A ``blocked_intent`` is a legitimate planner audit event, not an executed
    action. It is valid only when the intended ID is allowlisted and the planner
    explicitly reports a blocked prerequisite. Other known selection roles are
    checked against their expected decision source.
    """
    action_id = event.get("action_id")
    role = event.get("selection_role")
    source = event.get("selection_source")
    status = str(event.get("status", ""))

    if action_id not in ACTION_CATALOG:
        return False
    if role == "blocked_intent":
        return source == "dependency_planner" and status.startswith("blocked_")
    if role == "prerequisite":
        return source == "dependency_planner"
    if role in {"finding_probe", "reconnaissance"}:
        return source in {
            "llm", "llm_plan", "cvss_priority_guard", "progress_guard", "fallback",
            "single_candidate", "dependency_planner",
        }
    return False


class ActionValidationError(ValueError):
    pass


class ActionValidator:
    def validate(
        self,
        action_id: str,
        executed: list[str],
        context: dict[str, Any],
    ) -> None:
        if action_id not in ACTION_CATALOG:
            raise ActionValidationError(f"Action is not allowlisted: {action_id}")

        if action_id in executed:
            raise ActionValidationError(f"Action already executed: {action_id}")

        action = ACTION_CATALOG[action_id]
        path = action["path"]

        if not (path == "/" or path.startswith("/lab/") or path == "/health"):
            raise ActionValidationError("Path is outside the local lab allowlist")

        prerequisite_actions = set(context.get("successful_actions", []))
        for dependency in action["requires"]:
            if dependency not in prerequisite_actions:
                raise ActionValidationError(
                    f"Missing successful prerequisite action: {dependency}"
                )
        if action.get("resource_id_key"):
            primary_user_id = context.get("primary_user_id")
            if not is_positive_integer(primary_user_id):
                raise ActionValidationError(
                    "Required positive integer user_id from successful user_control has not been discovered"
                )


class HTTPExecutor:
    def __init__(self, base_url: str = API_BASE) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("The lab target must be an explicit HTTP URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials must not be embedded in PENTELLIGENT_API_BASE")
        host = parsed.hostname.lower()
        is_loopback = False
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = host == "localhost"
        if not is_loopback and host not in ALLOWED_TARGET_HOSTS:
            raise ValueError(
                f"Target host {host!r} is not allowlisted. Use loopback or "
                "explicitly set PENTELLIGENT_ALLOWED_HOSTS for an authorized lab."
            )
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("PENTELLIGENT_API_BASE must be an origin, without path/query/fragment")
        self.initiated_requests = 0
        self.completed_responses = 0

    async def execute(self, action_id: str, observations: dict[str, Any] | None = None) -> dict[str, Any]:
        if action_id not in ACTION_CATALOG:
            raise ActionValidationError(f"Action is not allowlisted: {action_id}")
        action = ACTION_CATALOG[action_id]
        path = action["path"]
        if "{user_id}" in path:
            primary_user_id = (observations or {}).get("primary_user_id")
            if not is_positive_integer(primary_user_id):
                raise ActionValidationError(
                    "Action requires a positive integer user_id from successful user_control"
                )
            path = path.format(user_id=primary_user_id)
        url = self.base_url + path
        request_body = action.get("body")
        if request_body is not None:
            primary_user_id = (observations or {}).get("primary_user_id")

            def resolve_resource_tokens(value: Any) -> Any:
                if value == "{user_id}":
                    if not is_positive_integer(primary_user_id):
                        raise ActionValidationError(
                            "Request body requires a positive integer user_id from successful user_control"
                        )
                    return primary_user_id
                if isinstance(value, dict):
                    return {key: resolve_resource_tokens(item) for key, item in value.items()}
                if isinstance(value, list):
                    return [resolve_resource_tokens(item) for item in value]
                return value

            request_body = resolve_resource_tokens(request_body)

        started = time.perf_counter()
        self.initiated_requests += 1

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=False,
        ) as client:
            response = await client.request(
                method=action["method"],
                url=url,
                params=action["params"],
                json=request_body,
            )

        elapsed = time.perf_counter() - started
        self.completed_responses += 1

        body: Any
        try:
            body = response.json()
        except ValueError:
            body = response.text[:3000]

        return {
            "action_id": action_id,
            "method": action["method"],
            "url": str(response.request.url),
            "request_params": action.get("params", {}),
            "request_json": request_body,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body,
            "elapsed_seconds": round(elapsed, 6),
        }


# ============================================================
# VULNERABILITY DETECTOR AND CONTEXT
# ============================================================

class VulnerabilityDetector:
    """Detect only explicit, action-specific markers in the controlled synthetic lab."""

    # These are predefined benchmark-fixture tiers. They are not CVSS ratings.
    BENCHMARK_TIERS = {
        "BOLA": "High",
        "BROKEN_ADMIN_AUTH": "High",
        "MASS_ASSIGNMENT": "High",
        "SIMULATED_SQLI": "Medium",
        "SECRET_DISCLOSURE": "High",
        "SIMULATED_PATH_TRAVERSAL": "High",
        "OPEN_REDIRECT": "Medium",
        "CORS_MISCONFIGURATION": "High",
        "MISSING_SECURITY_HEADERS": "Low",
        "EXCESSIVE_DATA_EXPOSURE": "High",
        "VERBOSE_ERROR_DISCLOSURE": "Medium",
        "EXPOSED_INTERNAL_DOCUMENTATION": "Medium",
        "WEAK_PASSWORD_POLICY": "Medium",
        "INSECURE_JWT_CONFIGURATION": "High",
        "SIMULATED_SSRF": "High",
        "MISSING_RATE_LIMITING": "Medium",
        "SENSITIVE_CACHEABLE_RESPONSE": "Medium",
    }
    # Backwards-compatible alias; internal reporting uses BENCHMARK_TIERS.
    SEVERITIES = BENCHMARK_TIERS

    def detect(self, action_id: str, response: dict[str, Any]) -> list[dict[str, Any]]:
        body = response.get("body")
        if not isinstance(body, dict):
            body = {}
        raw_headers = response.get("headers") or {}
        headers = {str(k).lower(): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}
        status = response.get("status_code")
        findings: list[dict[str, Any]] = []

        def add(category: str, evidence: str) -> None:
            findings.append({
                "category": category,
                "title": category.replace("_", " ").title(),
                "benchmark_severity": self.BENCHMARK_TIERS.get(category, "Informational"),
                "benchmark_severity_definition": (
                    "Preassigned synthetic-benchmark tier used as fixture metadata; not the CVSS qualitative rating."
                ),
                "evidence": evidence,
                "action_id": action_id,
                "synthetic_lab": True,
            })

        marker = str(body.get("lab_marker", ""))

        if action_id == "bola_probe" and marker == "BOLA_CROSS_USER_PROFILE_ACCESS":
            if body.get("requester_id") != body.get("user_id") and body.get("email"):
                add("BOLA", "Cross-user profile data returned to requester_id different from user_id.")

        if action_id == "admin_access_probe" and marker == "ADMIN_METRICS_ACCESS_WITHOUT_AUTHORIZATION" and status == 200:
            add("BROKEN_ADMIN_AUTH", "Admin metrics returned to role=user.")

        if action_id == "mass_assignment_probe" and marker == "MASS_ASSIGNMENT_PRIVILEGED_ROLE_ACCEPTED" and body.get("role_after_update") == "admin":
            add("MASS_ASSIGNMENT", "The supplied privileged role field was accepted by the synthetic API.")

        if action_id == "injection_probe" and marker == "SIMULATED_SQL_INJECTION_PATTERN_ACCEPTED" and status == 200:
            add("SIMULATED_SQLI", "Synthetic injection marker returned by search; no SQL engine is accessed.")

        if action_id == "debug_probe" and marker == "DEBUG_SECRET_DISCLOSURE" and body.get("secret"):
            add("SECRET_DISCLOSURE", "Synthetic lab secret exposed by debug endpoint.")

        if action_id == "traversal_probe" and marker == "SIMULATED_PATH_TRAVERSAL_ACCEPTED" and body.get("simulated_content"):
            add("SIMULATED_PATH_TRAVERSAL", "Synthetic traversal marker returned; no real filesystem accessed.")

        if action_id == "redirect_probe":
            location = headers.get("location", "")
            if status in {301, 302, 303, 307, 308} and location.startswith("https://"):
                add("OPEN_REDIRECT", f"Synthetic API accepted an external redirect: {location}")

        if action_id == "cors_probe" and marker == "CORS_REFLECTS_UNTRUSTED_ORIGIN":
            origin = str(body.get("origin", ""))
            if (origin == "https://attacker.invalid"
                    and headers.get("access-control-allow-origin") == origin
                    and headers.get("access-control-allow-credentials", "").lower() == "true"):
                add("CORS_MISCONFIGURATION", "Untrusted Origin reflected while Access-Control-Allow-Credentials is true.")

        if action_id == "security_headers_probe" and marker == "MISSING_SECURITY_HEADERS_SIMULATION":
            required = ("content-security-policy", "x-content-type-options", "x-frame-options")
            missing = [name for name in required if name not in headers]
            if len(missing) >= 2:
                add("MISSING_SECURITY_HEADERS", "Missing baseline response headers: " + ", ".join(missing) + ".")

        if action_id == "data_exposure_probe" and marker == "EXCESSIVE_SYNTHETIC_DATA_EXPOSURE":
            records = body.get("records")
            if isinstance(records, list) and any(isinstance(row, dict) and row.get("api_key") for row in records):
                add("EXCESSIVE_DATA_EXPOSURE", "Bulk user export exposes synthetic API-key fields beyond ordinary profile data.")

        if action_id == "error_disclosure_probe" and marker == "VERBOSE_SYNTHETIC_ERROR_DISCLOSURE" and status == 500 and body.get("stack_trace"):
            add("VERBOSE_ERROR_DISCLOSURE", "Synthetic HTTP 500 response exposed internal stack details.")

        if action_id == "internal_docs_probe" and marker == "INTERNAL_DOCUMENTATION_EXPOSED":
            routes = body.get("internal_routes")
            if isinstance(routes, list) and routes:
                add("EXPOSED_INTERNAL_DOCUMENTATION", "Internal-only route names were returned without authentication in the synthetic lab.")

        if action_id == "weak_password_policy_probe" and marker == "SHORT_PASSWORD_ACCEPTED":
            if body.get("registered") is True and body.get("password_length", 99) < 8:
                add("WEAK_PASSWORD_POLICY", "Synthetic registration accepted a password shorter than eight characters.")

        if action_id == "jwt_config_probe" and marker == "JWT_ALGORITHM_NONE_ENABLED":
            algorithms = body.get("accepted_algorithms")
            if isinstance(algorithms, list) and "none" in [str(item).lower() for item in algorithms]:
                add("INSECURE_JWT_CONFIGURATION", "Synthetic auth configuration advertises the JWT none algorithm.")

        if action_id == "ssrf_probe" and marker == "SIMULATED_SSRF_INTERNAL_RESOURCE_RESOLVED":
            if body.get("simulated_only") is True and body.get("requested_host") == "internal.lab":
                add("SIMULATED_SSRF", "Synthetic URL preview resolved an internal host marker; no outbound network call occurred.")

        if action_id == "rate_limit_probe" and marker == "NO_RATE_LIMIT_ENFORCEMENT_IN_LAB" and body.get("rate_limit_enforced") is False:
            add("MISSING_RATE_LIMITING", "Synthetic lab endpoint explicitly reports that rate-limit enforcement is disabled.")

        if action_id == "cache_control_probe" and marker == "SENSITIVE_RESPONSE_PUBLICLY_CACHEABLE":
            cache_control = headers.get("cache-control", "").lower()
            if "public" in cache_control and body.get("report"):
                add("SENSITIVE_CACHEABLE_RESPONSE", f"Synthetic sensitive report returned with Cache-Control: {cache_control}.")

        return findings


class ContextManager:
    def __init__(self) -> None:
        self.observations: dict[str, Any] = {
            "api_discovered": False,
            "known_user_ids": [],
            "primary_user_id": None,
            "tested_actions": [],
            "successful_actions": [],
            "failed_actions": [],
            "skipped_actions": [],
            "confirmed_findings": [],
            "remaining_findings": sorted(TARGET_FINDINGS),
            "last_status_code": None,
            "last_action": None,
            "last_error": None,
        }
        self.history: list[dict[str, Any]] = []

    @staticmethod
    def _response_means_action_successful(
        action_id: str, response: dict[str, Any]
    ) -> bool:
        status_code = response.get("status_code")
        body = response.get("body")
        # An intentional synthetic 500 is a successful execution of this probe,
        # but it must never be treated as a successful prerequisite for other actions.
        if action_id == "error_disclosure_probe":
            return (
                status_code == 500
                and isinstance(body, dict)
                and body.get("lab_marker") == "VERBOSE_SYNTHETIC_ERROR_DISCLOSURE"
                and bool(body.get("stack_trace"))
            )
        if type(status_code) is not int or not 200 <= status_code < 400:
            return False
        # Prerequisites are semantically verified, not unlocked by any arbitrary 2xx.
        if action_id == "health_check":
            return 200 <= status_code < 300 and isinstance(body, dict) and body.get("status") == "ok"
        if action_id == "user_control":
            return (
                200 <= status_code < 300
                and isinstance(body, dict)
                and is_positive_integer(body.get("id"))
            )
        return True

    def _snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self.observations, ensure_ascii=False))

    def update(
        self,
        action_id: str,
        response: dict[str, Any],
        new_findings: list[dict[str, Any]],
    ) -> None:
        self.observations["api_discovered"] = True
        self.observations["last_action"] = action_id
        self.observations["last_status_code"] = response.get("status_code")
        self.observations["last_error"] = None
        if action_id not in self.observations["tested_actions"]:
            self.observations["tested_actions"].append(action_id)

        if self._response_means_action_successful(action_id, response):
            if action_id not in self.observations["successful_actions"]:
                self.observations["successful_actions"].append(action_id)
            if action_id in self.observations["failed_actions"]:
                self.observations["failed_actions"].remove(action_id)
        elif action_id not in self.observations["failed_actions"]:
            self.observations["failed_actions"].append(action_id)

        confirmed = set(self.observations["confirmed_findings"])
        for finding in new_findings:
            confirmed.add(finding["category"])
        self.observations["confirmed_findings"] = sorted(confirmed)
        self.observations["remaining_findings"] = sorted(TARGET_FINDINGS - confirmed)

        body = response.get("body")
        status_code = response.get("status_code")
        if action_id == "user_control":
            primary_id = body.get("id") if isinstance(body, dict) else None
            self.observations["primary_user_id"] = (
                primary_id
                if self._response_means_action_successful(action_id, response)
                and is_positive_integer(primary_id)
                else None
            )
        if isinstance(body, dict) and type(status_code) is int and 200 <= status_code < 300:
            listed_users = body.get("users")
            if isinstance(listed_users, list):
                known_ids = self.observations["known_user_ids"]
                for item in listed_users:
                    listed_id = item.get("id") if isinstance(item, dict) else None
                    if is_positive_integer(listed_id) and listed_id not in known_ids:
                        known_ids.append(listed_id)
            discovered_id = body.get("user_id")
            if discovered_id is None and action_id == "user_control":
                discovered_id = body.get("id")
            if is_positive_integer(discovered_id):
                known_ids = self.observations["known_user_ids"]
                if action_id == "user_control":
                    # Only successful user_control may establish the primary resource.
                    if discovered_id in known_ids:
                        known_ids.remove(discovered_id)
                    known_ids.insert(0, discovered_id)
                elif discovered_id not in known_ids:
                    known_ids.append(discovered_id)

        self.history.append({
            "action_id": action_id,
            "request": {
                "method": response.get("method"),
                "url": response.get("url"),
                "params": response.get("request_params", {}),
                "json": response.get("request_json"),
            },
            "status_code": response.get("status_code"),
            "response_headers": response.get("headers", {}),
            "response_body": body,
            "elapsed_seconds": response.get("elapsed_seconds"),
            "new_findings": new_findings,
            "observations_after_action": self._snapshot(),
        })

    def record_skipped(
        self,
        action_id: str,
        reason: str,
        request_template: dict[str, Any] | None = None,
    ) -> None:
        """Record that a planned action was blocked before HTTP execution."""
        self.observations["last_action"] = action_id
        self.observations["last_error"] = reason
        if action_id == "user_control":
            self.observations["primary_user_id"] = None
        if action_id not in self.observations["skipped_actions"]:
            self.observations["skipped_actions"].append(action_id)
        self.history.append({
            "action_id": action_id,
            "request": request_template or {},
            "status_code": None,
            "response_headers": {},
            "response_body": None,
            "skipped": True,
            "error": reason,
            "new_findings": [],
            "observations_after_action": self._snapshot(),
        })

    def record_failure(
        self,
        action_id: str,
        error: str,
        request_template: dict[str, Any] | None = None,
    ) -> None:
        """Preserve a failed attempt so subsequent decisions see it in context."""
        self.observations["last_action"] = action_id
        self.observations["last_status_code"] = None
        self.observations["last_error"] = error
        if action_id == "user_control":
            self.observations["primary_user_id"] = None
        if action_id not in self.observations["tested_actions"]:
            self.observations["tested_actions"].append(action_id)
        if action_id not in self.observations["failed_actions"]:
            self.observations["failed_actions"].append(action_id)
        self.history.append({
            "action_id": action_id,
            "request": request_template or {},
            "status_code": None,
            "response_headers": {},
            "response_body": None,
            "error": error,
            "new_findings": [],
            "observations_after_action": self._snapshot(),
        })


# ============================================================
# LLM SELECTOR
# ============================================================

def get_plan_horizon() -> int:
    """Read the short planning horizon (default three; hard bound one to three)."""
    raw = os.getenv("PENTELLIGENT_PLAN_HORIZON", "3")
    try:
        horizon = int(raw)
    except ValueError as exc:
        raise ValueError("PENTELLIGENT_PLAN_HORIZON must be an integer from 1 to 3") from exc
    if not 1 <= horizon <= 3:
        raise ValueError("PENTELLIGENT_PLAN_HORIZON must be between 1 and 3")
    return horizon


class ActionSelector:
    """Context-adaptive intent selection with locally enforced execution safety.

    Each decision presents the LLM with the full meaningful choice set: every
    unresolved, recoverable finding probe plus useful reconnaissance actions. A
    separate, cached qualitative severity estimate may inform the decision. The
    scenario-reference CVSS baseline is retained for post-run comparison only: no
    CVSS vector or score is sent to the action-selection prompt or used as a gate.
    Prerequisite scheduling, validation, and HTTP execution remain deterministic.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.errors = 0
        self.fallbacks = 0
        self.plan_horizon = get_plan_horizon()
        # Recoveries are not fallbacks: the model must have emitted a complete,
        # allowlisted action_id before any truncation. Keep them separately so
        # the report remains transparent about imperfect model output.
        self.response_recoveries = 0
        self.traces: list[dict[str, Any]] = []
        # The priority rubric is deterministic and local. An optional profile path
        # carries historical LLM proposals for audit, but its scores are rebuilt from
        # the current reference vectors on load. This avoids bootstrapping scores
        # from a generic model response when no profile path is configured.
        self.cvss_profile_path = os.getenv("PENTELLIGENT_CVSS_PROFILE_FILE")
        self.cvss_profile = (
            load_cvss_profile(self.cvss_profile_path, OLLAMA_MODEL)
            if self.cvss_profile_path
            else build_cvss_reference_profile(OLLAMA_MODEL)
        )
        self.cvss_assessments: dict[str, dict[str, Any]] = self.cvss_profile.get("assessments", {})
        self.cvss_priority_order: list[str] = list(self.cvss_profile.get("priority_order", []))
        if set(self.cvss_assessments) != set(_cvss_action_ids()):
            raise ValueError(
                "A complete local scenario-reference CVSS baseline is required for reporting; "
                "the action selector will never request CVSS vectors from the selection LLM."
            )
        self.llm_risk_profile_path = os.getenv("PENTELLIGENT_LLM_RISK_PROFILE_FILE")
        self.llm_risk_profile: dict[str, Any] = (
            load_llm_risk_profile(self.llm_risk_profile_path, OLLAMA_MODEL)
            if self.llm_risk_profile_path else {}
        )
        self.llm_risk_assessments: dict[str, dict[str, Any]] = self.llm_risk_profile.get("assessments", {})

    @staticmethod
    def _needed_prerequisites(
        remaining: set[str], executed: list[str], successful: set[str]
    ) -> set[str]:
        """Return transitively required, unresolved prerequisite action IDs."""
        needed: set[str] = set()
        visited: set[str] = set()
        stack = [
            action_id for action_id, definition in ACTION_CATALOG.items()
            if action_id not in executed and definition.get("finding") in remaining
        ]
        while stack:
            action_id = stack.pop()
            if action_id in visited:
                continue
            visited.add(action_id)
            for dependency in ACTION_CATALOG.get(action_id, {}).get("requires", []):
                if dependency in successful:
                    continue
                if dependency not in executed:
                    needed.add(dependency)
                    stack.append(dependency)
        return needed

    @staticmethod
    def _prerequisites_are_resolvable(
        action_id: str,
        context: ContextManager,
        executed: set[str],
        visiting: set[str] | None = None,
    ) -> bool:
        """True when missing prerequisites have not already irrecoverably failed."""
        visiting = set() if visiting is None else visiting
        if action_id in visiting:
            return False  # dependency cycle
        visiting.add(action_id)
        successful = set(context.observations.get("successful_actions", []))
        failed = set(context.observations.get("failed_actions", [])) | set(context.observations.get("skipped_actions", []))
        for dependency in ACTION_CATALOG[action_id].get("requires", []):
            if dependency in successful:
                continue
            if dependency in executed or dependency in failed:
                return False
            if not ActionSelector._prerequisites_are_resolvable(dependency, context, executed, visiting.copy()):
                return False
        if ACTION_CATALOG[action_id].get("resource_id_key") and not is_positive_integer(
            context.observations.get("primary_user_id")
        ):
            source_action = "user_control"
            if source_action in successful:
                # A successful source action must have produced a valid ID. If
                # this invariant is violated, do not pretend the resource can be resolved.
                return False
            if source_action in executed or source_action in failed:
                return False
            if not ActionSelector._prerequisites_are_resolvable(source_action, context, executed, visiting.copy()):
                return False
        return True

    def _fallback(
        self,
        remaining: set[str],
        available: list[str],
        executed: list[str],
        successful: set[str] | None = None,
        context: ContextManager | None = None,
    ) -> str:
        """Diagnostic-only intent fallback; dependencies are resolved by the engine."""
        if context is not None:
            successful_actions = successful or set(context.observations.get("successful_actions", []))
        else:
            successful_actions = successful or set()
        needed = self._needed_prerequisites(remaining, executed, successful_actions)
        # Select an unresolved target intent even when it is blocked right now.
        # The dependency planner, not the fallback, decides what can execute next.
        for action_id in available:
            if ACTION_CATALOG[action_id].get("finding") in remaining:
                self.fallbacks += 1
                return action_id
        for action_id in available:
            if action_id in needed:
                self.fallbacks += 1
                return action_id
        for action_id in available:
            if ACTION_CATALOG[action_id].get("adaptive_candidate"):
                self.fallbacks += 1
                return action_id
        return ""

    async def select(
        self,
        context: ContextManager,
        executed: list[str],
    ) -> tuple[str | None, dict[str, Any]]:
        remaining = set(context.observations.get("remaining_findings", []))
        successful = set(context.observations.get("successful_actions", []))
        executed_set = set(executed)
        candidate_ids: list[str] = []
        for action_id, definition in ACTION_CATALOG.items():
            if action_id in executed_set:
                continue
            finding = definition.get("finding")
            unresolved_probe = finding is not None and finding in remaining
            useful_recon = (
                definition.get("action_type") == "reconnaissance"
                and bool(definition.get("adaptive_candidate"))
            )
            if not (unresolved_probe or useful_recon):
                continue
            if not self._prerequisites_are_resolvable(action_id, context, executed_set):
                continue
            candidate_ids.append(action_id)

        base_trace: dict[str, Any] = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "model": OLLAMA_MODEL,
            "llm_request_made": False,
            "prompt_text_sent": None,
            "prompt_context": None,
            "raw_model_response": None,
            "partial_model_response": None,
            "parsed_model_response": None,
            "ollama_metrics": None,
            "error": None,
            "selected_action": None,
            "selection_source": "none",
            "model_proposal_valid": None,
            "model_proposal_appropriate": None,
            "candidate_count": len(candidate_ids),
        }

        if not remaining:
            base_trace["reason"] = "All target finding categories are already confirmed."
            base_trace["selection_source"] = "none"
            self.traces.append(base_trace)
            return None, base_trace

        if not candidate_ids:
            base_trace["error"] = "No unresolved feasible finding, prerequisite, or useful reconnaissance action remains."
            self.traces.append(base_trace)
            return None, base_trace

        # Skip generation only if there is literally one meaningful candidate left.
        # A unique highest CVSS score is NOT a singleton: lower-scored probes and
        # reconnaissance still remain available to the LLM for context-aware choice.
        if len(candidate_ids) == 1:
            selected = candidate_ids[0]
            definition = ACTION_CATALOG[selected]
            role = "finding_probe" if definition.get("finding") in remaining else "reconnaissance"
            base_trace.update({
                "selected_action": selected,
                "proposed_action": selected,
                "selection_source": "single_candidate",
                "selected_action_role": role,
                "decision_method": "only_feasible_meaningful_intent",
                "reason": "Only one meaningful, recoverable action intent remains; no strategic choice is available.",
                "model_proposal_valid": True,
                "model_proposal_appropriate": True,
                "candidate_count": 1,
                "plan_horizon": self.plan_horizon,
                "planned_actions": [{"action_id": selected, "reason": "Only feasible meaningful action remains."}],
                "plan_length": 1,
                "plan_method": "single_candidate_no_model_call",
            })
            self.traces.append(base_trace)
            return selected, base_trace

        # Keep the model input intentionally small. The full request/response history
        # remains in the JSON/JSONL artifacts; repeating it in every generation call
        # made small local models spend minutes evaluating prompt tokens before they
        # emitted their first streamed chunk.
        recent_history: list[dict[str, Any]] = []
        for item in context.history[-3:]:
            response_body = item.get("response_body")
            response_summary: dict[str, Any] = {}
            if isinstance(response_body, dict):
                for key in (
                    "status", "id", "user_id", "requester_id", "finding", "lab_marker",
                    "username", "role", "requested_role", "registered", "valid",
                    "accepted_algorithms", "rate_limit_enforced", "detail",
                ):
                    if key in response_body:
                        value = response_body[key]
                        if isinstance(value, (str, int, float, bool)) or value is None:
                            response_summary[key] = str(value)[:100] if isinstance(value, str) else value
                if isinstance(response_body.get("users"), list):
                    response_summary["user_ids"] = [
                        row.get("id") for row in response_body["users"]
                        if isinstance(row, dict) and row.get("id") is not None
                    ][:8]
            headers = item.get("response_headers") or {}
            if isinstance(headers, dict):
                lowered = {str(k).lower(): v for k, v in headers.items()}
                for key in (
                    "location", "access-control-allow-origin",
                    "access-control-allow-credentials", "cache-control",
                ):
                    if key in lowered:
                        response_summary[key] = str(lowered[key])[:100]
            recent_history.append({
                "action_id": item.get("action_id"),
                "status_code": item.get("status_code"),
                "error": str(item.get("error") or "")[:100] or None,
                "skipped": bool(item.get("skipped", False)),
                "finding_categories": [
                    finding.get("category") for finding in (item.get("new_findings") or [])
                    if isinstance(finding, dict) and finding.get("category")
                ][:5],
                "response_summary": response_summary,
            })

        compact_state = {
            "api_discovered": bool(context.observations.get("api_discovered")),
            "primary_user_id": context.observations.get("primary_user_id"),
            "successful_prerequisites": sorted(set(successful) & {
                dependency for definition in ACTION_CATALOG.values()
                for dependency in definition.get("requires", [])
            }),
            "failed_prerequisites": sorted(set(context.observations.get("failed_actions", [])) & {
                dependency for definition in ACTION_CATALOG.values()
                for dependency in definition.get("requires", [])
            }),
            "last_status_code": context.observations.get("last_status_code"),
            "last_action": context.observations.get("last_action"),
            "last_error": str(context.observations.get("last_error") or "")[:60] or None,
        }

        # A complete local baseline was validated in __init__. It is never a
        # responsibility of this action-selection call to propose CVSS vectors.
        # Give the model the full meaningful candidate set plus human-authored
        # impact context and independent qualitative estimates. CVSS score/vector
        # data are intentionally absent from the prompt. Candidate rows retain
        # stable catalogue order to avoid severity-rank position bias.
        candidate_actions: list[dict[str, Any]] = []
        for action_id in candidate_ids:
            definition = ACTION_CATALOG[action_id]
            finding = definition.get("finding")
            risk_assessment = self.llm_risk_assessments.get(action_id) if finding else None
            unmet_dependencies = [
                dependency for dependency in definition.get("requires", [])
                if dependency not in successful and dependency != "health_check"
            ]
            # Short JSON keys are intentional: the complete history is in the
            # artifact, while this repeated per-candidate prompt must fit in a small
            # local-model context window without cutting the important impact cue.
            row: dict[str, Any] = {
                "id": action_id,
                "finding": finding,
                "d": _compact_prompt_text(definition.get("description", ""), 48),
            }
            if finding:
                row["impact"] = _compact_prompt_text(
                    LLM_ACTION_IMPACT_HINTS.get(action_id, LLM_RISK_SCENARIO_CONTEXT.get(action_id, "")), 58
                )
            else:
                row["why"] = _compact_prompt_text(
                    LLM_RECON_DECISION_HINTS.get(action_id, "Use only if it materially improves the next decision."), 58
                )
            # Independent qualitative estimates are generated once and cached.
            # Deliberately do NOT put the CVSS vector or reference score into this
            # prompt: the model must not merely copy/anchor to the baseline.
            if risk_assessment:
                # Short field names keep every repeated candidate row compact
                # enough for a small model's configured context window.
                row["severity"] = risk_assessment.get("severity_estimate")
                row["confidence"] = risk_assessment.get("confidence")
                # Give the selector the compact basis for the band so it can weigh
                # the uncertainty/caveat rather than treating a label as ground truth.
                row["risk_basis"] = str(risk_assessment.get("rationale", ""))[:40]
            if unmet_dependencies:
                row["needs"] = unmet_dependencies
            candidate_actions.append(row)

        prompt_candidate_ids = [str(row["id"]) for row in candidate_actions]
        prompt_context = {
            "task": "adaptive_short_horizon_plan",
            "goal": "Plan the next few safe synthetic API testing intents from current state, not a fixed sequence.",
            "planning_horizon": self.plan_horizon,
            "selection_policy": [
                "All listed candidates are eligible; CVSS scores/vectors are not supplied.",
                "Balance plausible impact, evidence, uncovered findings, information gain, and dependency cost; do not just sort by a label.",
                "Test plausible auth bypass, privilege escalation, injection, sensitive-data exposure, or internal-service access early when context supports it.",
                "Prefer direct finding probes. Recon is for decision-changing uncertainty, not merely because it is available.",
                "At most one recon per plan, last; if recon is first, return it alone.",
                "Synthetic markers are evidence about this lab, not proof of identical real-world impact.",
            ],
            "state": compact_state,
            "recent": [
                {
                    "a": item.get("action_id"),
                    "s": item.get("status_code"),
                    "error": str(item.get("error") or "")[:45] or None,
                    "findings": [finding.get("category") for finding in (item.get("new_findings") or []) if isinstance(finding, dict)][:3],
                    "skipped": bool(item.get("skipped", False)),
                    "response": item.get("response_summary", {}),
                }
                for item in recent_history[-3:]
            ],
            "confirmed": sorted(context.observations.get("confirmed_findings", [])),
            "remaining": sorted(remaining),
            "llm_severity_profile_available": bool(self.llm_risk_assessments),
            "candidate_actions": candidate_actions,
            "candidate_count": len(candidate_actions),
            "rules": [
                "Use only candidate action IDs; never invent or repeat an ID.",
                "Return up to three distinct intents in order, with short reasons; use fewer only when justified.",
                'JSON only: {"plan":[{"action_id":"candidate id","reason":"brief reason <=80 chars"}]}.',
            ],
        }
        system_prompt = (
            "Choose an impact-aware short plan from all candidates; no CVSS data are supplied. "
            "Prefer direct consequential probes over routine recon. Up to 3 unique actions, brief reasons, JSON only.\n\n"
        )

        prompt_context_snapshot = deepcopy(prompt_context)
        prompt_text = system_prompt + json.dumps(
            prompt_context, ensure_ascii=False, separators=(",", ":")
        )
        prompt_estimated_tokens = max(1, (len(prompt_text) + 3) // 4)
        base_trace.update({
            "llm_request_made": True,
            "prompt_text_sent": prompt_text,
            "prompt_context": prompt_context_snapshot,
            "prompt_characters": len(prompt_text),
            "prompt_estimated_tokens": prompt_estimated_tokens,
            "ollama_context_window": OLLAMA_NUM_CTX,
            "candidate_action_ids_available_locally": list(candidate_ids),
            "candidate_action_ids_sent_to_model": list(prompt_candidate_ids),
            "planning_horizon": self.plan_horizon,
            "cvss_scoring_required": False,
            "cvss_scores_disclosed_to_selector": False,
            "llm_risk_profile_available": bool(self.llm_risk_assessments),
            "candidate_model_risk_assessments": {
                action_id: {
                    "severity_estimate": self.llm_risk_assessments[action_id].get("severity_estimate"),
                    "confidence": self.llm_risk_assessments[action_id].get("confidence"),
                }
                for action_id in prompt_candidate_ids if action_id in self.llm_risk_assessments
            },
        })

        # Ollama JSON Schema constrains a short ordered plan to allowlisted IDs.
        # The plan is bounded to three intents so output stays within small-model budgets.
        response_format: str | dict[str, Any] = {
            "type": "object",
            "properties": {
                "plan": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": min(self.plan_horizon, len(prompt_candidate_ids)),
                    "items": {
                        "type": "object",
                        "properties": {
                            "action_id": {"type": "string", "enum": prompt_candidate_ids},
                            "reason": {"type": "string", "minLength": 1, "maxLength": 80},
                        },
                        "required": ["action_id", "reason"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["plan"],
            "additionalProperties": False,
        }
        self.calls += 1
        llm_started = time.perf_counter()
        response_fragments: list[str] = []
        ollama_metrics: dict[str, Any] = {}
        done_seen = False
        try:
            timeout = httpx.Timeout(
                timeout=OLLAMA_TIMEOUT,
                connect=min(10.0, OLLAMA_TIMEOUT),
                read=OLLAMA_TIMEOUT,
                write=min(30.0, OLLAMA_TIMEOUT),
                pool=min(10.0, OLLAMA_TIMEOUT),
            )
            request_payload = {
                "model": OLLAMA_MODEL,
                "prompt": prompt_text,
                "stream": True,
                "format": response_format,
                "keep_alive": os.getenv("OLLAMA_KEEP_ALIVE", "30m"),
                "options": {
                    "temperature": 0,
                    "num_predict": 192,
                    "num_ctx": OLLAMA_NUM_CTX,
                },
            }
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream("POST", f"{OLLAMA_URL}/api/generate", json=request_payload) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        chunk = json.loads(line)
                        if not isinstance(chunk, dict):
                            raise ValueError("Ollama stream chunk must be a JSON object")
                        if chunk.get("error"):
                            raise ValueError(f"Ollama generation error: {chunk['error']}")
                        fragment = chunk.get("response", "")
                        if isinstance(fragment, str) and fragment:
                            response_fragments.append(fragment)
                        for key in ("total_duration", "load_duration", "prompt_eval_count", "eval_count", "done_reason"):
                            if key in chunk:
                                ollama_metrics[key] = chunk[key]
                        if chunk.get("done") is True:
                            done_seen = True
            generated = "".join(response_fragments)
            base_trace["partial_model_response"] = generated or None
            if not done_seen:
                raise ValueError("Ollama stream ended without a final done=true chunk")
            if not generated.strip():
                raise ValueError("Ollama returned an empty generated response")
            base_trace["raw_model_response"] = generated
            base_trace["ollama_metrics"] = ollama_metrics
            try:
                parsed = json.loads(generated)
                base_trace["model_response_json_valid"] = True
                base_trace["partial_model_response"] = None
            except json.JSONDecodeError:
                match = None
                if ollama_metrics.get("done_reason") == "length":
                    match = re.match(
                        r'^\s*\{\s*"plan"\s*:\s*\[\s*\{\s*"action_id"\s*:\s*"([A-Za-z0-9_-]+)"\s*,',
                        generated,
                    )
                    if not match:
                        match = re.match(
                            r'^\s*\{\s*"action_id"\s*:\s*"([A-Za-z0-9_-]+)"\s*,',
                            generated,
                        )
                recovered_action = match.group(1) if match else None
                if recovered_action not in prompt_candidate_ids:
                    raise
                parsed = {
                    "plan": [{
                        "action_id": recovered_action,
                        "reason": "Truncated response; replan after this intent.",
                    }],
                }
                self.response_recoveries += 1
                base_trace.update({
                    "model_response_json_valid": False,
                    "model_response_recovered": True,
                    "model_response_recovery_kind": "complete_action_id_before_truncated_json",
                    "model_response_recovery_note": (
                        "Ollama stopped at the generation limit after emitting a complete, allowlisted action_id. "
                        "Only that identifier was accepted; the incomplete rationale was discarded."
                    ),
                    # Preserve the incomplete text for audit rather than hiding it.
                    "partial_model_response": generated,
                })
            if not isinstance(parsed, dict):
                raise ValueError("LLM output must be a JSON object")
            base_trace["parsed_model_response"] = parsed
            legacy_response = False
            raw_plan = parsed.get("plan")
            legacy_key = None
            legacy_action = parsed.get("action_id")
            if not isinstance(legacy_action, str) and isinstance(parsed.get("selected_action"), str):
                legacy_action = parsed["selected_action"]
                legacy_key = "selected_action"
            elif isinstance(legacy_action, str):
                legacy_key = "action_id"
            if raw_plan is None and isinstance(legacy_action, str):
                raw_plan = [{"action_id": legacy_action, "reason": parsed.get("reason", "Legacy single-action response.")}]
                legacy_response = True
                base_trace["legacy_response_key_used"] = legacy_key
            else:
                base_trace["legacy_response_key_used"] = None
            if not isinstance(raw_plan, list) or not raw_plan:
                raise ValueError("LLM plan must be a non-empty list")
            if len(raw_plan) > min(self.plan_horizon, len(prompt_candidate_ids)):
                raise ValueError("LLM plan exceeds the configured planning horizon")
            validated_plan: list[dict[str, str]] = []
            seen_plan_ids: set[str] = set()
            for position, item in enumerate(raw_plan, start=1):
                if not isinstance(item, dict):
                    raise ValueError(f"Plan item {position} must be a JSON object")
                action_id = item.get("action_id")
                reason = item.get("reason", "")
                if not isinstance(action_id, str) or action_id not in prompt_candidate_ids:
                    raise ValueError(f"Plan item {position} contains a non-candidate action_id")
                if action_id in seen_plan_ids:
                    raise ValueError(f"LLM plan repeats action_id {action_id!r}")
                if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 120:
                    raise ValueError(f"Plan item {position} reason must contain 1-120 characters")
                seen_plan_ids.add(action_id)
                validated_plan.append({"action_id": action_id, "reason": " ".join(reason.split())[:120]})

            # Reconnaissance can reveal new context, so never queue later actions
            # behind a recon item. If the model puts recon first, honor that choice
            # but reduce it to a one-item plan; if it puts recon after probes, retain
            # the probes and keep recon last. This avoids knowingly creating a stale
            # tail that the runner would immediately discard after recon executes.
            model_plan_length_before_policy = len(validated_plan)
            recon_positions = [
                i for i, item in enumerate(validated_plan)
                if ACTION_CATALOG[item["action_id"]].get("action_type") == "reconnaissance"
            ]
            plan_policy_adjustments: list[dict[str, Any]] = []
            if recon_positions:
                first_recon = recon_positions[0]
                kept_length = 1 if first_recon == 0 else first_recon + 1
                for removed in validated_plan[kept_length:]:
                    plan_policy_adjustments.append({
                        "action_id": removed["action_id"],
                        "reason": "reconnaissance_must_be_last_or_standalone",
                    })
                if kept_length < len(validated_plan):
                    validated_plan = validated_plan[:kept_length]
            proposed = validated_plan[0]["action_id"]
            parsed_reason = validated_plan[0]["reason"]
            base_trace["proposed_action"] = proposed
            base_trace["proposed_plan"] = validated_plan
            base_trace["legacy_single_action_response"] = legacy_response
            base_trace["reason"] = (
                "Recovered complete allowlisted action_id; rationale was truncated and remaining plan discarded."
                if base_trace.get("model_response_recovered") else parsed_reason
            )
            if not isinstance(proposed, str) or proposed not in prompt_candidate_ids:
                base_trace["model_proposal_valid"] = False
                base_trace["model_proposal_appropriate"] = False
                raise ValueError("LLM selected an action outside the candidate action-intent allowlist")
            if set(self.cvss_assessments) != set(_cvss_action_ids()):
                raise ValueError("The local CVSS reference baseline is incomplete; no LLM CVSS fallback is permitted")

            proposed_definition = ACTION_CATALOG[proposed]
            proposed_finding = proposed_definition.get("finding")
            proposed_is_unresolved_probe = proposed_finding is not None and proposed_finding in remaining
            proposed_is_useful_recon = proposed_definition.get("action_type") == "reconnaissance"
            appropriate = proposed_is_unresolved_probe or proposed_is_useful_recon

            # The LLM's valid candidate choice is honored. Local code validates its
            # identity and handles dependencies, but does not silently replace a
            # context-sensitive proposal merely because its CVSS reference score is
            # below another candidate's score.
            selected = proposed
            definition = ACTION_CATALOG[selected]
            finding = definition.get("finding")
            is_unresolved_probe = finding is not None and finding in remaining
            selected_assessment = self.cvss_assessments.get(selected, {})
            selected_score = selected_assessment.get("base_score")
            sorted_scored_probes = sorted(
                [
                    action_id for action_id in candidate_ids
                    if ACTION_CATALOG[action_id].get("finding") in remaining
                    and action_id in self.cvss_assessments
                ],
                key=lambda action_id: (
                    -float(self.cvss_assessments[action_id]["base_score"]),
                    self.cvss_priority_order.index(action_id) if action_id in self.cvss_priority_order else 10_000,
                ),
            )
            selected_rank = sorted_scored_probes.index(selected) + 1 if selected in sorted_scored_probes else None
            base_trace.update({
                "model_proposal_valid": True,
                "model_proposal_appropriate": appropriate,
            "model_response_recovered": bool(base_trace.get("model_response_recovered", False)),
                "proposal_target_type": "finding_probe" if proposed_is_unresolved_probe else "reconnaissance",
                "selected_action": selected,
                "selection_source": "llm",
                "selected_action_role": "finding_probe" if is_unresolved_probe else "reconnaissance",
                "planned_actions": validated_plan,
                "plan_length": len(validated_plan),
                "model_plan_length_before_local_policy": model_plan_length_before_policy,
                "plan_policy_adjustments": plan_policy_adjustments,
                "plan_items_removed_by_local_policy": len(plan_policy_adjustments),
                "plan_horizon": self.plan_horizon,
                "plan_method": "llm_short_horizon_ordered_intents",
                "plan_recovered_from_truncation": bool(base_trace.get("model_response_recovered")),
                "selected_action_unmet_prerequisites": [
                    dependency for dependency in definition.get("requires", [])
                    if dependency not in successful
                ],
                "cvss_reference_score_for_model_proposal": self.cvss_assessments.get(proposed, {}).get("base_score"),
                "selected_cvss_score": selected_score,
                "selected_cvss_reference_rank": selected_rank,
                "candidate_count": len(prompt_candidate_ids),
                "highest_available_cvss_score": max(
                    (float(self.cvss_assessments[action_id]["base_score"]) for action_id in sorted_scored_probes),
                    default=None,
                ),
                "cvss_priority_guard_applied": False,
                "cvss_remaining_priority_order": sorted_scored_probes,
                "llm_request_elapsed_seconds": round(time.perf_counter() - llm_started, 6),
            })
            self.traces.append(base_trace)
            return selected, base_trace

        except (httpx.HTTPError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            self.errors += 1
            partial = "".join(response_fragments)
            if partial:
                base_trace["partial_model_response"] = partial
            base_trace["error"] = f"{type(exc).__name__}: {exc}"
            if isinstance(exc, httpx.ReadTimeout):
                base_trace["error_diagnostic"] = (
                    f"Ollama sent no stream data within {OLLAMA_TIMEOUT:g}s; "
                    f"prompt was {len(prompt_text)} chars (~{max(1, (len(prompt_text) + 3) // 4)} estimated tokens). "
                    "Check model load, available RAM/VRAM, and Ollama logs if this persists."
                )
            base_trace["model_proposal_valid"] = False
            base_trace["model_proposal_appropriate"] = False
            fallback_enabled = os.getenv("PENTELLIGENT_ALLOW_FALLBACK", "1").strip().lower() in {"1", "true", "yes", "on"}
            if fallback_enabled:
                selected = self._fallback(remaining, candidate_ids, executed, successful, context)
                base_trace["selected_action"] = selected or None
                base_trace["selection_source"] = "fallback" if selected else "none"
                base_trace["selected_action_role"] = ACTION_CATALOG[selected].get("action_type") if selected else "none"
                base_trace["planned_actions"] = ([{"action_id": selected, "reason": "Explicit diagnostic fallback after model error."}] if selected else [])
                base_trace["plan_length"] = 1 if selected else 0
                base_trace["plan_horizon"] = self.plan_horizon
                base_trace["plan_method"] = "diagnostic_fallback"
                base_trace["fallback_enabled"] = True
            else:
                selected = ""
                base_trace["selected_action"] = None
                base_trace["selection_source"] = "none"
                base_trace["selected_action_role"] = "none"
                base_trace["fallback_enabled"] = False
                base_trace["fallback_suppressed"] = True
            base_trace["llm_request_elapsed_seconds"] = round(time.perf_counter() - llm_started, 6)
            self.traces.append(base_trace)
            return selected or None, base_trace


# ============================================================
# EXPERIMENT ENGINE
# ============================================================

# All engine instances share the same lock because the synthetic API state is
# process-global. This prevents concurrent benchmark requests from resetting
# or changing the lab state in the middle of another experiment.
_EXPERIMENT_LOCK = asyncio.Lock()

class PentelligentEngine:
    def __init__(self) -> None:
        self.executor = HTTPExecutor()
        self.validator = ActionValidator()
        self.detector = VulnerabilityDetector()
        self.selector = ActionSelector()
        self.run_lock = _EXPERIMENT_LOCK

    async def reset_target(self, scenario: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{API_BASE}/lab/reset",
                params={"scenario": scenario},
            )
            response.raise_for_status()
            body = response.json()
        if not isinstance(body, dict) or body.get("reset") is not True or body.get("scenario") != scenario:
            raise RuntimeError("Synthetic API did not confirm the requested initial-state reset")
        return body

    def _next_unmet_prerequisite(
        self,
        action_id: str,
        context: ContextManager,
        executed: list[str],
    ) -> tuple[str | None, str | None]:
        """Return (next prerequisite to execute, irrecoverable-block reason).

        (None, None) means the target action is ready. Dependencies are traversed
        depth-first in catalogue order, ensuring every prerequisite executes before
        its dependent action. Failed/previously handled prerequisites are never retried
        implicitly and always block the dependent action.
        """
        successful = set(context.observations.get("successful_actions", []))
        failed = set(context.observations.get("failed_actions", [])) | set(context.observations.get("skipped_actions", []))
        handled = set(executed)
        visiting: set[str] = set()

        def resolve(target: str) -> tuple[str | None, str | None]:
            if target in visiting:
                return None, f"Dependency cycle detected while planning {target!r}."
            visiting.add(target)
            definition = ACTION_CATALOG[target]
            for dependency in definition.get("requires", []):
                if dependency in successful:
                    continue
                if dependency in failed or dependency in handled:
                    return None, f"Required prerequisite {dependency!r} was already attempted and did not succeed."
                next_dep, error = resolve(dependency)
                if error:
                    return None, error
                if next_dep:
                    return next_dep, None
                # All prerequisites of this dependency are satisfied; execute it now.
                return dependency, None
            if definition.get("resource_id_key") and not is_positive_integer(context.observations.get("primary_user_id")):
                source_action = "user_control"
                if source_action in successful:
                    return None, f"Prerequisite {source_action!r} succeeded without a valid primary resource ID."
                if source_action in failed or source_action in handled:
                    return None, f"Required resource ID from {source_action!r} is unavailable and cannot be retried in this run."
                next_dep, error = resolve(source_action)
                if error:
                    return None, error
                return next_dep or source_action, None
            visiting.remove(target)
            return None, None

        return resolve(action_id)

    async def run(
        self,
        mode: str,
        max_actions: int,
        scenario: str = "default",
        verbose: bool = False,
    ) -> dict[str, Any]:
        if mode not in {"fixed", "adaptive"}:
            raise ValueError("mode must be 'fixed' or 'adaptive'")
        if not 1 <= max_actions <= 100:
            raise ValueError("max_actions must be between 1 and 100")
        if scenario not in {"default", "single_user_context", "unavailable_user_context"}:
            raise ValueError("scenario must be 'default', 'single_user_context', or 'unavailable_user_context'")

        async with self.run_lock:
            return await self._run_locked(
                mode=mode,
                max_actions=max_actions,
                scenario=scenario,
                verbose=verbose,
            )

    async def _run_locked(
        self,
        mode: str,
        max_actions: int,
        scenario: str,
        verbose: bool,
    ) -> dict[str, Any]:
        run_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        setup_start = time.perf_counter()

        self.executor.initiated_requests = 0
        self.executor.completed_responses = 0
        self.selector = ActionSelector()

        reset_record = await self.reset_target(scenario)
        setup_reset_seconds = time.perf_counter() - setup_start
        testing_started_at = datetime.now(timezone.utc).isoformat()
        start = time.perf_counter()

        context = ContextManager()
        # `executed` means handled by the mode so the same action cannot loop.
        # `sequence` / `http_attempted` contain only actions that reached the executor.
        executed: list[str] = []
        http_attempted: list[str] = []
        skipped_action_ids: list[str] = []
        sequence: list[str] = []
        events: list[dict[str, Any]] = []
        all_findings: dict[str, dict[str, Any]] = {}
        llm_traces: list[dict[str, Any]] = []
        stop_reason = "action_budget_exhausted"

        if verbose:
            show_banner(mode, scenario, max_actions)

        pending_action_id: str | None = None
        pending_trace: dict[str, Any] | None = None
        # One LLM call proposes a short plan; the local engine executes only
        # validated IDs and replans when the plan becomes stale or evidence changes.
        plan_queue: list[dict[str, Any]] = []
        current_plan: dict[str, Any] | None = None
        plan_replan_events: list[dict[str, Any]] = []
        plan_queue_discarded_count = 0
        plan_followup_intent_count = 0  # queued follow-up intents whose HTTP request started
        plan_followup_intent_completed_count = 0  # queued follow-up intents with an HTTP response
        anticipated_resource_prerequisites_preserved_count = 0

        def invalidate_plan(reason: str, step_number: int) -> None:
            """Record one invalidation/exhaustion event; never alter a pending intent."""
            nonlocal plan_queue, plan_queue_discarded_count
            # Record an exhausted/invalidated active plan even if its last queued
            # item was just popped. Avoid duplicate events when a prerequisite
            # already invalidated the remaining plan but its pending intent still runs.
            if current_plan is None or current_plan.get("invalidated_reason"):
                if not plan_queue:
                    return
            discarded_items = list(plan_queue)
            queued_count = len(discarded_items)
            plan_queue_discarded_count += queued_count
            plan_replan_events.append({
                "step": step_number,
                "plan_id": (current_plan or {}).get("plan_id"),
                "reason": reason,
                "queued_intents_discarded": queued_count,
            })
            for item in discarded_items:
                events.append({
                    "step": step_number,
                    "action_id": item.get("action_id"),
                    "status": "planned_intent_discarded",
                    "reason": reason,
                    "selection_source": "plan_manager",
                    "selection_role": "discarded_plan_item",
                    "plan_id": item.get("plan_id"),
                    "plan_position": item.get("plan_position"),
                    "planned_reason": item.get("reason"),
                })
            if current_plan is not None:
                current_plan["invalidated_reason"] = reason
            plan_queue = []

        for index in range(max_actions):
            remaining = set(context.observations["remaining_findings"])
            # Discard queued items that are no longer meaningful/resolvable. This
            # is plan maintenance, not an executed-action slot or a model decision.
            while mode == "adaptive" and pending_action_id is None and plan_queue:
                queued = plan_queue[0]
                queued_id = queued["action_id"]
                queued_finding = ACTION_CATALOG[queued_id].get("finding")
                if queued_id in executed:
                    discard_reason = "already_handled"
                elif queued_finding is not None and queued_finding not in remaining:
                    discard_reason = "finding_already_confirmed"
                elif not self.selector._prerequisites_are_resolvable(queued_id, context, set(executed)):
                    discard_reason = "prerequisites_no_longer_resolvable"
                else:
                    break
                plan_queue.pop(0)
                plan_queue_discarded_count += 1
                events.append({
                    "step": index + 1,
                    "action_id": queued_id,
                    "status": "planned_intent_discarded",
                    "reason": discard_reason,
                    "selection_source": "plan_manager",
                    "selection_role": "discarded_plan_item",
                    "plan_id": queued.get("plan_id"),
                    "plan_position": queued.get("plan_position"),
                    "planned_reason": queued.get("reason"),
                })

            # Adaptive stops once all target findings are confirmed. Fixed mode
            # continues through the entire predetermined catalogue sequence.
            if mode == "adaptive" and not remaining:
                stop_reason = "all_target_findings_confirmed"
                break

            if mode == "fixed":
                action_id = next((candidate for candidate in FIXED_SEQUENCE if candidate not in executed), None)
                active_trace = None
                intent_action_id = action_id
            elif pending_action_id is not None:
                intent_action_id = pending_action_id
                planned_prerequisite, planning_error = self._next_unmet_prerequisite(
                    pending_action_id, context, executed
                )
                if planning_error:
                    invalidate_plan("pending_intent_prerequisite_unrecoverable", index + 1)
                    blocked = pending_action_id
                    reason = planning_error
                    request_template = {
                        "method": ACTION_CATALOG[blocked].get("method"),
                        "path_template": ACTION_CATALOG[blocked].get("path"),
                        "params": ACTION_CATALOG[blocked].get("params", {}),
                        "json_template": ACTION_CATALOG[blocked].get("body"),
                    }
                    context.record_skipped(blocked, reason, request_template)
                    executed.append(blocked)
                    skipped_action_ids.append(blocked)
                    events.append({
                        "step": index + 1,
                        "action_id": blocked,
                        "intent_action_id": blocked,
                        "status": "blocked_unrecoverable_prerequisite",
                        "reason": reason,
                        "request": request_template,
                        "selection_source": "dependency_planner",
                        "selection_role": "blocked_intent",
                        "intent_selection_source": (pending_trace or {}).get("selection_source"),
                        "plan_id": (pending_trace or {}).get("plan_id"),
                        "plan_position": (pending_trace or {}).get("plan_position"),
                        "remaining_findings_before_action": sorted(remaining),
                    })
                    pending_action_id = None
                    pending_trace = None
                    continue
                if planned_prerequisite:
                    action_id = planned_prerequisite
                    active_trace = {
                        "selection_source": "dependency_planner",
                        "selected_action_role": "prerequisite",
                        "requested_action_id": intent_action_id,
                        "intent_selection_source": (pending_trace or {}).get("selection_source", "unknown"),
                        "reason": f"Satisfy prerequisite chain for {intent_action_id}.",
                        "plan_id": (pending_trace or {}).get("plan_id"),
                        "plan_position": (pending_trace or {}).get("plan_position"),
                    }
                    original = pending_trace or {}
                    planned = original.setdefault("scheduled_prerequisites", [])
                    if action_id not in planned:
                        planned.append(action_id)
                else:
                    # The original model-chosen intent is now safe to execute.
                    action_id = pending_action_id
                    active_trace = pending_trace or {"selection_source": "dependency_planner", "selected_action_role": "finding_probe"}
                    pending_action_id = None
                    pending_trace = None
            elif mode == "adaptive" and plan_queue:
                # Consume the next item from the existing validated plan. Do not
                # create a new plan ID or clear the remaining queue here; doing so
                # would silently reduce a multi-step plan to one follow-up action.
                queued = plan_queue.pop(0)
                selected_intent = queued["action_id"]
                definition = ACTION_CATALOG[selected_intent]
                finding = definition.get("finding")
                selection_trace = {
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "model": OLLAMA_MODEL,
                    "llm_request_made": False,
                    "selected_action": selected_intent,
                    "proposed_action": selected_intent,
                    "selection_source": "llm_plan",
                    "selected_action_role": "finding_probe" if finding in remaining else "reconnaissance",
                    "model_proposal_valid": True,
                    "model_proposal_appropriate": True,
                    "reason": queued.get("reason", "Validated follow-up from the current short-horizon plan."),
                    "candidate_count": queued.get("candidate_count"),
                    "plan_id": queued.get("plan_id"),
                    "plan_position": queued.get("plan_position"),
                    "plan_horizon": queued.get("plan_horizon", self.selector.plan_horizon),
                    "plan_length": queued.get("plan_length"),
                    "selected_cvss_score": queued.get("selected_cvss_score"),
                    "highest_available_cvss_score": queued.get("highest_available_cvss_score"),
                    "selected_cvss_reference_rank": queued.get("selected_cvss_reference_rank"),
                    "cvss_priority_guard_applied": False,
                    "plan_method": "llm_short_horizon_ordered_intents",
                    "is_planned_intent": True,
                    "queued_plan_item": True,
                }
                intent_action_id = selected_intent
                planned_prerequisite, planning_error = self._next_unmet_prerequisite(
                    selected_intent, context, executed
                )
                if planning_error:
                    invalidate_plan("planned_intent_prerequisite_became_unrecoverable", index + 1)
                    selection_trace["planner_error"] = planning_error
                    events.append({
                        "step": index + 1,
                        "action_id": selected_intent,
                        "intent_action_id": selected_intent,
                        "status": "blocked_unrecoverable_prerequisite",
                        "reason": planning_error,
                        "selection_source": "dependency_planner",
                        "selection_role": "blocked_intent",
                        "intent_selection_source": "llm_plan",
                        "plan_id": selection_trace.get("plan_id"),
                        "plan_position": selection_trace.get("plan_position"),
                        "remaining_findings_before_action": sorted(remaining),
                    })
                    context.record_skipped(selected_intent, planning_error)
                    executed.append(selected_intent)
                    skipped_action_ids.append(selected_intent)
                    continue
                if planned_prerequisite:
                    pending_action_id = selected_intent
                    pending_trace = selection_trace
                    action_id = planned_prerequisite
                    active_trace = {
                        "selection_source": "dependency_planner",
                        "selected_action_role": "prerequisite",
                        "requested_action_id": selected_intent,
                        "intent_selection_source": "llm_plan",
                        "reason": f"Satisfy prerequisite chain for {selected_intent}.",
                        "plan_id": selection_trace.get("plan_id"),
                        "plan_position": selection_trace.get("plan_position"),
                    }
                    selection_trace.setdefault("scheduled_prerequisites", []).append(action_id)
                else:
                    action_id = selected_intent
                    active_trace = selection_trace
            else:
                selected_intent, selection_trace = await self.selector.select(context, executed)
                llm_traces.append(selection_trace)
                if not selected_intent:
                    if (
                        selection_trace.get("llm_request_made") is True
                        and selection_trace.get("error")
                        and selection_trace.get("selection_source") == "none"
                        and selection_trace.get("fallback_suppressed") is True
                    ):
                        stop_reason = "llm_selection_failed_strict_mode"
                    elif mode == "fixed" and len(executed) >= len(FIXED_SEQUENCE):
                        stop_reason = "fixed_sequence_exhausted"
                    else:
                        stop_reason = "no_actions_remaining"
                    break

                # Register a new short-horizon plan exactly once, at the original
                # LLM decision. Follow-up items share this plan ID and are consumed
                # by the plan_queue branch without silently starting a new plan.
                proposed_plan = selection_trace.get("planned_actions")
                if not isinstance(proposed_plan, list) or not proposed_plan:
                    proposed_plan = [{"action_id": selected_intent, "reason": selection_trace.get("reason", "")}]
                proposed_plan = [
                    item for item in proposed_plan
                    if isinstance(item, dict)
                    and item.get("action_id") in ACTION_CATALOG
                ][:self.selector.plan_horizon]
                if not proposed_plan or proposed_plan[0].get("action_id") != selected_intent:
                    # The selector's primary choice must agree with the first plan
                    # item. Reject the protocol inconsistency rather than executing
                    # one action while logging a different plan.
                    selection_trace["model_proposal_valid"] = False
                    selection_trace["error"] = "Plan's first action does not match selected_action."
                    selection_trace["selection_source"] = "none"
                    stop_reason = "llm_selection_failed_strict_mode"
                    break
                if selection_trace.get("model_response_recovered"):
                    proposed_plan = proposed_plan[:1]
                    selection_trace["plan_recovered_from_truncation"] = True
                plan_id = str(uuid.uuid4())
                current_plan = {
                    "plan_id": plan_id,
                    "horizon": self.selector.plan_horizon,
                    "proposed_length": len(proposed_plan),
                    "executed_intents": 0,
                    "selection_source": selection_trace.get("selection_source"),
                    "started_at_step": index + 1,
                }
                selection_trace["planned_actions"] = proposed_plan
                selection_trace["plan_id"] = plan_id
                selection_trace["plan_position"] = 1
                selection_trace["plan_horizon"] = self.selector.plan_horizon
                selection_trace["plan_length"] = len(proposed_plan)
                selection_trace["plan_queued_action_ids"] = [item["action_id"] for item in proposed_plan[1:]]
                decision_time_priority_order = selection_trace.get("cvss_remaining_priority_order") or []
                decision_time_priority_rank = {
                    candidate_id: rank for rank, candidate_id in enumerate(decision_time_priority_order, start=1)
                }
                plan_queue = [
                    {
                        "action_id": item["action_id"],
                        "reason": item.get("reason", ""),
                        "plan_id": plan_id,
                        "plan_position": position,
                        "plan_horizon": self.selector.plan_horizon,
                        "plan_length": len(proposed_plan),
                        "candidate_count": selection_trace.get("candidate_count"),
                        # Local audit metadata only; never sent back to the model.
                        "selected_cvss_score": self.selector.cvss_assessments.get(item["action_id"], {}).get("base_score"),
                        "highest_available_cvss_score": selection_trace.get("highest_available_cvss_score"),
                        "selected_cvss_reference_rank": decision_time_priority_rank.get(item["action_id"]),
                    }
                    for position, item in enumerate(proposed_plan[1:], start=2)
                ]

                intent_action_id = selected_intent
                planned_prerequisite, planning_error = self._next_unmet_prerequisite(
                    selected_intent, context, executed
                )
                if planning_error:
                    invalidate_plan("selected_intent_prerequisite_unrecoverable", index + 1)
                    # The intent should normally have been filtered as impossible.
                    # Record the invariant violation; do not fabricate a replacement.
                    selection_trace["planner_error"] = planning_error
                    events.append({
                        "step": index + 1,
                        "action_id": selected_intent,
                        "intent_action_id": selected_intent,
                        "status": "blocked_unrecoverable_prerequisite",
                        "reason": planning_error,
                        "selection_source": "dependency_planner",
                        "selection_role": "blocked_intent",
                        "intent_selection_source": selection_trace.get("selection_source"),
                        "remaining_findings_before_action": sorted(remaining),
                    })
                    context.record_skipped(selected_intent, planning_error)
                    executed.append(selected_intent)
                    skipped_action_ids.append(selected_intent)
                    continue
                if planned_prerequisite:
                    pending_action_id = selected_intent
                    pending_trace = selection_trace
                    action_id = planned_prerequisite
                    active_trace = {
                        "selection_source": "dependency_planner",
                        "selected_action_role": "prerequisite",
                        "requested_action_id": selected_intent,
                        "intent_selection_source": selection_trace.get("selection_source", "unknown"),
                        "reason": f"Satisfy prerequisite chain for {selected_intent}.",
                        "plan_id": selection_trace.get("plan_id"),
                        "plan_position": selection_trace.get("plan_position"),
                    }
                    selection_trace.setdefault("scheduled_prerequisites", []).append(action_id)
                else:
                    action_id = selected_intent
                    active_trace = selection_trace

            if not action_id:
                if mode == "fixed" and len(executed) >= len(FIXED_SEQUENCE):
                    stop_reason = "fixed_sequence_exhausted"
                else:
                    stop_reason = "no_actions_remaining"
                break

            successful_before = set(context.observations.get("successful_actions", []))
            dependency_check = {
                "requires": list(ACTION_CATALOG[action_id].get("requires", [])),
                "satisfied_before_execution": {
                    dependency: dependency in successful_before
                    for dependency in ACTION_CATALOG[action_id].get("requires", [])
                },
                "known_user_ids_before_execution": list(context.observations.get("known_user_ids", [])),
                "primary_user_id_before_execution": context.observations.get("primary_user_id"),
                "intended_action_id": intent_action_id,
            }
            try:
                self.validator.validate(action_id, executed, context.observations)
            except ActionValidationError as exc:
                reason = str(exc)
                request_template = {
                    "method": ACTION_CATALOG[action_id].get("method"),
                    "path_template": ACTION_CATALOG[action_id].get("path"),
                    "params": ACTION_CATALOG[action_id].get("params", {}),
                    "json_template": ACTION_CATALOG[action_id].get("body"),
                }
                is_expected_prerequisite_block = (
                    reason.startswith("Missing successful prerequisite action:")
                    or reason.startswith("Required positive integer")
                )
                if mode == "fixed" and is_expected_prerequisite_block:
                    events.append({
                        "step": index + 1, "action_id": action_id,
                        "status": "skipped_missing_prerequisite", "reason": reason,
                        "request": request_template, "dependency_check": dependency_check,
                        "remaining_findings_before_action": sorted(remaining),
                        "selection_source": "fixed", "selection_role": "fixed_sequence",
                    })
                    context.record_skipped(action_id, reason, request_template)
                    executed.append(action_id)
                    skipped_action_ids.append(action_id)
                    continue
                invalidate_plan("local_action_validation_rejected", index + 1)
                events.append({
                    "step": index + 1, "action_id": action_id,
                    "intent_action_id": intent_action_id,
                    "status": "rejected", "reason": reason,
                    "request": request_template, "dependency_check": dependency_check,
                    "remaining_findings_before_action": sorted(remaining),
                    "selection_source": active_trace.get("selection_source") if active_trace else "fixed",
                    "selection_role": active_trace.get("selected_action_role") if active_trace else "fixed_sequence",
                })
                stop_reason = "action_validation_rejected"
                break

            requests_before = self.executor.initiated_requests
            try:
                response = await self.executor.execute(action_id, context.observations)
            except Exception as exc:
                error_text = f"{type(exc).__name__}: {exc}"
                request_template = {
                    "method": ACTION_CATALOG[action_id].get("method"),
                    "path_template": ACTION_CATALOG[action_id].get("path"),
                    "params": ACTION_CATALOG[action_id].get("params", {}),
                    "json_template": ACTION_CATALOG[action_id].get("body"),
                }
                context.record_failure(action_id, error_text, request_template)
                invalidate_plan("http_or_execution_error", index + 1)
                request_was_started = self.executor.initiated_requests > requests_before
                if (request_was_started and action_id == intent_action_id and active_trace
                        and active_trace.get("selection_source") == "llm_plan"):
                    plan_followup_intent_count += 1
                events.append({
                    "step": index + 1, "action_id": action_id,
                    "intent_action_id": intent_action_id,
                    "status": "request_error" if request_was_started else "preflight_error",
                    "request": request_template, "dependency_check": dependency_check,
                    "remaining_findings_before_action": sorted(remaining), "reason": error_text,
                    "selection_source": active_trace.get("selection_source") if active_trace else "fixed",
                    "selection_role": active_trace.get("selected_action_role") if active_trace else "fixed_sequence",
                    "intent_selection_source": active_trace.get("intent_selection_source") if active_trace else None,
                })
                executed.append(action_id)
                if request_was_started:
                    http_attempted.append(action_id)
                    sequence.append(action_id)
                # A failed prerequisite must never release its dependent intent.
                continue

            if (mode == "adaptive" and action_id == intent_action_id and active_trace
                    and active_trace.get("selection_source") == "llm_plan"):
                plan_followup_intent_completed_count += 1

            new_findings = self.detector.detect(action_id, response)
            for finding in new_findings:
                all_findings[finding["category"]] = finding
            context.update(action_id, response, new_findings)
            executed.append(action_id)
            http_attempted.append(action_id)
            sequence.append(action_id)

            event = {
                "step": index + 1,
                "action_id": action_id,
                "intent_action_id": intent_action_id,
                "plan_id": (active_trace or {}).get("plan_id"),
                "plan_position": (active_trace or {}).get("plan_position"),
                "planned_reason": (active_trace or {}).get("reason"),
                "request": {
                    "method": response.get("method"),
                    "url": response.get("url"),
                    "params": response.get("request_params", ACTION_CATALOG[action_id].get("params", {})),
                    "json": response.get("request_json"),
                },
                "response": response,
                "dependency_check": dependency_check,
                "remaining_findings_before_action": sorted(remaining),
                "selection_role": active_trace.get("selected_action_role") if active_trace else "fixed_sequence",
                "new_findings": new_findings,
                "confirmed_findings": context.observations["confirmed_findings"],
                "remaining_findings": context.observations["remaining_findings"],
                "selection_source": active_trace.get("selection_source") if active_trace else "fixed",
                "intent_selection_source": active_trace.get("intent_selection_source") if active_trace else None,
                "requested_action_id": active_trace.get("requested_action_id") if active_trace else None,
                "intent_cvss_estimate": self.selector.cvss_assessments.get(intent_action_id, {}).get("base_score") if intent_action_id else None,
                "executed_action_cvss_estimate": self.selector.cvss_assessments.get(action_id, {}).get("base_score"),
                "selected_cvss_score": (active_trace or {}).get("selected_cvss_score"),
                "highest_available_cvss_score": (active_trace or {}).get("highest_available_cvss_score"),
                "selected_cvss_reference_rank": (active_trace or {}).get("selected_cvss_reference_rank"),
                "cvss_priority_guard_applied": bool(active_trace.get("cvss_priority_guard_applied", False)) if active_trace else False,
            }
            events.append(event)

            if verbose:
                status = f"HTTP {response['status_code']}"
                if new_findings:
                    status += " | FINDING: " + ", ".join(item["category"] for item in new_findings)
                show_action(index + 1, max_actions, action_id, status)

            if mode == "adaptive" and active_trace and active_trace.get("plan_id") and action_id == intent_action_id:
                role = active_trace.get("selected_action_role")
                plan_id_for_event = active_trace.get("plan_id")
                if current_plan and current_plan.get("plan_id") == plan_id_for_event and role in {"finding_probe", "reconnaissance"}:
                    current_plan["executed_intents"] = int(current_plan.get("executed_intents", 0)) + 1
                    if active_trace.get("selection_source") == "llm_plan":
                        plan_followup_intent_count += 1
                    if role == "reconnaissance":
                        if _reconnaissance_response_is_material(action_id, response):
                            invalidate_plan("reconnaissance_material_context_change", index + 1)
                        elif current_plan["executed_intents"] >= int(current_plan.get("horizon", self.selector.plan_horizon)):
                            invalidate_plan("maximum_plan_horizon_reached", index + 1)
                        elif not plan_queue:
                            invalidate_plan("proposed_plan_exhausted", index + 1)
                    else:
                        expected_finding = ACTION_CATALOG[action_id].get("finding")
                        observed_categories = {item.get("category") for item in new_findings if isinstance(item, dict)}
                        if expected_finding and expected_finding not in observed_categories:
                            invalidate_plan("expected_finding_not_confirmed", index + 1)
                        elif current_plan["executed_intents"] >= int(current_plan.get("horizon", self.selector.plan_horizon)):
                            invalidate_plan("maximum_plan_horizon_reached", index + 1)
                        elif not plan_queue:
                            invalidate_plan("proposed_plan_exhausted", index + 1)
            # A resource ID obtained for the currently selected plan intent is an
            # anticipated prerequisite, not a reason to throw away unrelated queued
            # intents. The original LLM plan already included this dependency. Keep
            # the queue if the resource was obtained successfully for that pending
            # intent; genuinely unrelated resource updates still invalidate it.
            if (mode == "adaptive" and action_id == "user_control"
                    and (active_trace or {}).get("selected_action_role") == "prerequisite"):
                prerequisite_for = (active_trace or {}).get("requested_action_id")
                same_active_plan = (
                    current_plan is not None
                    and (active_trace or {}).get("plan_id") == current_plan.get("plan_id")
                    and prerequisite_for == intent_action_id
                )
                if same_active_plan and is_positive_integer(context.observations.get("primary_user_id")):
                    current_plan["anticipated_resource_prerequisites_satisfied"] = int(
                        current_plan.get("anticipated_resource_prerequisites_satisfied", 0)
                    ) + 1
                    anticipated_resource_prerequisites_preserved_count += 1
                else:
                    invalidate_plan("new_resource_id_acquired", index + 1)

            if mode == "adaptive" and not context.observations["remaining_findings"]:
                stop_reason = "all_target_findings_confirmed"
                # All findings are now confirmed; do not execute a queued non-finding
                # intent merely because it preceded this final response.
                pending_action_id = None
                pending_trace = None
                break

        if pending_action_id is not None and stop_reason == "action_budget_exhausted":
            stop_reason = "action_budget_exhausted_with_pending_intent"
        if mode == "fixed" and stop_reason == "action_budget_exhausted":
            if len(executed) >= len(FIXED_SEQUENCE):
                stop_reason = "fixed_sequence_exhausted"
        elapsed = time.perf_counter() - start
        confirmed = set(context.observations["confirmed_findings"])
        coverage = len(confirmed & TARGET_FINDINGS) / len(TARGET_FINDINGS) * 100

        target_actions = [
            action_id
            for action_id in sequence
            if ACTION_CATALOG[action_id].get("finding") is not None
        ]
        productive_count = sum(
            1
            for event in events
            if event.get("new_findings")
        )

        # Post-run only: audit how early the study's scenario-reference Critical
        # categories were detected. These scores are never present in selector prompts.
        finding_detection_request_positions: dict[str, int] = {}
        executed_request_position = 0
        for event in events:
            if not isinstance(event.get("response"), dict):
                continue
            executed_request_position += 1
            for finding in event.get("new_findings", []) or []:
                category = finding.get("category") if isinstance(finding, dict) else None
                if isinstance(category, str) and category:
                    finding_detection_request_positions.setdefault(category, executed_request_position)
        reference_critical_categories = sorted({
            str(ACTION_CATALOG[action_id].get("finding"))
            for action_id, assessment in self.selector.cvss_assessments.items()
            if ACTION_CATALOG.get(action_id, {}).get("finding")
            and isinstance(assessment.get("base_score"), (int, float))
            and float(assessment["base_score"]) >= 9.0
        })
        reference_critical_detection_positions = {
            category: finding_detection_request_positions.get(category)
            for category in reference_critical_categories
        }
        detected_critical_positions = [
            position for position in reference_critical_detection_positions.values()
            if position is not None
        ]

        def _reference_critical_coverage_at(request_budget: int) -> float:
            if not reference_critical_categories:
                return 0.0
            return round(
                100.0 * sum(
                    1 for position in reference_critical_detection_positions.values()
                    if position is not None and position <= request_budget
                ) / len(reference_critical_categories),
                2,
            )

        contextual_soundness = (
            productive_count / len(sequence) * 100 if sequence else 0.0
        )

        # Attach the validated scenario-reference CVSS vector/score to confirmed
        # synthetic findings. These are formula-derived scores for explicit hypothetical
        # assumptions, not analyst-validated ratings of the synthetic marker itself.
        for finding in all_findings.values():
            assessment = self.selector.cvss_assessments.get(finding.get("action_id"))
            if assessment:
                finding["cvss_estimate"] = {
                    "version": assessment["cvss_version"],
                    "base_score": assessment["base_score"],
                    "severity": assessment["severity"],
                    "vector": assessment["vector"],
                    "status": assessment["status"],
                }
            else:
                finding["cvss_estimate"] = None
            model_risk = self.selector.llm_risk_assessments.get(finding.get("action_id"))
            finding["llm_risk_assessment"] = (
                {
                    "severity_estimate": model_risk.get("severity_estimate"),
                    "confidence": model_risk.get("confidence"),
                    "rationale": model_risk.get("rationale"),
                    "status": "model_generated_qualitative_estimate_not_cvss",
                }
                if model_risk else None
            )

        selection_sources = [
            trace.get("selection_source") for trace in llm_traces
        ]
        ollama_metrics = [
            trace.get("ollama_metrics", {})
            for trace in llm_traces
            if trace.get("ollama_metrics")
        ]
        measured_calls = [
            metric for metric in ollama_metrics
            if isinstance(metric.get("total_duration"), (int, float))
        ]

        llm_seconds = sum(
            metric["total_duration"] for metric in measured_calls
        ) / 1_000_000_000
        llm_load_seconds = sum(
            metric.get("load_duration", 0)
            for metric in measured_calls
            if isinstance(metric.get("load_duration", 0), (int, float))
        ) / 1_000_000_000
        prompt_tokens = sum(
            metric.get("prompt_eval_count", 0)
            for metric in measured_calls
            if isinstance(metric.get("prompt_eval_count", 0), (int, float))
        )
        generated_tokens = sum(
            metric.get("eval_count", 0)
            for metric in measured_calls
            if isinstance(metric.get("eval_count", 0), (int, float))
        )

        selection_decisions = [
            event for event in events
            if event.get("selection_source") in {"llm", "llm_plan", "cvss_priority_guard", "progress_guard", "fallback", "dependency_planner", "single_candidate"}
            and event.get("action_id") is not None
        ]
        valid_selection_events = sum(
            1 for event in selection_decisions
            if selection_event_action_role_is_valid(event)
        )
        llm_request_elapsed = sum(
            float(trace.get("llm_request_elapsed_seconds", 0) or 0)
            for trace in llm_traces
        )
        actual_llm_traces = [trace for trace in llm_traces if trace.get("llm_request_made") is True]
        parsed_proposal_traces = [
            trace for trace in actual_llm_traces if "proposed_action" in trace
        ]
        appropriate_model_proposals = sum(
            1 for trace in parsed_proposal_traces
            if trace.get("model_proposal_appropriate") is True
        )
        metrics = {
            "testing_time_seconds": round(elapsed, 3),
            "setup_reset_time_seconds": round(setup_reset_seconds, 6),
            "action_catalog_size": len(ACTION_CATALOG),
            "control_action_count": sum(1 for action in ACTION_CATALOG.values() if action.get("action_type") == "control"),
            "reconnaissance_action_count": sum(1 for action in ACTION_CATALOG.values() if action.get("action_type") == "reconnaissance"),
            "test_actions": len(sequence),
            "handled_action_slots": len(executed),
            "skipped_actions": len(skipped_action_ids),
            "preflight_errors": sum(1 for event in events if event.get("status") == "preflight_error"),
            "rejected_actions": sum(
                1 for event in events if event.get("status") == "rejected"
            ),
            "http_requests": self.executor.initiated_requests,
            "completed_http_responses": self.executor.completed_responses,
            "confirmed_vulnerabilities": len(confirmed),
            "target_finding_count": len(TARGET_FINDINGS),
            "target_findings_detected": len(confirmed & TARGET_FINDINGS),
            "target_finding_coverage_percent": round(coverage, 2),
            "productive_action_rate_percent": (
                round(contextual_soundness, 2) if mode == "adaptive" else None
            ),
            "productive_action_rate_definition": (
                "Fraction of executed adaptive actions that immediately confirmed a new target finding; "
                "this is a productivity measure, not standalone model accuracy."
            ),
            "llm_decision_validity_percent": (
                round(100.0 * sum(1 for t in actual_llm_traces if t.get("model_proposal_valid") is True) / len(actual_llm_traces), 2)
                if actual_llm_traces else None
            ),
            "llm_decision_validity_definition": (
                "Share of actual Ollama responses that chose an allowlisted candidate action intent. "
                "Deterministic singleton decisions and dependency-planner executions are excluded. "
                "This is action validity, not contextual appropriateness or vulnerability-detection accuracy."
            ),
            "llm_parsed_proposals": len(parsed_proposal_traces),
            "llm_eligible_intent_percent": (
                round(100.0 * appropriate_model_proposals / len(parsed_proposal_traces), 2)
                if parsed_proposal_traces else None
            ),
            "llm_eligible_intent_definition": (
                "Share of parsed proposals that select an unresolved finding probe or useful reconnaissance intent. "
                "This checks eligibility only, not whether the choice was strategically optimal; candidates are prefiltered to be eligible."
            ),
            "selected_action_role_validity_percent": (
                round(100.0 * valid_selection_events / len(selection_decisions), 2)
                if selection_decisions else None
            ),
            "selected_action_role_validity_definition": (
                "Share of all recorded selection events whose action ID is in the allowlist and whose source/role/status "
                "combination is recognized. A dependency planner's blocked_intent event is valid when the intended action "
                "is allowlisted and the status explicitly records a blocked prerequisite; it is not counted as an executed "
                "action. Invalid or malformed events remain in the denominator. This is an execution-integrity check, not "
                "semantic appropriateness, severity-ranking accuracy, or vulnerability-detection accuracy."
            ),
            "llm_request_attempts": self.selector.calls,
            "llm_plan_calls": sum(1 for trace in actual_llm_traces if trace.get("plan_method") == "llm_short_horizon_ordered_intents"),
            "llm_plan_followup_intents_attempted": plan_followup_intent_count,
            "llm_plan_followup_intents_completed": plan_followup_intent_completed_count,
            "llm_plan_followup_intents_executed": plan_followup_intent_count,
            "llm_plan_followup_intents_executed_compatibility_note": (
                "Legacy alias of llm_plan_followup_intents_attempted: queued follow-up intents for which the target HTTP request started."
            ),
            "llm_plan_items_discarded": plan_queue_discarded_count,
            "llm_plan_items_removed_by_local_policy": sum(
                int(trace.get("plan_items_removed_by_local_policy", 0) or 0) for trace in actual_llm_traces
            ),
            "llm_anticipated_resource_prerequisites_preserved": anticipated_resource_prerequisites_preserved_count,
            "llm_planning_horizon": self.selector.plan_horizon,
            "llm_proposed_plan_lengths": [int(trace.get("plan_length", 0) or 0) for trace in actual_llm_traces if trace.get("plan_method") == "llm_short_horizon_ordered_intents"],
            "llm_mean_proposed_plan_length": round(sum(int(trace.get("plan_length", 0) or 0) for trace in actual_llm_traces if trace.get("plan_method") == "llm_short_horizon_ordered_intents") / max(1, sum(1 for trace in actual_llm_traces if trace.get("plan_method") == "llm_short_horizon_ordered_intents")), 2) if any(trace.get("plan_method") == "llm_short_horizon_ordered_intents" for trace in actual_llm_traces) else None,
            "llm_plan_replan_events": plan_replan_events,
            "llm_plan_replan_count": len(plan_replan_events),
            "llm_response_recovery_count": self.selector.response_recoveries,
            "llm_response_recovery_definition": (
                "Count of truncated Ollama selection responses where the model had already emitted a complete, "
                "first-field action_id that exactly matched a candidate. The rationale is discarded; no substitute "
                "action is invented. These are disclosed separately from transport/parse errors and fallbacks."
            ),
            "llm_intent_decision_count": sum(1 for trace in llm_traces if trace.get("selected_action")),
            "llm_intent_decision_share_percent": (
                round(100.0 * sum(1 for trace in llm_traces if trace.get("selected_action") and trace.get("selection_source") == "llm") /
                      sum(1 for trace in llm_traces if trace.get("selected_action")), 2)
                if any(trace.get("selected_action") for trace in llm_traces) else 0.0
            ),
            "mean_candidates_considered_per_llm_request": round(
                sum(float(trace.get("candidate_count", 0) or 0) for trace in actual_llm_traces) / len(actual_llm_traces), 2
            ) if actual_llm_traces else None,
            "llm_lower_score_probe_selections": sum(
                1 for event in events
                if event.get("selection_source") in {"llm", "llm_plan"}
                and event.get("action_id") == event.get("intent_action_id")
                and event.get("selection_role") == "finding_probe"
                and isinstance(event.get("response"), dict)
                and isinstance(event.get("selected_cvss_score"), (int, float))
                and isinstance(event.get("highest_available_cvss_score"), (int, float))
                and float(event["selected_cvss_score"]) < float(event["highest_available_cvss_score"])
            ),
            "llm_lower_score_probe_selection_definition": (
                "Executed LLM-proposed finding intents below the highest reference CVSS score among candidates at the time the plan was proposed. "
                "Follow-up intents use that original plan's candidate set. Audit-only; not a selection rule or a measure of strategic quality."
            ),
            "cvss_policy_note": (
                "CVSS scenario-reference scores are not included in the LLM action-selection prompt and do not rank or filter candidates. "
                "The LLM receives its own separately cached qualitative severity estimates, current evidence, all unresolved feasible finding probes, "
                "and useful reconnaissance actions. CVSS is a post-run comparative baseline only."
            ),
            "llm_risk_profile_loaded": bool(self.selector.llm_risk_assessments),
            "llm_risk_assessment_count": len(self.selector.llm_risk_assessments),
            "llm_risk_assessment_coverage_percent": round(100 * len(self.selector.llm_risk_assessments) / max(1, len(TARGET_FINDINGS)), 2),
            "llm_risk_profile_version": self.selector.llm_risk_profile.get("profile_version"),
            "llm_request_wall_time_seconds": round(llm_request_elapsed, 3),
            "goal_relevant_probe_percent": round(
                len(target_actions) / len(sequence) * 100, 2
            ) if sequence else 0.0,
            "ollama_selection_count": selection_sources.count("llm"),
            "cvss_priority_guard_selection_count": selection_sources.count("cvss_priority_guard"),
            "cvss_profile_loaded": bool(self.selector.cvss_assessments),
            "reference_critical_scenario_category_count": len(reference_critical_categories),
            "reference_critical_scenario_categories_detected": len(detected_critical_positions),
            "reference_critical_detection_request_positions": reference_critical_detection_positions,
            "mean_reference_critical_detection_request_position": round(
                sum(detected_critical_positions) / len(detected_critical_positions), 2
            ) if detected_critical_positions else None,
            "last_reference_critical_detection_request_position": max(detected_critical_positions) if detected_critical_positions else None,
            "reference_critical_coverage_after_5_requests_percent": _reference_critical_coverage_at(5),
            "reference_critical_coverage_after_10_requests_percent": _reference_critical_coverage_at(10),
            "reference_critical_coverage_after_15_requests_percent": _reference_critical_coverage_at(15),
            "reference_critical_detection_metrics_note": (
                "Post-run audit only. Reference-critical means study-defined scenario-reference CVSS Base Score >= 9.0; "
                "these hypothetical vectors are not validated ratings of real vulnerabilities and never influence selection."
            ),
            "cvss_profile_generation_elapsed_seconds": self.selector.cvss_profile.get("profile_generation_elapsed_seconds"),
            "cvss_assessment_count": len(self.selector.cvss_assessments),
            "cvss_base_score_calculator": "FIRST CVSS v3.1 Base Score equations, implemented locally",
            "progress_guard_selection_count": selection_sources.count("progress_guard"),
            "dependency_planner_selection_count": sum(1 for event in events if event.get("selection_source") == "dependency_planner"),
            "scheduled_prerequisite_execution_count": sum(1 for event in events if event.get("selection_source") == "dependency_planner"),
            "selected_intent_count": sum(1 for trace in llm_traces if trace.get("selected_action")),
            "single_candidate_selection_count": selection_sources.count("single_candidate"),
            "fallback_selection_count": selection_sources.count("fallback"),
            "llm_error_count": self.selector.errors,
            "llm_measured_calls": len(measured_calls),
            "llm_total_duration_seconds": round(llm_seconds, 3),
            "llm_model_load_seconds": round(llm_load_seconds, 3),
            "llm_prompt_tokens": prompt_tokens,
            "llm_generated_tokens": generated_tokens,
        }

        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

        report = {
            "run_id": run_id,
            "timestamp_utc": started_at,
            "testing_started_utc": testing_started_at,
            "mode": mode,
            "scenario": scenario,
            "initial_state_reset": reset_record,
            "stop_reason": stop_reason,
            "configuration": {
                "target_url": API_BASE,
                "target_host_allowlist": sorted(ALLOWED_TARGET_HOSTS),
                "ollama_url": OLLAMA_URL,
                "llm_model": OLLAMA_MODEL if mode == "adaptive" else None,
                "action_budget": max_actions,
                "llm_planning_horizon": self.selector.plan_horizon,
                "llm_replanning_policy": "replan after unexpected/material reconnaissance results, request/validation errors, missing expected findings, unrecoverable prerequisites, or exhaustion of the three-intent horizon; routine baseline reconnaissance and anticipated prerequisites do not automatically discard valid queued actions",
                "target_finding_categories": sorted(TARGET_FINDINGS),
            },
            "metrics": metrics,
            "cvss_prioritization": {
                "cvss_version": "3.1",
                "rubric_version": CVSS_RUBRIC_VERSION,
                "source": "Study-defined illustrative scenario-reference vectors; locally calculated; used as a separate post-run comparative baseline only",
                "status": "illustrative_scenario_estimate_requires_analyst_review" if self.selector.cvss_assessments else "not_available",
                "methodology_note": (
                    "CVSS v3.1 Base Scores are calculated locally from the study-defined scenario-reference vectors. "
                    "The adaptive selector deliberately does not receive these scores or vectors, preventing the reference baseline from anchoring the LLM's independent severity judgment. "
                    "Any model-proposed vectors are retained for optional comparison only and do not replace reference scores. "
                    "These vectors describe hypothetical analogue scenarios, not validated ratings of the synthetic responses. "
                    "Missing headers, weak password policy, or disabled rate limiting alone do not prove the assumed exploit impact; "
                    "review vectors and assumptions before academic publication."
                ),
                "model_proposal_summary": self.selector.cvss_profile.get("model_proposal_summary", {}),
                "show_model_proposal_audit": os.getenv("PENTELLIGENT_SHOW_LLM_CVSS_AUDIT", "0").strip().lower() in {"1", "true", "yes", "on"},
                "priority_order": list(self.selector.cvss_priority_order),
                "assessments": [
                    self.selector.cvss_assessments[action_id]
                    for action_id in self.selector.cvss_priority_order
                    if action_id in self.selector.cvss_assessments
                ],
                "profile_file": self.selector.cvss_profile_path,
            },
            "benchmark_severity_policy": (
                "benchmark_severity is a preassigned label from the synthetic fixture, not a CVSS result. "
                "The LLM qualitative severity estimate is a separate uncalibrated judgment, not a CVSS score and not ground truth."
            ),
            "llm_risk_assessment": {
                "status": "available" if self.selector.llm_risk_assessments else "not_available",
                "model": OLLAMA_MODEL,
                "profile_version": self.selector.llm_risk_profile.get("profile_version"),
                "source": "Independent LLM qualitative assessment; CVSS vector/score intentionally withheld from selection prompt",
                "methodology_note": (
                    "Severity is a qualitative estimate of a plausible real-world analogue if validated, not a factual claim about the synthetic API. "
                    "Confidence reflects model judgment, not a statistically calibrated probability. The model assessments require expert validation."
                ),
                "severity_order": list(self.selector.llm_risk_profile.get("severity_order", [])),
                "assessments": [
                    self.selector.llm_risk_assessments[action_id]
                    for action_id in self.selector.llm_risk_profile.get("severity_order", [])
                    if action_id in self.selector.llm_risk_assessments
                ],
                "profile_file": self.selector.llm_risk_profile_path,
            },
            "findings": list(all_findings.values()),
            "action_sequence": sequence,
            "context_history": context.history,
            "final_observations": context.observations,
            "dependency_audit": {
                action_id: {
                    "requires": ACTION_CATALOG[action_id].get("requires", []),
                    "handled": action_id in executed,
                    "executed": action_id in http_attempted,
                    "skipped": action_id in skipped_action_ids,
                    "succeeded": action_id in context.observations.get("successful_actions", []),
                    "preflight_check": next(
                        (event.get("dependency_check") for event in events
                         if event.get("action_id") == action_id and event.get("dependency_check") is not None),
                        None,
                    ),
                    "dependency_check_at_execution": next(
                        (event.get("dependency_check") for event in events
                         if event.get("action_id") == action_id
                         and event.get("dependency_check") is not None
                         and event.get("response") is not None),
                        None,
                    ),
                    "resource_id_required": bool(ACTION_CATALOG[action_id].get("resource_id_key")),
                    "resource_id_available_at_execution": next(
                        (is_positive_integer(event.get("dependency_check", {}).get("primary_user_id_before_execution"))
                         for event in events if event.get("action_id") == action_id and event.get("dependency_check") is not None),
                        None,
                    ),
                    "resource_id_value_at_preflight": next(
                        (event.get("dependency_check", {}).get("primary_user_id_before_execution")
                         for event in events if event.get("action_id") == action_id and event.get("dependency_check") is not None),
                        None,
                    ),
                }
                for action_id in ACTION_CATALOG
            },
            "events": events,
        }

        report_path = RESULTS_DIR / f"{mode}_{run_id}.json"
        events_path = RESULTS_DIR / f"events_{run_id}.jsonl"
        traces_path = RESULTS_DIR / f"llm_interactions_{run_id}.jsonl"

        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        with events_path.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")

        if mode == "adaptive":
            with traces_path.open("w", encoding="utf-8") as handle:
                for trace in llm_traces:
                    handle.write(
                        json.dumps(trace, ensure_ascii=False) + "\n"
                    )

        report["saved_files"] = {
            "report": str(report_path),
            "events": str(events_path),
        }
        if self.selector.cvss_profile_path:
            report["saved_files"]["cvss_profile"] = self.selector.cvss_profile_path
        if mode == "adaptive":
            report["saved_files"]["llm_interactions"] = str(traces_path)

        # Rewrite report so the paths are also persisted in it.
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        if verbose:
            show_summary(metrics, mode, scenario)
            print_experiment_report(report)

        return report


# ============================================================
# BENCHMARK API
# ============================================================

@app.post("/benchmark/{mode}")
async def benchmark(
    mode: str,
    scenario: str = Query(default="default"),
    max_actions: int = Query(default=12, ge=1, le=100),
) -> dict[str, Any]:
    if mode not in {"fixed", "adaptive"}:
        raise HTTPException(
            status_code=400,
            detail="mode must be 'fixed' or 'adaptive'",
        )

    engine = PentelligentEngine()
    return await engine.run(
        mode=mode,
        max_actions=max_actions,
        scenario=scenario,
        verbose=False,
    )
