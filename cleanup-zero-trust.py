#!/usr/bin/env python3
"""
cleanup-zero-trust.py
Removes Cloudflare Zero Trust Gateway rules (HTTP, DNS, network/L4),
Gateway lists, and device posture rules for the given account.

Credentials are read automatically from terraform.tfvars in the same
directory as this script. You can also override them via env vars:

  CF_API_TOKEN=xxx CF_ACCOUNT_ID=yyy python3 cleanup-zero-trust.py

Dry-run (preview only, no deletions):
  DRY_RUN=true python3 cleanup-zero-trust.py

Required permissions on the API token:
  - Zero Trust: Edit
  - Access: Device Posture: Edit
"""

import os
import re
import sys
import json
import urllib.request
import urllib.error
from pathlib import Path

# ── Colours ──────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"
BLUE   = "\033[0;34m"

def log(msg):     print(f"{CYAN}[INFO]{RESET}  {msg}")
def ok(msg):      print(f"{GREEN}[OK]{RESET}    {msg}")
def warn(msg):    print(f"{YELLOW}[WARN]{RESET}  {msg}")
def err(msg):     print(f"{RED}[ERROR]{RESET} {msg}", file=sys.stderr)
def detail(msg):  print(f"{DIM}         {msg}{RESET}")
def section(msg): print(f"\n{BOLD}{BLUE}━━━  {msg}  ━━━{RESET}")

# ── Config ────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).parent.resolve()
TFVARS     = SCRIPT_DIR / "terraform.tfvars"
BASE_URL   = "https://api.cloudflare.com/client/v4"

def parse_tfvars(path: Path) -> dict:
    """Parse key = "value" lines from a terraform.tfvars file."""
    result = {}
    for line in path.read_text().splitlines():
        m = re.match(r'^\s*(\w+)\s*=\s*"?([^"#\n]+?)"?\s*$', line)
        if m:
            result[m.group(1)] = m.group(2).strip()
    return result

tfvars = parse_tfvars(TFVARS) if TFVARS.exists() else {}

API_TOKEN  = os.environ.get("CF_API_TOKEN")  or tfvars.get("cloudflare_api_token",  "")
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID") or tfvars.get("cloudflare_account_id", "")
DRY_RUN    = os.environ.get("DRY_RUN", "false").lower() == "true"

if not API_TOKEN:
    err("cloudflare_api_token not found in terraform.tfvars or CF_API_TOKEN env var")
    sys.exit(1)
if not ACCOUNT_ID:
    err("cloudflare_account_id not found in terraform.tfvars or CF_ACCOUNT_ID env var")
    sys.exit(1)

# ── Totals ────────────────────────────────────────────────────────────────────

total_deleted = 0
total_failed  = 0
total_skipped = 0

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def cf_request(method: str, path: str) -> dict:
    url = f"{BASE_URL}{path}"
    log(f"{method} {url}")
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            body   = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        status = e.code
        body   = json.loads(e.read())

    detail(f"HTTP {status}")

    if not body.get("success"):
        errors = body.get("errors", [])
        for e_ in errors:
            err(f"  code={e_.get('code')} message={e_.get('message')}")
        err(f"API request failed — aborting.")
        sys.exit(1)

    return body


def cf_delete(path: str, label: str):
    global total_deleted, total_failed, total_skipped
    url = f"{BASE_URL}{path}"

    if DRY_RUN:
        warn(f"[DRY-RUN] Would DELETE {url}")
        detail(f"Resource: {label}")
        total_skipped += 1
        return

    log(f"DELETE {url}")
    detail(f"Resource: {label}")
    req = urllib.request.Request(
        url,
        method="DELETE",
        headers={
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            body   = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        status = e.code
        body   = json.loads(e.read())

    detail(f"HTTP {status}")

    if body.get("success"):
        ok(f"Deleted: {label}")
        total_deleted += 1
    else:
        errors = body.get("errors", [])
        err(f"Failed to delete: {label}")
        for e_ in errors:
            detail(f"  code={e_.get('code')} message={e_.get('message')}")
        total_failed += 1


# ── Gateway Rules ─────────────────────────────────────────────────────────────

def delete_gateway_rules(filter_type: str, type_label: str):
    section(f"Gateway {type_label} Rules")
    log("Fetching all Gateway rules from API…")

    body   = cf_request("GET", f"/accounts/{ACCOUNT_ID}/gateway/rules")
    rules  = body.get("result") or []
    detail(f"Total rules returned by API: {len(rules)}")

    count   = 0
    skipped = 0
    for rule in rules:
        filters = rule.get("filters") or []
        if filter_type not in filters:
            skipped += 1
            continue

        rid     = rule["id"]
        name    = rule.get("name", "(unnamed)")
        action  = rule.get("action", "unknown")
        enabled = rule.get("enabled", False)
        traffic = rule.get("traffic", "")

        log(f"Processing rule: {name}")
        detail(f"ID:      {rid}")
        detail(f"Filters: {', '.join(filters)}")
        detail(f"Action:  {action}")
        detail(f"Enabled: {enabled}")
        detail(f"Traffic: {traffic}")

        cf_delete(f"/accounts/{ACCOUNT_ID}/gateway/rules/{rid}",
                  f"{type_label} rule '{name}' ({rid})")
        count += 1

    print()
    if count == 0:
        warn(f"No {type_label} rules found to delete ({skipped} rule(s) belonged to other types).")
    else:
        ok(f"Section summary: {count} {type_label} rule(s) deleted, {skipped} skipped (wrong type).")


# ── Gateway Lists ─────────────────────────────────────────────────────────────

def delete_gateway_lists():
    section("Gateway Lists")
    log("Fetching all Gateway lists from API…")

    body  = cf_request("GET", f"/accounts/{ACCOUNT_ID}/gateway/lists")
    lists = body.get("result") or []
    detail(f"Total lists returned by API: {len(lists)}")

    count = 0
    for lst in lists:
        lid        = lst["id"]
        name       = lst.get("name", "(unnamed)")
        list_type  = lst.get("type", "unknown")
        item_count = lst.get("count", "?")

        log(f"Processing list: {name}")
        detail(f"ID:    {lid}")
        detail(f"Type:  {list_type}")
        detail(f"Items: {item_count}")

        cf_delete(f"/accounts/{ACCOUNT_ID}/gateway/lists/{lid}",
                  f"Gateway list '{name}' ({lid})")
        count += 1

    print()
    if count == 0:
        warn("No Gateway lists found to delete.")
    else:
        ok(f"Section summary: {count} Gateway list(s) deleted.")


# ── Device Posture ────────────────────────────────────────────────────────────

def delete_device_posture():
    section("Device Posture Rules")
    log("Fetching all device posture rules from API…")

    body  = cf_request("GET", f"/accounts/{ACCOUNT_ID}/devices/posture")
    rules = body.get("result") or []
    detail(f"Total posture rules returned by API: {len(rules)}")

    count = 0
    for rule in rules:
        rid       = rule["id"]
        name      = rule.get("name", "(unnamed)")
        rule_type = rule.get("type", "unknown")

        log(f"Processing posture rule: {name}")
        detail(f"ID:   {rid}")
        detail(f"Type: {rule_type}")

        cf_delete(f"/accounts/{ACCOUNT_ID}/devices/posture/{rid}",
                  f"device posture rule '{name}' ({rid})")
        count += 1

    print()
    if count == 0:
        warn("No device posture rules found to delete.")
    else:
        ok(f"Section summary: {count} device posture rule(s) deleted.")


# ── DLP ───────────────────────────────────────────────────────────────────────

def delete_dex_tests():
    section("DEX Tests")
    log("Fetching all DEX tests from API…")

    body   = cf_request("GET", f"/accounts/{ACCOUNT_ID}/dex/devices/dex_tests")
    result = body.get("result") or {}
    tests  = result.get("dex_tests") or []
    detail(f"Total DEX tests returned by API: {len(tests)}")

    count = 0
    for test in tests:
        tid     = test["test_id"]
        name    = test.get("name", "(unnamed)")
        kind    = test.get("data", {}).get("kind", "unknown")
        host    = test.get("data", {}).get("host", "")
        desc    = test.get("description", "")
        enabled = test.get("enabled", False)

        log(f"Processing DEX test: {name}")
        detail(f"ID:      {tid}")
        detail(f"Kind:    {kind}")
        detail(f"Host:    {host}")
        detail(f"Enabled: {enabled}")
        if desc:
            detail(f"Desc:    {desc}")

        cf_delete(f"/accounts/{ACCOUNT_ID}/dex/devices/dex_tests/{tid}",
                  f"DEX test '{name}' ({tid})")
        count += 1

    print()
    if count == 0:
        warn("No DEX tests found to delete.")
    else:
        ok(f"Section summary: {count} DEX test(s) deleted.")


def delete_dlp_custom_entries():
    section("DLP Custom Entries")
    log("Fetching all DLP entries from API…")

    body    = cf_request("GET", f"/accounts/{ACCOUNT_ID}/dlp/entries")
    entries = body.get("result") or []
    detail(f"Total entries returned by API: {len(entries)}")

    count   = 0
    skipped = 0
    for entry in entries:
        eid        = entry["id"]
        name       = entry.get("name", "(unnamed)")
        entry_type = entry.get("type", "unknown")

        if entry_type != "custom":
            detail(f"Skipping non-custom entry: {name} (type={entry_type})")
            skipped += 1
            continue

        profile_id   = entry.get("profile_id", "none")
        profile_name = entry.get("profile_name", "")

        log(f"Processing DLP custom entry: {name}")
        detail(f"ID:           {eid}")
        detail(f"Type:         {entry_type}")
        detail(f"Profile ID:   {profile_id}")
        detail(f"Profile name: {profile_name}")

        cf_delete(f"/accounts/{ACCOUNT_ID}/dlp/entries/{eid}",
                  f"DLP custom entry '{name}' ({eid})")
        count += 1

    print()
    if count == 0:
        warn(f"No DLP custom entries found to delete ({skipped} predefined/integration entries skipped).")
    else:
        ok(f"Section summary: {count} DLP custom entry/entries deleted, {skipped} skipped (not custom).")


def delete_dlp_custom_profiles():
    section("DLP Custom Profiles")
    log("Fetching all DLP custom profiles from API…")

    body     = cf_request("GET", f"/accounts/{ACCOUNT_ID}/dlp/profiles/custom")
    profiles = body.get("result") or []
    detail(f"Total custom profiles returned by API: {len(profiles)}")

    count = 0
    for profile in profiles:
        pid         = profile["id"]
        name        = profile.get("name", "(unnamed)")
        description = profile.get("description", "")

        log(f"Processing DLP custom profile: {name}")
        detail(f"ID:          {pid}")
        detail(f"Description: {description}")

        cf_delete(f"/accounts/{ACCOUNT_ID}/dlp/profiles/custom/{pid}",
                  f"DLP custom profile '{name}' ({pid})")
        count += 1

    print()
    if count == 0:
        warn("No DLP custom profiles found to delete.")
    else:
        ok(f"Section summary: {count} DLP custom profile(s) deleted.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print()
    print(f"{BOLD}╔══════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║   Cloudflare Zero Trust Cleanup Script       ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════╝{RESET}")
    print()
    log(f"Account ID:  {ACCOUNT_ID[:6]}{'*' * 26}")
    log(f"API Token:   {API_TOKEN[:6]}{'*' * 20}")
    log(f"tfvars file: {TFVARS}")
    log(f"Dry-run:     {DRY_RUN}")
    print()

    if DRY_RUN:
        warn("DRY-RUN mode is ON — no resources will be deleted.")

    # Rules must be deleted before lists (rules can reference lists)
    delete_gateway_rules("http", "HTTP")
    delete_gateway_rules("dns",  "DNS")
    delete_gateway_rules("l4",   "Network (L4)")
    delete_gateway_lists()
    delete_device_posture()

    # DEX tests
    delete_dex_tests()

    # DLP: entries must be deleted before profiles
    delete_dlp_custom_entries()
    delete_dlp_custom_profiles()

    section("Final Summary")
    ok(f"Deleted:  {total_deleted} resource(s)")
    if total_skipped:
        warn(f"Skipped:  {total_skipped} resource(s) (dry-run)")
    if total_failed:
        err(f"Failed:   {total_failed} resource(s) — review errors above")
        print()
        sys.exit(1)
    print()


if __name__ == "__main__":
    main()
