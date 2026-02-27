#!/usr/bin/env python3
"""
Summarize evaluation results into a table for the research paper.

Reads all composition analysis JSON files from results/evaluation/
and produces a markdown summary table plus statistics.

Usage:
    python summarize_evaluation.py
"""

import json
import os
import glob
import re


def load_results(results_dir="results/evaluation"):
    """Load all composition result JSONs."""
    pattern = os.path.join(results_dir, "*-COMPOSITION-*.json")
    files = sorted(glob.glob(pattern))
    results = []
    for f in files:
        with open(f, "r") as fh:
            data = json.load(fh)
        # Determine category from log file name
        basename = os.path.basename(f)
        results.append({"file": basename, "data": data})
    return results


def classify_pair(servers):
    """Classify a server pair as HIGH-RISK or CONTROL based on the evaluation plan."""
    control_pairs = {
        frozenset(["google-maps", "memory"]),
        frozenset(["fetch", "google-maps"]),
        frozenset(["postgres", "sqlite"]),
    }
    server_set = frozenset(s.lower().replace("20260227-120000-", "") for s in servers)
    if server_set in control_pairs:
        return "CONTROL"
    return "HIGH-RISK"


def summarize(results):
    """Build summary statistics."""
    rows = []
    for r in results:
        d = r["data"]
        servers = d.get("servers_analyzed", [])
        category = classify_pair(servers)
        n_surpluses = len(d.get("composition_surpluses", []))
        n_chains = len(d.get("attack_chains", []))
        risk_score = d.get("composition_risk_score", "Unknown")
        action = d.get("action", "Unknown")

        # Severity distribution of surpluses
        severities = [s["severity"] for s in d.get("composition_surpluses", [])]
        crit = severities.count("Critical")
        high = severities.count("High")
        med = severities.count("Medium")
        low = severities.count("Low")

        # Cross-server ratio
        cross = sum(1 for s in d.get("composition_surpluses", []) if s.get("is_cross_server"))

        rows.append({
            "category": category,
            "servers": " + ".join(servers),
            "total_tools": d.get("total_tools", 0),
            "pairwise": d.get("pairwise_combinations", 0),
            "surpluses": n_surpluses,
            "cross_server": cross,
            "chains": n_chains,
            "risk_score": risk_score,
            "action": action,
            "sev_crit": crit,
            "sev_high": high,
            "sev_med": med,
            "sev_low": low,
        })

    return rows


def print_markdown_table(rows):
    """Print a markdown table for the paper."""
    print("\n## Composition Analysis Evaluation Results\n")
    print("| Category | Server Pair | Tools | Pairs | Σ_ij | Cross-Server | Chains | Risk | Action |")
    print("|----------|-------------|-------|-------|------|-------------|--------|------|--------|")

    for r in sorted(rows, key=lambda x: (x["category"] != "HIGH-RISK", x["servers"])):
        print(
            f"| {r['category']} "
            f"| {r['servers']} "
            f"| {r['total_tools']} "
            f"| {r['pairwise']} "
            f"| {r['surpluses']} "
            f"| {r['cross_server']} "
            f"| {r['chains']} "
            f"| {r['risk_score']} "
            f"| {r['action']} |"
        )

    # Summary stats
    high_risk = [r for r in rows if r["category"] == "HIGH-RISK"]
    control = [r for r in rows if r["category"] == "CONTROL"]

    print("\n## Summary Statistics\n")
    print(f"- **Total test pairs:** {len(rows)}")
    print(f"- **High-risk pairs:** {len(high_risk)}")
    print(f"- **Control pairs:** {len(control)}")

    if high_risk:
        avg_surpluses_hr = sum(r["surpluses"] for r in high_risk) / len(high_risk)
        total_chains_hr = sum(r["chains"] for r in high_risk)
        print(f"- **Avg surpluses (high-risk):** {avg_surpluses_hr:.1f}")
        print(f"- **Total attack chains (high-risk):** {total_chains_hr}")

    if control:
        avg_surpluses_ctrl = sum(r["surpluses"] for r in control) / len(control)
        print(f"- **Avg surpluses (control):** {avg_surpluses_ctrl:.1f}")

    # Severity distribution
    all_crit = sum(r["sev_crit"] for r in rows)
    all_high = sum(r["sev_high"] for r in rows)
    all_med = sum(r["sev_med"] for r in rows)
    all_low = sum(r["sev_low"] for r in rows)
    total_surpluses = sum(r["surpluses"] for r in rows)

    print(f"\n### Surplus Severity Distribution (n={total_surpluses})\n")
    print(f"- Critical: {all_crit}")
    print(f"- High: {all_high}")
    print(f"- Medium: {all_med}")
    print(f"- Low: {all_low}")

    # Cross-server ratio
    total_cross = sum(r["cross_server"] for r in rows)
    if total_surpluses > 0:
        print(f"\n- **Cross-server surpluses:** {total_cross}/{total_surpluses} ({100*total_cross/total_surpluses:.0f}%)")

    # Action distribution
    actions = {}
    for r in rows:
        actions[r["action"]] = actions.get(r["action"], 0) + 1
    print(f"\n### Recommended Actions\n")
    for action, count in sorted(actions.items()):
        print(f"- {action}: {count}")


def main():
    results = load_results()
    if not results:
        print("No results found in results/evaluation/")
        print("Run ./run_evaluation.sh first.")
        return

    rows = summarize(results)
    print_markdown_table(rows)

    # Also save as JSON for further processing
    output_path = "results/evaluation/summary.json"
    with open(output_path, "w") as f:
        json.dump(rows, f, indent=2)
    print(f"\n\nRaw data saved to: {output_path}")


if __name__ == "__main__":
    main()
