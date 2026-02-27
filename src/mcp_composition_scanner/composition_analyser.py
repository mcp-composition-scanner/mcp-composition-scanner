#!/usr/bin/env python3
"""
Composition Analyser — Cross-server capability composition risk analysis.

Takes tool declarations from multiple MCP servers and evaluates the COMBINED
tool set for emergent composition risks (the "1+1=3 problem"):
capabilities that arise ONLY when tools from different servers are composed
by a reasoning model, and that no per-server review would detect.

Usage:
    # Analyze tools from multiple live MCP servers
    python -m mcp_composition_scanner.composition_analyser --servers ServerA ServerB

    # Analyze from saved result files (offline mode)
    python -m mcp_composition_scanner.composition_analyser --files results/server_a.json results/server_b.json

    # Analyze all servers in mcp.json
    python -m mcp_composition_scanner.composition_analyser --all
"""

import json
import asyncio
import os
import datetime
import re
import argparse
from typing import Optional

from agents import Agent, Runner
from fastmcp import Client

from .models import CompositionAnalysis


# ═══════════════════════════════════════════════════════════════════════════════
# Composition Analysis Prompt
# ═══════════════════════════════════════════════════════════════════════════════

COMPOSITION_SYSTEM_PROMPT = """
You are a security analyst AI specializing in COMPOSITIONAL THREAT ANALYSIS
for agentic AI tool ecosystems. You operate under the Model Context Protocol
(MCP) governance framework.

CRITICAL CONTEXT: You are analyzing tools from MULTIPLE MCP servers that will
be simultaneously available to a single AI agent. Current MCP governance
evaluates tools per-server or per-tool. Your job is to find what that
approach MISSES: emergent capabilities that arise ONLY when a reasoning
model combines tools across server boundaries.

THE 1+1=3 PROBLEM: A frontier reasoning model (GPT-4, Claude, etc.) does not
merely execute tools — it REASONS about tool combinations. Given a set of
tools and an objective, it will autonomously identify multi-step chains that
synthesize capabilities no individual tool provides. Each step may appear
benign; the composed trajectory is not.

YOUR ANALYSIS MUST:

1. CAPABILITY VECTOR MAPPING
   For each tool, assign coarse capability classes:
   ReadFiles, WriteFiles, Execute, NetworkEgress, NetworkIngress,
   InstallSoftware, DatabaseAccess, Messaging, Authentication,
   FinancialTransaction, CloudInfra, BrowserAutomation, Scheduling,
   CodeGeneration, PackageManagement, DNSManagement, CICD, Surveillance,
   DataExfiltration, SupplyChainModification

2. COMPOSITION SURPLUS IDENTIFICATION (Sigma_ij)
   For each PAIR (or higher-order group) of tools from DIFFERENT servers,
   determine whether:
     Cap(t_i ⊕ t_j) ⊃ Cap(t_i) ∪ Cap(t_j)
   That is: does combining them produce capabilities that NEITHER tool
   has alone? This is the composition surplus Σ_ij.

   Focus especially on CROSS-SERVER compositions — these are invisible to
   per-server authorization because each server's tools look safe in isolation.

   Consider environment conditions (E) under which the surplus materializes:
   - Does it require unrestricted network egress?
   - Does it require the ability to install software?
   - Does it require access to credentials or session tokens?
   - Would a sandboxed environment block it?

3. ATTACK CHAIN CONSTRUCTION
   For each non-trivial surplus, construct a realistic multi-step attack chain
   showing how a reasoning model would execute it. Each step should use a
   tool within its stated purpose. Show how human-in-the-loop approval would
   fail (each step looks benign individually).

4. GOVERNANCE GAP ANALYSIS
   Identify what a per-tool or per-server security review would miss.
   Be specific: "Server A's tools are individually low-risk; Server B's
   tools are individually low-risk; but combining tool X from A with
   tool Y from B enables [specific unauthorized capability]."

5. RECOMMENDATIONS
   Propose specific mitigations:
   - Mutual exclusion constraints ("tools X and Y must not be co-authorized")
   - Session-level capability tracking thresholds
   - Environment hardening requirements
   - Delegation depth limits if relevant

IMPORTANT GUIDELINES:
- Not all tool pairs produce surplus. Many are redundant or orthogonal.
  Only report GENUINE emergent capabilities.
- Severity should reflect the emergent capability, not the individual tools.
- Be concrete and specific. "Data could be exfiltrated" is too vague.
  "Tool A reads database records, Tool B sends HTTP POST — combined they
  enable autonomous exfiltration of query results to attacker-controlled
  endpoints" is specific enough.
- Consider that the model can chain MORE than two tools. Look for 3+ tool
  compositions where the chain is more dangerous than any pair.
- Consider temporal composition: tools used at different times but combined
  through the agent's memory/context.
"""


# ═══════════════════════════════════════════════════════════════════════════════
# Tool collection functions
# ═══════════════════════════════════════════════════════════════════════════════


async def collect_tools_from_server(url: str, server_name: str) -> list[dict]:
    """Connect to an MCP server and retrieve its tool declarations."""
    print(f"  Connecting to {server_name} ({url})...")
    try:
        client = Client(url)
        async with client:
            tools = await client.list_tools()
            tools_dicts = []
            for tool in tools:
                t = tool.model_dump()
                t["_server_origin"] = server_name
                t["_server_url"] = url
                tools_dicts.append(t)
            print(f"  ✓ {server_name}: {len(tools_dicts)} tools retrieved")
            return tools_dicts
    except Exception as e:
        print(f"  ✗ {server_name}: Failed to connect — {e}")
        return []


def collect_tools_from_result_file(filepath: str) -> list[dict]:
    """
    Extract tool names from a saved analysis result file.
    Since result files contain assessments (not raw tool declarations),
    we reconstruct minimal tool records from the assessment data.
    """
    base = os.path.basename(filepath)
    match = re.match(r"\d{8}-\d{6}-(.+)\.json", base)
    server_name = match.group(1) if match else base.replace(".json", "")

    with open(filepath, "r") as f:
        data = json.load(f)

    tools = []
    for assessment in data.get("tool_assessments", []):
        tools.append(
            {
                "name": assessment["tool_name"],
                "description": assessment.get("risk_summary", ""),
                "inputSchema": {},
                "_server_origin": server_name,
                "_source_file": filepath,
                "_original_risk_level": assessment.get("risk_level", "Unknown"),
            }
        )
    print(f"  ✓ {server_name} (from file): {len(tools)} tools extracted")
    return tools


def load_servers_from_mcp_json(mcp_path: str = None) -> dict:
    """Load server configurations from mcp.json."""
    if mcp_path is None:
        for candidate in ["mcp.json", "../mcp.json"]:
            if os.path.exists(candidate):
                mcp_path = candidate
                break
    if mcp_path is None or not os.path.exists(mcp_path):
        return {}

    with open(mcp_path, "r") as f:
        data = json.load(f)
    return data.get("servers", {})


# ═══════════════════════════════════════════════════════════════════════════════
# Composition analysis
# ═══════════════════════════════════════════════════════════════════════════════


async def analyze_composition(
    combined_tools: list[dict],
    server_names: list[str],
) -> CompositionAnalysis:
    """
    Run composition analysis on a combined tool set from multiple servers.

    This is the core function: it constructs a prompt with all tools annotated
    by server origin, then uses a structured-output agent to produce a
    CompositionAnalysis with surpluses, attack chains, and constraints.
    """
    n = len(combined_tools)
    pairwise = n * (n - 1) // 2

    # Build the user prompt with server-annotated tool declarations
    tools_by_server: dict[str, list[dict]] = {}
    for t in combined_tools:
        server = t.get("_server_origin", "unknown")
        if server not in tools_by_server:
            tools_by_server[server] = []
        tools_by_server[server].append(t)

    prompt_parts = [
        "COMPOSITION ANALYSIS REQUEST\n",
        f"Servers: {', '.join(server_names)}",
        f"Total tools: {n}",
        f"Pairwise combinations: {pairwise}\n",
        "─── Tool declarations by server ───\n",
    ]

    for server, tools in tools_by_server.items():
        prompt_parts.append(f"\n### Server: {server} ({len(tools)} tools)\n")
        clean_tools = []
        for t in tools:
            clean = {k: v for k, v in t.items() if not k.startswith("_")}
            clean_tools.append(clean)
        prompt_parts.append(json.dumps(clean_tools, indent=2))

    prompt_parts.append(
        f"\n─── Analysis request ───\n"
        f"Analyze the COMBINED tool set above for composition risks.\n"
        f"Focus on CROSS-SERVER compositions: capabilities that emerge from "
        f"combining tools from {' + '.join(server_names)} that would NOT be "
        f"detected by analyzing each server independently.\n"
        f"Apply the 1+1=3 framework: for each dangerous pair/group, identify "
        f"the composition surplus Σ_ij — the capability that exists ONLY in "
        f"the composition and is invisible to per-tool governance."
    )

    user_prompt = "\n".join(prompt_parts)

    agent = Agent(
        name="Composition Analysis Agent",
        instructions=COMPOSITION_SYSTEM_PROMPT,
        output_type=CompositionAnalysis,
    )

    print(f"\n▶ Running composition analysis on {n} tools from {len(server_names)} servers...")
    print(f"  Pairwise search space: {pairwise} combinations")
    result = await Runner.run(agent, user_prompt)
    return result.final_output


# ═══════════════════════════════════════════════════════════════════════════════
# Output
# ═══════════════════════════════════════════════════════════════════════════════


def save_composition_result(
    analysis: CompositionAnalysis,
    server_names: list[str],
    output_dir: str = None,
) -> str:
    """Save composition analysis result to a timestamped JSON file."""
    if output_dir is None:
        output_dir = os.path.join(os.getcwd(), "results", "compositions")
    os.makedirs(output_dir, exist_ok=True)

    now = datetime.datetime.now()
    date_time = now.strftime("%Y%m%d-%H%M%S")
    servers_tag = "+".join(s[:12] for s in server_names)
    filename = f"{date_time}-COMPOSITION-{servers_tag}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump(analysis.model_dump(), f, indent=2, ensure_ascii=False)

    return filepath


def print_composition_summary(analysis: CompositionAnalysis):
    """Print a human-readable summary of composition findings."""
    print("\n" + "═" * 70)
    print("  COMPOSITION ANALYSIS RESULTS")
    print("═" * 70)
    print(f"  Servers:    {', '.join(analysis.servers_analyzed)}")
    print(f"  Tools:      {analysis.total_tools}")
    print(f"  Pairs:      {analysis.pairwise_combinations}")
    print(f"  Risk Score: {analysis.composition_risk_score}")
    print(f"  Action:     {analysis.action}")
    print("─" * 70)

    if analysis.composition_surpluses:
        print(f"\n  ⚠ COMPOSITION SURPLUSES FOUND: {len(analysis.composition_surpluses)}\n")
        for s in analysis.composition_surpluses:
            cross = " [CROSS-SERVER]" if s.is_cross_server else ""
            print(f"  [{s.id}] {s.severity}{cross}")
            print(f"    Tools: {s.tool_a} ({s.tool_a_server}) ⊕ {s.tool_b} ({s.tool_b_server})")
            if s.additional_tools:
                print(f"    + {', '.join(s.additional_tools)}")
            print(f"    Emergent: {s.emergent_capability}")
            print(f"    Class: {s.emergent_capability_class}")
            print(f"    Environment: {s.environment_conditions}")
            print(f"    Gap: {s.existing_governance_gap}")
            print()
    else:
        print("\n  ✓ No composition surpluses detected.\n")

    if analysis.attack_chains:
        print(f"  ⚠ ATTACK CHAINS: {len(analysis.attack_chains)}\n")
        for chain in analysis.attack_chains:
            print(f"  [{chain.chain_id}] {chain.name} — {chain.severity}")
            print(f"    Final capability: {chain.final_capability}")
            print(f"    Approval bypass: {chain.human_approval_bypass}")
            for i, step in enumerate(chain.steps, 1):
                print(f"    Step {i}: {step}")
            print()

    if analysis.governance_blind_spots:
        print("  GOVERNANCE BLIND SPOTS:")
        for gap in analysis.governance_blind_spots:
            print(f"    • {gap}")
        print()

    if analysis.constraints:
        print("  RECOMMENDED CONSTRAINTS:")
        for c in analysis.constraints:
            print(f"    • {c}")
        print()

    print("═" * 70)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════


async def main():
    parser = argparse.ArgumentParser(
        description="Cross-server MCP composition risk analyzer (1+1=3 problem)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze two specific servers from mcp.json
  python -m mcp_composition_scanner.composition_analyser --servers ServerA ServerB

  # Analyze all servers in mcp.json together
  python -m mcp_composition_scanner.composition_analyser --all

  # Analyze from saved result files (offline)
  python -m mcp_composition_scanner.composition_analyser --files results/a.json results/b.json
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--servers", nargs="+", help="Server names from mcp.json to analyze together"
    )
    group.add_argument(
        "--files", nargs="+", help="Result JSON files to use as tool sources (offline mode)"
    )
    group.add_argument(
        "--all", action="store_true", help="Analyze all servers in mcp.json together"
    )
    parser.add_argument(
        "--mcp-config", default=None, help="Path to mcp.json (default: auto-detect)"
    )
    parser.add_argument(
        "--output-dir", default=None, help="Directory for result files (default: ./results/compositions)"
    )

    args = parser.parse_args()

    combined_tools = []
    server_names = []

    if args.files:
        print("Collecting tools from result files...")
        for filepath in args.files:
            if not os.path.exists(filepath):
                print(f"  ✗ File not found: {filepath}")
                continue
            tools = collect_tools_from_result_file(filepath)
            combined_tools.extend(tools)
            base = os.path.basename(filepath)
            match = re.match(r"\d{8}-\d{6}-(.+)\.json", base)
            name = match.group(1) if match else base
            if name not in server_names:
                server_names.append(name)

    elif args.servers or args.all:
        mcp_servers = load_servers_from_mcp_json(args.mcp_config)
        if not mcp_servers:
            print("Error: No servers found in mcp.json")
            return

        target_servers = list(mcp_servers.keys()) if args.all else args.servers

        print("Collecting tools from live MCP servers...")
        for name in target_servers:
            if name not in mcp_servers:
                print(f"  ✗ Server '{name}' not found in mcp.json")
                continue
            url = mcp_servers[name].get("url", "")
            if not url:
                print(f"  ✗ Server '{name}' has no URL configured")
                continue
            tools = await collect_tools_from_server(url, name)
            combined_tools.extend(tools)
            if name not in server_names:
                server_names.append(name)

    if len(combined_tools) < 2:
        print("\nError: Need at least 2 tools from 2+ servers for composition analysis.")
        return

    if len(server_names) < 2:
        print(
            "\nWarning: All tools come from a single server. Cross-server analysis is most"
            "\nvaluable with tools from multiple servers. Proceeding anyway.\n"
        )

    # Run composition analysis
    analysis = await analyze_composition(combined_tools, server_names)

    # Output
    print_composition_summary(analysis)

    filepath = save_composition_result(analysis, server_names, args.output_dir)
    print(f"\n  Results saved to: {filepath}")


if __name__ == "__main__":
    asyncio.run(main())
