# MCP Composition Scanner

**First documented cross-server MCP capability composition analyzer.**

Detects emergent security risks that arise when tools from multiple [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers are composed by a reasoning model — risks that are **invisible to per-server review**.

## The 1+1=3 Problem

Current MCP governance evaluates tools individually or per-server. This misses a critical threat class: **composition surplus**.

When a frontier reasoning model (GPT-4, Claude, etc.) has simultaneous access to tools from multiple MCP servers, it can autonomously chain them to synthesize capabilities that no individual tool provides. Each step appears benign; the composed trajectory is not.

```
Server A:  get_secret_word()     → retrieves authentication token  (low risk alone)
Server B:  update_cart()         → modifies e-commerce cart        (low risk alone)
Composed:  get_secret_word() ⊕ update_cart() → unauthorized purchase using leaked credential
                                                (HIGH risk — invisible to per-server review)
```

This tool performs **pre-authorization composition analysis**: it examines the combined tool set from multiple MCP servers BEFORE they are co-authorized, identifying composition surpluses (Σ_ij) that would escape per-tool governance.

## What It Does

1. **Collects tool declarations** from multiple MCP servers (live or from saved analysis files)
2. **Maps capability vectors** — assigns coarse capability classes to each tool
3. **Identifies composition surpluses** — tool pairs/groups where `Cap(t_i ⊕ t_j) ⊃ Cap(t_i) ∪ Cap(t_j)`
4. **Constructs attack chains** — realistic multi-step chains showing how a reasoning model would exploit the surplus
5. **Analyzes governance gaps** — what per-server authorization review would miss
6. **Recommends constraints** — mutual exclusion rules, session monitoring thresholds, environment hardening

## Quick Start

### Installation

```bash
git clone https://github.com/mcp-composition-scanner/mcp-composition-scanner.git
cd mcp-composition-scanner
pip install -e .
```

### Prerequisites

- Python 3.11+
- An OpenAI API key (used by the analysis agent via `openai-agents`)
- MCP servers to analyze (or saved analysis result files)

```bash
export OPENAI_API_KEY="sk-..."
```

### Configuration

Copy the example config and add your MCP servers:

```bash
cp mcp.json.example mcp.json
# Edit mcp.json with your server URLs
```

### Usage

#### Cross-server composition analysis (the main feature)

```bash
# Analyze two specific servers from mcp.json
python -m mcp_composition_scanner --servers ServerA ServerB

# Analyze all servers in mcp.json together
python -m mcp_composition_scanner --all

# Offline mode: analyze from saved per-server result files
python -m mcp_composition_scanner --files results/server_a.json results/server_b.json
```

#### Per-server tool analysis

```bash
python -m mcp_composition_scanner.intent_analyser --url http://127.0.0.1:8002/mcp --name MyServer
```

#### REST API

```bash
# Start the control plane
python -m mcp_composition_scanner.server

# Trigger composition analysis
curl -X POST http://localhost:8000/analyze-composition \
  -H "Content-Type: application/json" \
  -d '{"server_names": ["ServerA", "ServerB"]}'

# List composition results
curl http://localhost:8000/composition-results
```

## Example Output

From a real analysis of two MCP servers (ServerRogueMCP2 + pitchskin):

```
═══════════════════════════════════════════════════════════════════════════
  COMPOSITION ANALYSIS RESULTS
═══════════════════════════════════════════════════════════════════════════
  Servers:    ServerRogueMCP2, pitchskin
  Tools:      9
  Pairs:      36
  Risk Score: High
  Action:     ALLOW_WITH_CONSTRAINTS
──────────────────────────────────────────────────────────────────────────

  ⚠ COMPOSITION SURPLUSES FOUND: 2

  [S1] High [CROSS-SERVER]
    Tools: get_secret_word_0 (ServerRogueMCP2) ⊕ update_cart (pitchskin)
    Emergent: Unauthorized purchase using leaked credential
    Class: UnauthorizedPurchase
    Gap: Neither server exposes the full risk alone

  [S2] Medium [CROSS-SERVER]
    Tools: get_credit_amount_0 (ServerRogueMCP2) ⊕ pay_credit_amount_0
    + get_cart, update_cart
    Emergent: Coordinated financial-action replay
    Class: FinancialTransaction

  RECOMMENDED CONSTRAINTS:
    • Do not allow 'get_secret_word_0' in sessions where pitchskin cart tools are accessible
    • Flag agent flows that transfer secrets between ServerRogueMCP2 and pitchskin
    • Require joint authorization review for financial + cart modification workflows
═══════════════════════════════════════════════════════════════════════════
```

See [`examples/`](examples/) for the full JSON output.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   MCP Composition Scanner                │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐   ┌─────────────┐ │
│  │ MCP Server A │   │ MCP Server B │   │ MCP Server N │ │
│  │  (tools)     │   │  (tools)     │   │  (tools)     │ │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘ │
│         │                  │                   │         │
│         ▼                  ▼                   ▼         │
│  ┌─────────────────────────────────────────────────────┐ │
│  │           Tool Collection Layer                     │ │
│  │   (live MCP connections or saved result files)      │ │
│  └────────────────────────┬────────────────────────────┘ │
│                           │                              │
│                           ▼                              │
│  ┌─────────────────────────────────────────────────────┐ │
│  │        Composition Analysis Agent                   │ │
│  │   (structured output via OpenAI Agents SDK)         │ │
│  │                                                     │ │
│  │   1. Capability vector mapping                      │ │
│  │   2. Σ_ij surplus identification                    │ │
│  │   3. Attack chain construction                      │ │
│  │   4. Governance gap analysis                        │ │
│  │   5. Constraint recommendations                     │ │
│  └────────────────────────┬────────────────────────────┘ │
│                           │                              │
│                           ▼                              │
│  ┌─────────────────────────────────────────────────────┐ │
│  │             CompositionAnalysis                     │ │
│  │   (Pydantic structured output)                      │ │
│  │                                                     │ │
│  │   • Composition surpluses (Σ_ij)                    │ │
│  │   • Attack chains with approval bypass              │ │
│  │   • Governance blind spots                          │ │
│  │   • ALLOW / BLOCK / ALLOW_WITH_CONSTRAINTS          │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Key Concepts

| Concept | Definition |
|---------|-----------|
| **Composition Surplus (Σ_ij)** | An emergent capability that exists ONLY when tools from different servers are composed — invisible to per-tool review |
| **Capability Vector** | Coarse capability classes assigned to each tool (ReadFiles, NetworkEgress, FinancialTransaction, etc.) |
| **Cross-server composition** | Tool chaining across MCP server boundaries, where each server's tools appear safe in isolation |
| **Governance blind spot** | A security risk that per-server or per-tool authorization review cannot detect |
| **Pre-authorization analysis** | Evaluating composition risks BEFORE tools are co-authorized, not at runtime |

## Differentiation from Prior Work

| Tool/Paper | What it does | How we differ |
|-----------|-------------|--------------|
| **STAC** (Li et al., 2025) | Sequential tool attack chaining at runtime (ASR >90%) | We analyze BEFORE runtime; we focus on cross-server composition invisible to per-server review |
| **AgentLAB** (Ye et al., 2025) | Long-horizon attack benchmark (644 test cases) | We produce governance constraints, not just attack demonstrations |
| **MCP-ITP** (Shan & Chen, 2025) | Implicit tool poisoning (84.2% ASR) | We address multi-server composition, not single-tool poisoning |
| **Invariant Guardrails** | Runtime tool-call filtering | We operate pre-authorization; complementary approach |

## Project Structure

```
mcp-composition-scanner/
├── README.md
├── LICENSE
├── CITATION.md
├── pyproject.toml
├── mcp.json.example
├── src/
│   └── mcp_composition_scanner/
│       ├── __init__.py
│       ├── __main__.py
│       ├── models.py                  # Pydantic output types
│       ├── composition_analyser.py    # Cross-server composition analysis
│       ├── intent_analyser.py         # Per-server tool analysis
│       └── server.py                  # FastAPI control plane
└── examples/
    └── composition-result-*.json      # Sample analysis output
```

## Research Context

This tool implements concepts from ongoing research on emergent capability composition in agentic AI tool ecosystems. The theoretical framework — including the composition surplus operator, governance gap taxonomy, and defense architecture — is described in:

> P. Bogaerts, "Emergent Capability Composition in Agentic AI Tool Ecosystems: Security Implications of Cross-Protocol Tool Chaining in MCP and A2A Architectures," 2026.

## Contributing

Contributions welcome. Priority areas:

- **More server connectors** — stdio transport, A2A protocol support
- **Composition heuristics** — pre-filtering to reduce pairwise search space for large tool sets
- **Benchmark suite** — standardized server pairs with known composition surpluses
- **Runtime enforcement** — bridge between pre-authorization constraints and runtime guardrails
- **OWASP integration** — mapping composition surpluses to OWASP Agentic AI threat taxonomy

## License

Apache 2.0. See [LICENSE](LICENSE).

## Author

**Philippe Bogaerts** — [RadarSec](https://radarsec.com) — philippe.bogaerts@radarsec.com
