#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# MCP Composition Scanner — Evaluation Test Suite
# ═══════════════════════════════════════════════════════════════════════════════
#
# Runs the composition scanner across selected server pairs to build
# an evaluation dataset for the research paper.
#
# Categories:
#   HIGH-RISK pairs   — expect composition surpluses (Σ_ij > 0)
#   CONTROL pairs     — expect no/minimal surpluses (Σ_ij ≈ 0)
#
# Usage:
#   chmod +x run_evaluation.sh
#   ./run_evaluation.sh
#
# Prerequisites:
#   - OPENAI_API_KEY set in environment
#   - pip install -e . (from repo root)
# ═══════════════════════════════════════════════════════════════════════════════

set -e

SERVERS_DIR="test-servers"
RESULTS_DIR="results/evaluation"
mkdir -p "$RESULTS_DIR"

echo "═══════════════════════════════════════════════════════════════════════"
echo "  MCP Composition Scanner — Evaluation Suite"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

# ─── HIGH-RISK PAIRS (expect surpluses) ───────────────────────────────────────

HIGH_RISK_PAIRS=(
    # Pair 1: DB read → email exfiltration
    "postgres:sendgrid"
    # Pair 2: Local files → external URL
    "filesystem:fetch"
    # Pair 3: Message read → public repo push
    "slack:github"
    # Pair 4: Browser scrape → email out
    "puppeteer:sendgrid"
    # Pair 5: Cluster secrets → command execution
    "kubernetes:bash-executor"
    # Pair 6: DB query → cloud storage upload
    "sqlite:gdrive"
    # Pair 7: Command exec + cloud storage = full exfil
    "desktop-commander:s3"
    # Pair 8: Cache/session data → browser replay
    "redis:puppeteer"
    # Pair 9: Git history (leaked secrets) → email
    "git:sendgrid"
    # Pair 10: Knowledge graph context → messaging
    "memory:slack"
)

# ─── CONTROL PAIRS (expect minimal/no surpluses) ─────────────────────────────

CONTROL_PAIRS=(
    # Control 1: Both read-only, orthogonal domains
    "google-maps:memory"
    # Control 2: Both read-only information retrieval
    "fetch:google-maps"
    # Control 3: Two databases, redundant not compositional
    "postgres:sqlite"
)

# ─── BONUS: 3-SERVER COMPOSITIONS ────────────────────────────────────────────

TRIPLE_COMPOSITIONS=(
    # Triple 1: Read DB → process locally → email out
    "postgres:desktop-commander:sendgrid"
    # Triple 2: Browse web → store in Redis → push to GitHub
    "puppeteer:redis:github"
)

run_pair() {
    local server_a="$1"
    local server_b="$2"
    local category="$3"
    local pair_num="$4"

    local file_a="${SERVERS_DIR}/20260227-120000-${server_a}.json"
    local file_b="${SERVERS_DIR}/20260227-120000-${server_b}.json"

    if [ ! -f "$file_a" ]; then
        echo "  ✗ Missing: $file_a"
        return 1
    fi
    if [ ! -f "$file_b" ]; then
        echo "  ✗ Missing: $file_b"
        return 1
    fi

    echo ""
    echo "──────────────────────────────────────────────────────────────────"
    echo "  [${category} #${pair_num}] ${server_a} + ${server_b}"
    echo "──────────────────────────────────────────────────────────────────"

    python run_scan.py --files "$file_a" "$file_b" \
        --output-dir "$RESULTS_DIR" \
        2>&1 | tee "${RESULTS_DIR}/log-${category}-${pair_num}-${server_a}+${server_b}.txt"

    echo "  ✓ Complete: ${server_a} + ${server_b}"
}

run_triple() {
    local server_a="$1"
    local server_b="$2"
    local server_c="$3"
    local pair_num="$4"

    local file_a="${SERVERS_DIR}/20260227-120000-${server_a}.json"
    local file_b="${SERVERS_DIR}/20260227-120000-${server_b}.json"
    local file_c="${SERVERS_DIR}/20260227-120000-${server_c}.json"

    echo ""
    echo "──────────────────────────────────────────────────────────────────"
    echo "  [TRIPLE #${pair_num}] ${server_a} + ${server_b} + ${server_c}"
    echo "──────────────────────────────────────────────────────────────────"

    python run_scan.py --files "$file_a" "$file_b" "$file_c" \
        --output-dir "$RESULTS_DIR" \
        2>&1 | tee "${RESULTS_DIR}/log-TRIPLE-${pair_num}-${server_a}+${server_b}+${server_c}.txt"

    echo "  ✓ Complete: ${server_a} + ${server_b} + ${server_c}"
}

# ─── RUN HIGH-RISK PAIRS ─────────────────────────────────────────────────────

echo ""
echo "▶ Running HIGH-RISK pairs (10 pairs, expect composition surpluses)..."
echo ""

pair_num=1
for pair in "${HIGH_RISK_PAIRS[@]}"; do
    IFS=':' read -r server_a server_b <<< "$pair"
    run_pair "$server_a" "$server_b" "HIGH" "$pair_num" || true
    pair_num=$((pair_num + 1))
done

# ─── RUN CONTROL PAIRS ───────────────────────────────────────────────────────

echo ""
echo "▶ Running CONTROL pairs (3 pairs, expect minimal/no surpluses)..."
echo ""

pair_num=1
for pair in "${CONTROL_PAIRS[@]}"; do
    IFS=':' read -r server_a server_b <<< "$pair"
    run_pair "$server_a" "$server_b" "CTRL" "$pair_num" || true
    pair_num=$((pair_num + 1))
done

# ─── RUN TRIPLE COMPOSITIONS ─────────────────────────────────────────────────

echo ""
echo "▶ Running TRIPLE compositions (2 triples, higher-order chains)..."
echo ""

pair_num=1
for triple in "${TRIPLE_COMPOSITIONS[@]}"; do
    IFS=':' read -r server_a server_b server_c <<< "$triple"
    run_triple "$server_a" "$server_b" "$server_c" "$pair_num" || true
    pair_num=$((pair_num + 1))
done

# ─── SUMMARY ─────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "  EVALUATION COMPLETE"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "  Results saved to: ${RESULTS_DIR}/"
echo "  Total runs: $((${#HIGH_RISK_PAIRS[@]} + ${#CONTROL_PAIRS[@]} + ${#TRIPLE_COMPOSITIONS[@]}))"
echo ""
echo "  High-risk pairs: ${#HIGH_RISK_PAIRS[@]}"
echo "  Control pairs:   ${#CONTROL_PAIRS[@]}"
echo "  Triple combos:   ${#TRIPLE_COMPOSITIONS[@]}"
echo ""
echo "  Next: run summarize_evaluation.py to build the results table"
echo "═══════════════════════════════════════════════════════════════════════"
