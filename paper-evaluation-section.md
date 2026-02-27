# Section 6: Empirical Evaluation

## 6.1 Experimental Design

To evaluate the composition scanner's ability to detect emergent cross-server capabilities, we constructed a systematic test suite comprising 15 server-pair compositions drawn from 17 widely-deployed MCP servers. Tool declarations were collected from production-representative server configurations including database servers (PostgreSQL, SQLite), messaging platforms (SendGrid, Slack), cloud infrastructure (Kubernetes, S3, Google Drive), development tools (GitHub, Git), browser automation (Puppeteer), local system access (Desktop Commander, Filesystem, Bash Executor), data stores (Redis, Memory), and information retrieval services (Fetch, Google Maps).

Each server's tool declarations were captured as structured JSON containing tool names, descriptions, and input schemas—the same metadata available to an LLM agent at runtime. The scanner was then run across three categories of compositions:

**High-Risk Pairs (n=10).** Server combinations hypothesised to produce composition surpluses based on complementary capability classes. For example, a database-read server paired with an email-send server creates a potential data exfiltration channel invisible to per-server review.

**Control Pairs (n=3).** Server combinations expected to produce minimal or no surpluses, selected for domain orthogonality or functional redundancy: two read-only information retrieval servers (Fetch + Google Maps), two database servers (PostgreSQL + SQLite), and a location service paired with a knowledge graph (Google Maps + Memory).

**Triple Compositions (n=2).** Three-server combinations to test higher-order chain detection: PostgreSQL + Desktop Commander + SendGrid, and Puppeteer + Redis + GitHub.

All 15 runs used identical scanner configuration (GPT-4o as the reasoning backbone, structured output via Pydantic models, temperature 0). Each run produces a `CompositionAnalysis` object containing capability vectors, composition surpluses with severity ratings, attack chains, and governance recommendations.

## 6.2 Results

### 6.2.1 Summary Statistics

Table 1 presents the aggregate results across all 15 compositions.

| Category | Runs | Avg Tools | Avg Surpluses | Critical | High | Medium | Low |
|---|---|---|---|---|---|---|---|
| High-Risk Pairs | 10 | 16.6 | 3.9 | 7 | 24 | 8 | 0 |
| Control Pairs | 3 | 12.3 | 2.7 | 0 | 6 | 2 | 0 |
| Triple Compositions | 2 | 41.5 | 4.0 | 6 | 2 | 0 | 0 |
| **Total** | **15** | **19.1** | **3.7** | **13** | **32** | **10** | **0** |

Three key observations emerge.

First, **composition surplus is pervasive**: every single composition—including all three control pairs—produced at least two surpluses. The binary question "does this pair produce emergent capabilities?" was answered affirmatively in 100% of cases (15/15). This result is more significant than a clean separation between high-risk and control pairs: it demonstrates that capability composition is a structural property of multi-server MCP deployments, not an edge case confined to obviously dangerous combinations.

Second, **severity gradient discriminates risk**: while surpluses were universal, the severity distribution was not. High-risk pairs produced 7 Critical-severity surpluses across 10 runs; control pairs produced zero. The ratio of Critical+High to total surpluses was 0.79 for high-risk pairs versus 0.75 for controls—but the absolute Critical count (the category requiring immediate remediation) cleanly separated the groups. Triple compositions amplified this: with only 2 runs, they produced 6 Critical findings, including 4 in a single analysis (PostgreSQL + Desktop Commander + SendGrid).

Third, **all surpluses were cross-server**: 100% of detected surpluses involved tools from different servers (55/55). This confirms the central thesis—that composition risk is invisible to per-server governance. No surplus was flagged for tools co-located on the same server, validating that the scanner focuses on the inter-server boundary where current review processes have no visibility.

### 6.2.2 High-Risk Pair Findings

The high-risk pairs validated the scanner's ability to identify canonical composition attack patterns.

**Data Exfiltration Chains.** The most frequently detected pattern combined a data-read capability with a network-egress capability. The PostgreSQL + SendGrid composition identified that the `query` tool (read-only, classified as safe in isolation) combined with `send_email` creates autonomous database exfiltration to arbitrary email recipients. The scanner correctly noted the governance gap: "Per-server authorization classifies 'query' as read-only (safe) and 'send_email' as internal-messaging (safe); no per-tool analysis detects that, when cross-authorized, these enable full database exfiltration."

**Infrastructure Compromise.** The Kubernetes + Bash Executor pair—with only 6 total tools and 15 pairwise combinations—produced 3 surpluses, 2 at Critical severity. The scanner identified that `kubectl get secrets` chained with arbitrary command execution enables credential harvesting and lateral movement, a composition requiring only two tool invocations but granting cluster-wide compromise.

**Escalation Through Local Execution.** Desktop Commander + S3 (5 surpluses, 1 Critical) and Git + SendGrid (4 surpluses, 1 Critical) demonstrated that filesystem or repository access combined with cloud storage or messaging tools creates egress channels for sensitive data. The scanner identified specific multi-step chains: file discovery → content reading → cloud upload, and git log parsing (for leaked secrets) → email transmission.

### 6.2.3 Control Pair Findings: Reinterpreting "Safe" Compositions

The control pairs were designed as negative controls, yet each produced genuine composition surpluses. Rather than representing false positives, closer examination reveals these findings to be legitimate—and instructive.

**PostgreSQL + SQLite (3 surpluses, 0 Critical, 2 High, 1 Medium).** The scanner identified cross-database data migration as a composition surplus: the `query` tool on PostgreSQL combined with `create_record` on SQLite enables autonomous data copying from a production database to a less-controlled local store. It also detected targeted record purging—using PostgreSQL query results to drive SQLite deletions—as a supply-chain modification risk. These are real composition capabilities: neither server alone can read from one database and write to another, yet the composition enables exactly this.

**Google Maps + Memory (3 surpluses, 0 Critical, 2 High, 1 Medium).** The scanner detected that reverse geocoding combined with knowledge graph persistence creates a "persistent, queryable geolocation surveillance graph." While neither tool alone enables location tracking, their composition allows an agent to resolve coordinates to addresses and store them as longitudinal observations tied to entities—effectively building surveillance dossiers through individually benign operations.

**Fetch + Google Maps (2 surpluses, 0 Critical, 2 High).** Combining web content retrieval with geolocation services enables deanonymisation and location-correlated intelligence gathering. The scanner identified that fetching web content containing location references, then enriching those references via the Maps API, creates an OSINT-style reconnaissance capability absent from either server individually.

The critical insight is that control pairs exhibited a qualitatively different risk profile from high-risk pairs. The severity gradient—not the binary presence of surpluses—is the meaningful discriminator:

| Metric | High-Risk (n=10) | Control (n=3) |
|---|---|---|
| Mean surpluses per run | 3.9 | 2.7 |
| Critical-severity surpluses | 7 | 0 |
| Attack chains involving network egress | 17 | 0 |
| DataExfiltration class surpluses | 12 | 0 |

Control pairs produce surpluses in lower-severity categories (Surveillance, DataEnrichment, SupplyChainModification) while completely lacking the Critical-severity DataExfiltration patterns that dominate high-risk compositions. This suggests a natural severity threshold for governance decisions: compositions producing Critical surpluses require mutual exclusion constraints or human-in-the-loop approval, while those producing only Medium/High surpluses may be permitted with monitoring.

### 6.2.4 Higher-Order Compositions

The two triple compositions demonstrated superlinear growth in both attack surface and severity.

**PostgreSQL + Desktop Commander + SendGrid (32 tools, 496 pairwise combinations, 4 surpluses—all Critical).** This three-server composition produced the highest concentration of Critical findings in the dataset. The scanner identified a complete data exfiltration pipeline: database query → local file staging (with optional transformation via process execution) → email transmission. The three-server composition enabled attack chains impossible with any two-server subset, including code-execution-assisted data packaging before exfiltration.

**Puppeteer + Redis + GitHub (51 tools, 1275 pairwise combinations, 4 surpluses, 2 Critical).** Browser automation combined with session data access and repository write access creates both credential harvesting (scrape → cache → exfiltrate) and supply chain poisoning (browse → extract → commit malicious code) chains.

The pairwise search space grew from an average of 143 combinations for pairs to 886 for triples. Despite this 6× increase, the scanner maintained consistent analysis quality, suggesting the approach scales to realistic deployment configurations where 5–10 servers may be simultaneously authorised.

## 6.3 Threats to Validity

**LLM Reasoning Sensitivity.** The scanner relies on GPT-4o's reasoning about tool semantics. Different models or temperatures may produce different surplus counts. We mitigated this by using temperature 0 and structured output constraints, but acknowledge that LLM-based analysis introduces non-determinism. Future work should quantify inter-model agreement and test-retest reliability.

**Tool Declaration Fidelity.** Our evaluation used tool declarations collected from reference MCP server implementations. Real-world deployments may have customised tool descriptions, renamed functions, or omitted schema details. The scanner's effectiveness depends on the semantic richness of tool descriptions—minimal or obfuscated declarations would reduce detection accuracy.

**Ground Truth.** We lack a formal ground-truth dataset of composition surpluses against which to measure precision and recall. Our evaluation relies on expert assessment of whether detected surpluses represent genuine emergent capabilities. Constructing such a benchmark is an important direction for future work.

**Scope.** The evaluation covers 17 servers and 15 compositions. While these span representative capability classes (database, messaging, filesystem, cloud, browser), the MCP ecosystem contains hundreds of servers. Broader coverage would strengthen generalisability claims.

## 6.4 Key Findings

The evaluation supports three principal claims.

**Claim 1: Composition surplus is structural, not exceptional.** All 15 compositions, including controls, produced surpluses. This indicates that multi-server MCP deployments inherently create emergent capabilities invisible to per-server review. The relevant governance question is not "does this composition create new capabilities?" (the answer is almost always yes) but "how severe are the emergent capabilities?"

**Claim 2: Severity gradient enables actionable governance.** The clean separation of Critical-severity findings between high-risk pairs (7 Critical) and control pairs (0 Critical) demonstrates that the scanner produces a usable risk signal. Critical findings consistently involved DataExfiltration or infrastructure compromise patterns requiring immediate remediation, while lower-severity findings in control pairs involved DataEnrichment or Surveillance patterns amenable to monitoring-based controls.

**Claim 3: Pre-authorisation analysis is feasible and informative.** The scanner operates entirely on static tool declarations—no runtime execution, no prompt injection risk, no agent behaviour observation required. Analysis completes in under 60 seconds per composition and produces structured, actionable output including specific mutual-exclusion recommendations. This positions composition scanning as a practical addition to MCP server review workflows, complementary to runtime monitoring approaches.
