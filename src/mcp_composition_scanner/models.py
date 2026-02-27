"""
Pydantic models for MCP Composition Scanner.

Defines the structured output types used by the composition analysis agent
to produce typed, machine-readable security assessments.
"""

from pydantic import BaseModel, Field
from typing import Literal


# ═══════════════════════════════════════════════════════════════════════════════
# Per-server tool analysis models
# ═══════════════════════════════════════════════════════════════════════════════


class PredictedPrecedence(BaseModel):
    """Analysis of which tool a model would prefer when functions overlap."""
    tools: list[str] = Field(description="List of tool names involved in the precedence conflict.")
    likely_selection: str = Field(description="The tool likely to be selected by the model.")
    reason: str = Field(description="Reasoning for why this tool takes precedence.")
    conflicting_tools: list[str] = Field(description="Other tools that conflict with the selected one.")


class OverlappingFunctionality(BaseModel):
    """Detection of overlapping or redundant tool functionality."""
    description: str = Field(description="Description of the overlapping functionality issue.")
    predicted_precedence: list[PredictedPrecedence] = Field(
        description="Analysis of which tools might take precedence in case of overlap."
    )


class IssueCategory(BaseModel):
    """A category of issues found in tool declarations."""
    description: str = Field(description="Description of the issue category.")
    affected_tools: list[str] = Field(description="List of tools affected by this issue.")


class Recommendations(BaseModel):
    """Actionable recommendations for risk mitigation."""
    suggestions: list[str] = Field(description="List of actionable recommendations to mitigate risks.")


class ToolRiskAssessment(BaseModel):
    """Per-tool security risk assessment."""
    tool_name: str = Field(description="Name of the tool being assessed.")
    risk_summary: str = Field(description="Brief summary of the risks associated with this tool.")
    suspicious_language_patterns: list[str] = Field(
        description="List of specific phrases or patterns identified as suspicious."
    )
    risk_level: Literal["Low", "Medium", "High"] = Field(
        description="Assessed risk level for this tool."
    )
    mitigation_suggestions: list[str] = Field(
        description="Suggestions to mitigate the identified risks."
    )


class StructuredAnalysis(BaseModel):
    """Full per-server tool analysis output."""
    tool_assessments: list[ToolRiskAssessment] = Field(
        description="Detailed risk assessment for each tool."
    )
    overall_risk_score: Literal["Low", "Medium", "High"] = Field(
        description="Overall risk score for the entire set of tools."
    )
    risk_evaluation_summary: str = Field(description="Summary of the overall risk evaluation.")
    attack_paths: list["AttackPath"] = Field(
        description="List of identified attack paths that could exploit these tools."
    )
    overlapping_functionality: OverlappingFunctionality = Field(
        description="Analysis of overlapping functionality between tools."
    )
    influencing_or_persuasive_language: IssueCategory = Field(
        description="Analysis of influencing or persuasive language used in tool descriptions."
    )
    crafted_or_informal_tone: IssueCategory = Field(
        description="Analysis of crafted or informal tone in tool descriptions."
    )
    attention_seeking_wording: IssueCategory = Field(
        description="Analysis of attention-seeking wording."
    )
    inconsistency_in_tone_or_structure: IssueCategory = Field(
        description="Analysis of inconsistencies in tone or structure."
    )
    agentic_capability_tool_delta_expansion_risk: IssueCategory = Field(
        description="Risk assessment of agentic capability expansion."
    )
    recommendations: Recommendations = Field(
        description="Overall recommendations for the toolset."
    )
    action: Literal["ALLOW", "BLOCK"] = Field(
        description="Recommended action: ALLOW or BLOCK the toolset."
    )


class AttackPath(BaseModel):
    """A single-server attack path exploiting tool interactions."""
    description: str = Field(description="Description of the attack path.")
    involved_tools: list[str] = Field(description="Tools involved in this attack path.")
    severity: Literal["Low", "Medium", "High", "Critical"] = Field(
        description="Severity level of this attack path."
    )
    steps: list[str] = Field(
        description="Step-by-step breakdown of how the attack path could be executed."
    )
    mitigation: str = Field(description="Recommended mitigation or prevention strategy.")


class Capabilities_Delta(BaseModel):
    """Capability delta: expansion of capability surface through tool combination."""
    description: str = Field(description="Description of the capability delta.")
    affected_tools: list[str] = Field(
        description="Tools that contribute to this capability expansion."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Cross-server composition analysis models
# ═══════════════════════════════════════════════════════════════════════════════


class CapabilityClass(BaseModel):
    """Coarse capability class assigned to a tool (e.g., ReadFiles, NetworkEgress)."""
    class_name: str = Field(
        description=(
            "Capability class name (e.g., ReadFiles, WriteFiles, Execute, "
            "NetworkEgress, InstallSoftware, DatabaseAccess, Messaging, "
            "Authentication, FinancialTransaction, CloudInfra)."
        )
    )
    confidence: Literal["Low", "Medium", "High"] = Field(
        description="Confidence that this tool provides this capability class."
    )


class ToolCapabilityVector(BaseModel):
    """Maps a single tool to its capability classes."""
    tool_name: str = Field(description="Name of the tool.")
    server_origin: str = Field(description="Which MCP server this tool originates from.")
    capability_classes: list[CapabilityClass] = Field(
        description="List of capability classes this tool provides."
    )


class CompositionSurplus(BaseModel):
    """
    A single Σ_ij: emergent capability from composing two or more tools.

    Represents the composition surplus — the capability that exists ONLY
    through composition and would not be detected by per-server review.
    """
    id: str = Field(description="Identifier for this composition (e.g., 'S1', 'S2').")
    tool_a: str = Field(description="First tool in the composition.")
    tool_a_server: str = Field(description="Server origin of tool A.")
    tool_b: str = Field(description="Second tool in the composition.")
    tool_b_server: str = Field(description="Server origin of tool B.")
    additional_tools: list[str] = Field(
        default_factory=list,
        description="Any additional tools required for this composition chain."
    )
    emergent_capability: str = Field(
        description=(
            "The capability that emerges ONLY through composition and does "
            "NOT exist in either tool alone."
        )
    )
    emergent_capability_class: str = Field(
        description=(
            "Capability class of the emergent capability (e.g., Surveillance, "
            "DataExfiltration, SupplyChainCompromise, UnauthorizedPurchase, "
            "PrivilegeEscalation)."
        )
    )
    severity: Literal["Low", "Medium", "High", "Critical"] = Field(
        description="Severity of the emergent capability."
    )
    reasoning: str = Field(
        description="Step-by-step reasoning for how a frontier model could chain these tools."
    )
    is_cross_server: bool = Field(
        description="True if the composed tools originate from different MCP servers."
    )
    environment_conditions: str = Field(
        description=(
            "Environment conditions (E) under which this surplus materializes "
            "(e.g., 'no egress filtering', 'sandbox allows pip install')."
        )
    )
    existing_governance_gap: str = Field(
        description="Which governance control (if any) would catch this, and why it likely doesn't."
    )


class CompositionAttackChain(BaseModel):
    """A multi-step attack chain exploiting composition surplus."""
    chain_id: str = Field(description="Identifier for this attack chain.")
    name: str = Field(description="Short descriptive name for the attack chain.")
    composition_surpluses_used: list[str] = Field(
        description="IDs of CompositionSurplus entries used in this chain."
    )
    steps: list[str] = Field(
        description="Ordered steps a reasoning model would take to execute this chain."
    )
    final_capability: str = Field(
        description="The ultimate unauthorized capability achieved."
    )
    severity: Literal["Low", "Medium", "High", "Critical"] = Field(
        description="Overall severity of the attack chain."
    )
    human_approval_bypass: str = Field(
        description="How each step could appear benign to a human-in-the-loop approver."
    )
    mitigation: str = Field(description="Recommended mitigation strategy.")


class CompositionAnalysis(BaseModel):
    """
    Full cross-server composition risk analysis output.

    This is the primary output type for the composition scanner. It captures
    the complete analysis: tool vectors, composition surpluses (Σ_ij),
    attack chains, governance blind spots, and recommended constraints.
    """
    servers_analyzed: list[str] = Field(
        description="List of MCP server names whose tools were included in this analysis."
    )
    total_tools: int = Field(description="Total number of tools across all servers.")
    pairwise_combinations: int = Field(
        description="Number of pairwise tool combinations evaluated (n*(n-1)/2)."
    )
    tool_capability_vectors: list[ToolCapabilityVector] = Field(
        description="Capability class mapping for each tool."
    )
    composition_surpluses: list[CompositionSurplus] = Field(
        description=(
            "All identified composition surpluses (Σ_ij) where composed capability "
            "exceeds the union of individual capabilities."
        )
    )
    attack_chains: list[CompositionAttackChain] = Field(
        description="Multi-step attack chains exploiting composition surpluses."
    )
    cross_server_risk_summary: str = Field(
        description=(
            "Summary of risks that arise SPECIFICALLY from combining tools "
            "across different MCP servers."
        )
    )
    composition_risk_score: Literal["Low", "Medium", "High", "Critical"] = Field(
        description="Overall composition risk score for the combined tool set."
    )
    governance_blind_spots: list[str] = Field(
        description=(
            "Specific governance gaps: what a per-tool or per-server "
            "authorization review would miss."
        )
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations to mitigate composition risks."
    )
    action: Literal["ALLOW", "BLOCK", "ALLOW_WITH_CONSTRAINTS"] = Field(
        description=(
            "Recommended action for the combined toolset. ALLOW_WITH_CONSTRAINTS "
            "means allow but enforce mutual exclusion or session-level monitoring."
        )
    )
    constraints: list[str] = Field(
        default_factory=list,
        description=(
            "If action is ALLOW_WITH_CONSTRAINTS, the specific constraints to "
            "enforce (e.g., 'tool A and tool B must not be co-invoked in same session')."
        )
    )
