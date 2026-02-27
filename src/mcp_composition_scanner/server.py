#!/usr/bin/env python3
"""
FastAPI control plane for MCP Composition Scanner.

Provides REST endpoints for:
- Per-server tool analysis
- Cross-server composition risk analysis
- Result retrieval
"""

import json
import asyncio
import os
import glob
import re
from typing import List, Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel, validator
import uvicorn

from .intent_analyser import analyze_server
from .composition_analyser import (
    collect_tools_from_server,
    collect_tools_from_result_file,
    analyze_composition,
    save_composition_result,
    load_servers_from_mcp_json,
)

app = FastAPI(
    title="MCP Composition Scanner",
    description="Cross-server capability composition risk analysis for MCP tool ecosystems",
    version="0.1.0",
)


# ═══════════════════════════════════════════════════════════════════════════════
# Request/Response models
# ═══════════════════════════════════════════════════════════════════════════════


class UrlRequest(BaseModel):
    url: str
    server_name: Optional[str] = None

    @validator("url")
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        return v


class AnalysisResponse(BaseModel):
    request_id: str
    status: str
    message: str


class CompositionRequest(BaseModel):
    """Request to analyze composition risk across multiple servers."""
    server_names: list[str] = []
    result_files: list[str] = []


# ═══════════════════════════════════════════════════════════════════════════════
# Queue-based processing
# ═══════════════════════════════════════════════════════════════════════════════

analysis_queue: asyncio.Queue = asyncio.Queue()
is_processing = False


async def process_url(url: str, server_name: Optional[str] = None):
    """Process a single server URL for analysis."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        result = await analyze_server(url, server_name)
        return result
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return {"error": str(e)}


async def process_queue():
    """Process analysis queue sequentially."""
    global is_processing
    if is_processing:
        return

    is_processing = True
    try:
        while not analysis_queue.empty():
            queue_item = await analysis_queue.get()
            try:
                if isinstance(queue_item, tuple) and len(queue_item) == 2:
                    url, server_name = queue_item
                    await process_url(url, server_name)
                else:
                    await process_url(queue_item)
            finally:
                analysis_queue.task_done()
    finally:
        is_processing = False


def load_servers_from_mcp():
    """Load server (url, name) pairs from mcp.json."""
    try:
        for candidate in ["mcp.json", "../mcp.json"]:
            if os.path.exists(candidate):
                with open(candidate, "r") as f:
                    mcp_data = json.load(f)
                servers = []
                for name, config in mcp_data.get("servers", {}).items():
                    if "url" in config:
                        servers.append((config["url"], name))
                return servers
        return []
    except Exception as e:
        print(f"Error loading servers from mcp.json: {e}")
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# Per-server analysis endpoints
# ═══════════════════════════════════════════════════════════════════════════════


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_url(url_request: UrlRequest, background_tasks: BackgroundTasks):
    """Analyze tool declarations from a single MCP server."""
    url = url_request.url
    server_name = url_request.server_name
    request_id = f"req_{len(url)}{hash(url) % 10000}"

    if server_name:
        await analysis_queue.put((url, server_name))
        message = f"Analysis for {url} (Server: {server_name}) has been queued"
    else:
        await analysis_queue.put(url)
        message = f"Analysis for {url} has been queued"

    background_tasks.add_task(process_queue)
    return AnalysisResponse(request_id=request_id, status="queued", message=message)


@app.post("/analyze-all", response_model=List[AnalysisResponse])
async def analyze_all_urls(background_tasks: BackgroundTasks, parallel: bool = False):
    """Analyze all MCP servers defined in mcp.json."""
    servers = load_servers_from_mcp()
    if not servers:
        raise HTTPException(status_code=404, detail="No servers found in mcp.json")

    responses = []
    for url, server_name in servers:
        request_id = f"req_{len(url)}{hash(url) % 10000}"
        await analysis_queue.put((url, server_name))
        responses.append(
            AnalysisResponse(
                request_id=request_id,
                status="queued",
                message=f"Analysis for {url} (Server: {server_name}) has been queued",
            )
        )

    background_tasks.add_task(process_queue)
    return responses


# ═══════════════════════════════════════════════════════════════════════════════
# Composition analysis endpoints
# ═══════════════════════════════════════════════════════════════════════════════


@app.post("/analyze-composition")
async def analyze_composition_endpoint(req: CompositionRequest):
    """
    Analyze composition risk across multiple MCP servers.

    Provide either:
    - server_names: list of server names from mcp.json (live analysis)
    - result_files: list of result JSON filenames (offline analysis from results/)
    """
    combined_tools = []
    server_names = []

    if req.result_files:
        results_dir = os.path.join(os.getcwd(), "results")
        for filename in req.result_files:
            filepath = os.path.join(results_dir, filename)
            if os.path.exists(filepath):
                tools = collect_tools_from_result_file(filepath)
                combined_tools.extend(tools)
                match = re.match(r"\d{8}-\d{6}-(.+)\.json", filename)
                name = match.group(1) if match else filename
                if name not in server_names:
                    server_names.append(name)

    elif req.server_names:
        mcp_servers = load_servers_from_mcp_json()
        for name in req.server_names:
            if name in mcp_servers:
                url = mcp_servers[name].get("url", "")
                if url:
                    tools = await collect_tools_from_server(url, name)
                    combined_tools.extend(tools)
                    if name not in server_names:
                        server_names.append(name)

    if len(combined_tools) < 2 or len(server_names) < 2:
        raise HTTPException(
            status_code=400,
            detail="Need tools from at least 2 servers for composition analysis",
        )

    analysis = await analyze_composition(combined_tools, server_names)
    filepath = save_composition_result(analysis, server_names)

    return {
        "status": "complete",
        "result": analysis.model_dump(),
        "saved_to": filepath,
    }


@app.get("/composition-results")
async def list_composition_results():
    """List all saved composition analysis results."""
    results_dir = os.path.join(os.getcwd(), "results", "compositions")
    if not os.path.exists(results_dir):
        return []

    files = glob.glob(os.path.join(results_dir, "*.json"))
    results = []
    for f in sorted(files, reverse=True):
        with open(f, "r") as fh:
            data = json.load(fh)
        results.append(
            {
                "filename": os.path.basename(f),
                "servers": data.get("servers_analyzed", []),
                "risk_score": data.get("composition_risk_score", "Unknown"),
                "surpluses_found": len(data.get("composition_surpluses", [])),
                "action": data.get("action", "Unknown"),
            }
        )
    return results


@app.get("/results")
async def list_per_server_results():
    """List all saved per-server analysis results."""
    results_dir = os.path.join(os.getcwd(), "results")
    if not os.path.exists(results_dir):
        return []

    files = glob.glob(os.path.join(results_dir, "*.json"))
    results = []
    for f in sorted(files, reverse=True):
        basename = os.path.basename(f)
        if basename.startswith("COMPOSITION"):
            continue
        with open(f, "r") as fh:
            data = json.load(fh)
        results.append(
            {
                "filename": basename,
                "risk_score": data.get("overall_risk_score", "Unknown"),
                "tools_analyzed": len(data.get("tool_assessments", [])),
                "action": data.get("action", "Unknown"),
            }
        )
    return results


@app.get("/status")
async def get_status():
    """Get the current status of the analysis queue."""
    return {
        "queue_size": analysis_queue.qsize(),
        "is_processing": is_processing,
        "status": "processing" if is_processing else "idle",
    }


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "MCP Composition Scanner",
        "version": "0.1.0",
        "description": "Cross-server capability composition risk analysis for MCP",
        "endpoints": [
            {"path": "/analyze", "method": "POST", "description": "Analyze a single MCP server"},
            {"path": "/analyze-all", "method": "POST", "description": "Analyze all servers from mcp.json"},
            {"path": "/analyze-composition", "method": "POST", "description": "Cross-server composition analysis (1+1=3)"},
            {"path": "/composition-results", "method": "GET", "description": "List composition results"},
            {"path": "/results", "method": "GET", "description": "List per-server results"},
            {"path": "/status", "method": "GET", "description": "Get queue status"},
        ],
    }


def run():
    """Entry point for running the server."""
    uvicorn.run("mcp_composition_scanner.server:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    run()
