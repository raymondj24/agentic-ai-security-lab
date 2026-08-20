"""
Lab 03 - Indirect Prompt Injection & Tool Abuse

This module simulates an AI agent that reads support tickets and
decides which tools to call.

SECURED VERSION:
The AI agent may propose tool calls, but privileged operations
must pass deterministic authorization before execution.
"""

import json
import re

from data import get_ticket
from tools import execute_tool
from policy import authorize_tool_call


# -------------------------------------------------------------------
# AGENT SYSTEM PROMPT
# -------------------------------------------------------------------

SYSTEM_PROMPT = """
You are an IT Support AI Agent.

You assist users by reading support tickets and choosing tools
that can help resolve the request.

Available tools:

1. get_user_info(username)
2. get_asset_info(asset_id)
3. disable_account(username)

You may propose administrative actions when appropriate.

IMPORTANT:
Your proposed actions are subject to application-level
authorization before execution.
"""


# -------------------------------------------------------------------
# SIMPLE MODEL SIMULATION
# -------------------------------------------------------------------

def simulate_model(ticket):
    """
    Simulate how a tool-enabled LLM might interpret a support ticket.

    The model may still be manipulated by untrusted ticket content.

    Security does NOT depend on preventing the model from making
    a malicious or incorrect proposal.
    """

    body = ticket["body"].lower()

    # ---------------------------------------------------------------
    # PRIVILEGED ACTION DETECTION
    # ---------------------------------------------------------------

    disable_match = re.search(
        r"disable\s+(?:the\s+account\s+(?:belonging\s+to\s+)?)?([a-z]+)",
        body
    )

    if disable_match:
        username = disable_match.group(1)

        return {
            "tool_name": "disable_account",
            "arguments": {
                "username": username
            },
            "reason": (
                "The ticket contains instructions requesting that "
                f"the account '{username}' be disabled."
            )
        }

    # ---------------------------------------------------------------
    # ASSET LOOKUP
    # ---------------------------------------------------------------

    asset_match = re.search(
        r"\b(?:LT|SRV)-\d{4}\b",
        ticket["body"],
        re.IGNORECASE
    )

    if asset_match:
        asset_id = asset_match.group(0).upper()

        return {
            "tool_name": "get_asset_info",
            "arguments": {
                "asset_id": asset_id
            },
            "reason": (
                f"The ticket references asset '{asset_id}'."
            )
        }

    # ---------------------------------------------------------------
    # USER ACCOUNT LOOKUP
    # ---------------------------------------------------------------

    if "account" in body:
        submitted_by = ticket["submitted_by"]

        return {
            "tool_name": "get_user_info",
            "arguments": {
                "username": submitted_by
            },
            "reason": (
                "The ticket requests information about the "
                "submitter's account."
            )
        }

    # ---------------------------------------------------------------
    # NO TOOL REQUIRED
    # ---------------------------------------------------------------

    return {
        "tool_name": None,
        "arguments": {},
        "reason": "No supported tool action was identified."
    }


# -------------------------------------------------------------------
# SECURED AGENT EXECUTION
# -------------------------------------------------------------------

def process_ticket(ticket_id):
    """
    Process a support ticket using deterministic authorization
    before executing model-requested tools.
    """

    ticket = get_ticket(ticket_id)

    if not ticket:
        return {
            "success": False,
            "error": f"Ticket '{ticket_id}' was not found."
        }

    model_decision = simulate_model(ticket)

    result = {
        "ticket_id": ticket["ticket_id"],
        "submitted_by": ticket["submitted_by"],
        "subject": ticket["subject"],
        "model_decision": model_decision,
    }

    tool_name = model_decision["tool_name"]

    if tool_name is None:
        result["authorization"] = None
        result["tool_result"] = None
        return result

    # ---------------------------------------------------------------
    # SECURITY BOUNDARY
    # ---------------------------------------------------------------

    allowed, authorization_reason = authorize_tool_call(
        requester=ticket["submitted_by"],
        tool_name=tool_name,
        arguments=model_decision["arguments"],
    )

    result["authorization"] = {
        "allowed": allowed,
        "reason": authorization_reason,
    }

    # ---------------------------------------------------------------
    # DENY UNAUTHORIZED TOOL CALL
    # ---------------------------------------------------------------

    if not allowed:
        result["tool_result"] = {
            "success": False,
            "executed": False,
            "error": "Tool execution blocked by authorization policy.",
        }

        return result

    # ---------------------------------------------------------------
    # EXECUTE AUTHORIZED TOOL
    # ---------------------------------------------------------------

    tool_result = execute_tool(
        tool_name,
        model_decision["arguments"]
    )

    result["tool_result"] = tool_result

    return result


# -------------------------------------------------------------------
# DISPLAY HELPER
# -------------------------------------------------------------------

def print_ticket_result(ticket_id):
    """
    Process a ticket and print the result in readable JSON.
    """

    result = process_ticket(ticket_id)

    print(json.dumps(result, indent=2))