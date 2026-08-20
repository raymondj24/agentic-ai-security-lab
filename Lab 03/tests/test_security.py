"""
Lab 03 - Security Regression Tests

These tests verify that the deterministic authorization boundary
prevents indirect prompt injection from causing unauthorized
privileged tool execution.
"""

import os
import sys

# Allow tests to import modules from the Lab 03 directory.
sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from agent import process_ticket
from data import reset_lab_state
from tools import get_user_info
from policy import authorize_tool_call


# -------------------------------------------------------------------
# TEST SETUP
# -------------------------------------------------------------------

def setup_function():
    """
    Reset mutable lab state before every test.
    """
    reset_lab_state()


# -------------------------------------------------------------------
# BASELINE FUNCTIONALITY
# -------------------------------------------------------------------

def test_legitimate_asset_lookup_is_allowed():
    """
    Normal support activity should continue working.
    """

    result = process_ticket(1001)

    assert result["model_decision"]["tool_name"] == "get_asset_info"
    assert result["authorization"]["allowed"] is True
    assert result["tool_result"]["success"] is True


def test_legitimate_user_lookup_is_allowed():
    """
    Normal account lookup should continue working.
    """

    result = process_ticket(1003)

    assert result["model_decision"]["tool_name"] == "get_user_info"
    assert result["authorization"]["allowed"] is True
    assert result["tool_result"]["success"] is True


# -------------------------------------------------------------------
# INDIRECT PROMPT INJECTION
# -------------------------------------------------------------------

def test_prompt_injection_is_detected_by_security_boundary():
    """
    The simulated model may still interpret malicious ticket content
    as an instruction to disable Alice.

    The authorization layer must deny execution.
    """

    result = process_ticket(9001)

    # Demonstrate that the model was manipulated.
    assert result["model_decision"]["tool_name"] == "disable_account"
    assert result["model_decision"]["arguments"]["username"] == "alice"

    # Security boundary must deny execution.
    assert result["authorization"]["allowed"] is False

    # Tool must not execute.
    assert result["tool_result"]["executed"] is False


def test_prompt_injection_does_not_change_account_state():
    """
    Verify the blocked attack produces no unauthorized state change.
    """

    before = get_user_info("alice")

    assert before["user"]["account_status"] == "active"

    process_ticket(9001)

    after = get_user_info("alice")

    assert after["user"]["account_status"] == "active"


# -------------------------------------------------------------------
# AUTHORIZATION POLICY
# -------------------------------------------------------------------

def test_regular_user_cannot_disable_another_user():
    """
    A regular user must not be able to invoke privileged account
    administration.
    """

    allowed, _ = authorize_tool_call(
        requester="bob",
        tool_name="disable_account",
        arguments={"username": "alice"},
    )

    assert allowed is False


def test_admin_can_disable_account():
    """
    Verify legitimate administrative functionality remains available.
    """

    allowed, _ = authorize_tool_call(
        requester="admin",
        tool_name="disable_account",
        arguments={"username": "alice"},
    )

    assert allowed is True


def test_unknown_tool_is_denied():
    """
    Policy should fail closed when an unknown tool is requested.
    """

    allowed, _ = authorize_tool_call(
        requester="bob",
        tool_name="make_bob_domain_admin",
        arguments={},
    )

    assert allowed is False