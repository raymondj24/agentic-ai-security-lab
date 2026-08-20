"""
Lab 03 - Deterministic Authorization Policy

This module provides an authorization boundary between the
AI agent and privileged tools.

IMPORTANT:
The AI model does NOT decide whether an operation is authorized.
The application makes that decision using deterministic policy.
"""


# -------------------------------------------------------------------
# TOOL CLASSIFICATION
# -------------------------------------------------------------------

READ_ONLY_TOOLS = {
    "get_user_info",
    "get_asset_info",
}

PRIVILEGED_TOOLS = {
    "disable_account",
}


# -------------------------------------------------------------------
# AUTHORIZATION POLICY
# -------------------------------------------------------------------

def authorize_tool_call(
    requester,
    tool_name,
    arguments,
):
    """
    Determine whether a proposed tool call is authorized.

    Returns:
        (allowed, reason)
    """

    # ---------------------------------------------------------------
    # UNKNOWN TOOL
    # ---------------------------------------------------------------

    if tool_name not in READ_ONLY_TOOLS | PRIVILEGED_TOOLS:
        return (
            False,
            f"Tool '{tool_name}' is not recognized by policy."
        )

    # ---------------------------------------------------------------
    # READ-ONLY OPERATIONS
    # ---------------------------------------------------------------

    if tool_name in READ_ONLY_TOOLS:
        return (
            True,
            "Read-only tool permitted."
        )

    # ---------------------------------------------------------------
    # DISABLE ACCOUNT POLICY
    # ---------------------------------------------------------------

    if tool_name == "disable_account":

        target_username = arguments.get("username")

        if not target_username:
            return (
                False,
                "No target username was supplied."
            )

        # Regular users may never disable accounts.
        if requester != "admin":
            return (
                False,
                (
                    f"Requester '{requester}' is not authorized "
                    "to disable user accounts."
                )
            )

        # Administrator is permitted.
        return (
            True,
            (
                f"Requester '{requester}' is authorized "
                f"to disable '{target_username}'."
            )
        )

    return (
        False,
        "Tool call denied by default."
    )