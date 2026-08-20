"""
Lab 03 - Indirect Prompt Injection & Tool Abuse

This module defines the tools available to the AI agent.

The intentionally vulnerable design allows the agent to call
privileged tools directly without an independent authorization layer.
"""

from data import USERS, ASSETS


# -------------------------------------------------------------------
# READ-ONLY TOOLS
# -------------------------------------------------------------------

def get_user_info(username):
    """
    Return information about a synthetic user account.
    """
    user = USERS.get(username)

    if not user:
        return {
            "success": False,
            "error": f"User '{username}' was not found."
        }

    return {
        "success": True,
        "user": {
            "username": user["username"],
            "full_name": user["full_name"],
            "email": user["email"],
            "role": user["role"],
            "department": user["department"],
            "account_status": user["account_status"],
        }
    }


def get_asset_info(asset_id):
    """
    Return information about a synthetic IT asset.
    """
    asset = ASSETS.get(asset_id)

    if not asset:
        return {
            "success": False,
            "error": f"Asset '{asset_id}' was not found."
        }

    return {
        "success": True,
        "asset": {
            "asset_id": asset["asset_id"],
            "hostname": asset["hostname"],
            "owner": asset["owner"],
            "operating_system": asset["operating_system"],
            "status": asset["status"],
        }
    }


# -------------------------------------------------------------------
# PRIVILEGED TOOL
# -------------------------------------------------------------------

def disable_account(username):
    """
    Disable a synthetic user account.

    WARNING:
    This is intentionally vulnerable for Lab 03.

    No authorization check is performed before the account
    status is changed.
    """
    user = USERS.get(username)

    if not user:
        return {
            "success": False,
            "error": f"User '{username}' was not found."
        }

    previous_status = user["account_status"]

    user["account_status"] = "disabled"

    return {
        "success": True,
        "action": "disable_account",
        "username": username,
        "previous_status": previous_status,
        "new_status": user["account_status"],
        "message": f"Account '{username}' has been disabled."
    }


# -------------------------------------------------------------------
# TOOL REGISTRY
# -------------------------------------------------------------------

TOOLS = {
    "get_user_info": get_user_info,
    "get_asset_info": get_asset_info,
    "disable_account": disable_account,
}


def execute_tool(tool_name, arguments):
    """
    Execute a registered tool using model-supplied arguments.

    This intentionally trusts the requested tool and arguments.
    Later in the lab, this execution path will be secured.
    """
    tool = TOOLS.get(tool_name)

    if not tool:
        return {
            "success": False,
            "error": f"Unknown tool '{tool_name}'."
        }

    try:
        return tool(**arguments)

    except TypeError as exc:
        return {
            "success": False,
            "error": f"Invalid arguments for tool '{tool_name}': {exc}"
        }