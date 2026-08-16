import json
import os
from copy import deepcopy
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from openai import OpenAI


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

app = Flask(__name__)

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-5.5",
)


# ============================================================
# SYNTHETIC LAB DATA
# ============================================================

INITIAL_USERS = {
    "jsmith": {
        "username": "jsmith",
        "name": "Jordan Smith",
        "department": "Finance",
        "role": "standard_user",
        "status": "active",
    },

    "mgarcia": {
        "username": "mgarcia",
        "name": "Maria Garcia",
        "department": "Engineering",
        "role": "developer",
        "status": "active",
    },

    "intern01": {
        "username": "intern01",
        "name": "Alex Intern",
        "department": "IT",
        "role": "intern",
        "status": "active",
    },

    "secadmin": {
        "username": "secadmin",
        "name": "Security Administrator",
        "department": "Security",
        "role": "security_admin",
        "status": "active",
    },
}


INITIAL_ASSETS = {
    "10.10.20.15": {
        "ip": "10.10.20.15",
        "hostname": "FIN-LT-015",
        "owner": "jsmith",
        "os": "Windows 11",
        "criticality": "medium",
    },

    "10.10.20.25": {
        "ip": "10.10.20.25",
        "hostname": "ENG-WS-025",
        "owner": "mgarcia",
        "os": "Ubuntu 24.04",
        "criticality": "medium",
    },

    "10.10.20.50": {
        "ip": "10.10.20.50",
        "hostname": "SEC-ADMIN-01",
        "owner": "secadmin",
        "os": "Windows 11",
        "criticality": "high",
    },
}


users = deepcopy(INITIAL_USERS)
assets = deepcopy(INITIAL_ASSETS)

audit_log = []


# ============================================================
# LAB AUTHENTICATION
#
# This is intentionally simple because the purpose of the lab
# is authorization, not building a production identity system.
#
# The browser supplies a username representing the authenticated
# lab identity.
# ============================================================

DEFAULT_LAB_USER = "intern01"


def get_requester(username):
    requester = users.get(username)

    if requester is None:
        return None

    if requester["status"] != "active":
        return None

    return deepcopy(requester)


# ============================================================
# SECURITY POLICY
# ============================================================

READ_ONLY_TOOLS = {
    "lookup_user",
    "lookup_asset",
}


PRIVILEGED_TOOLS = {
    "change_asset_owner",
    "set_user_role",
    "disable_user",
}


ROLE_PERMISSIONS = {
    "intern": {
        "lookup_user",
        "lookup_asset",
    },

    "standard_user": {
        "lookup_user",
        "lookup_asset",
    },

    "developer": {
        "lookup_user",
        "lookup_asset",
    },

    "security_admin": {
        "lookup_user",
        "lookup_asset",
        "change_asset_owner",
    },
}


# These operations are considered too sensitive for autonomous
# execution even when the requester is a security administrator.

HUMAN_APPROVAL_REQUIRED = {
    "set_user_role",
    "disable_user",
}


# ============================================================
# AUDIT LOGGING
# ============================================================

def record_event(
    event_type,
    requester,
    tool_name,
    arguments,
    decision,
    reason,
    result=None,
):
    event = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "event_type": event_type,

        "requester": (
            requester["username"]
            if requester
            else None
        ),

        "requester_role": (
            requester["role"]
            if requester
            else None
        ),

        "tool": tool_name,

        "arguments": arguments,

        "decision": decision,

        "reason": reason,

        "result": result,
    }

    audit_log.append(event)


# ============================================================
# AUTHORIZATION ENGINE
# ============================================================

def authorize_tool_call(
    requester,
    tool_name,
    arguments,
):
    """
    Deterministic authorization boundary.

    The LLM does NOT control this decision.
    """

    if requester is None:
        return {
            "allowed": False,
            "decision": "DENY",
            "reason": (
                "Requester is not authenticated "
                "or the account is inactive."
            ),
        }

    if tool_name not in (
        READ_ONLY_TOOLS
        | PRIVILEGED_TOOLS
    ):
        return {
            "allowed": False,
            "decision": "DENY",
            "reason": (
                "Unknown or unapproved tool."
            ),
        }

    role = requester["role"]

    allowed_tools = ROLE_PERMISSIONS.get(
        role,
        set(),
    )

    if tool_name not in allowed_tools:
        return {
            "allowed": False,
            "decision": "DENY",
            "reason": (
                f"Role '{role}' is not "
                f"authorized to execute "
                f"'{tool_name}'."
            ),
        }

    if tool_name in HUMAN_APPROVAL_REQUIRED:
        return {
            "allowed": False,
            "decision": "REQUIRE_APPROVAL",
            "reason": (
                f"Tool '{tool_name}' requires "
                "human approval and cannot be "
                "executed autonomously."
            ),
        }

    # --------------------------------------------------------
    # ARGUMENT-LEVEL AUTHORIZATION
    #
    # Even if someone is authorized to use a tool, individual
    # arguments may still violate policy.
    # --------------------------------------------------------

    if tool_name == "change_asset_owner":

        ip = arguments.get("ip")

        asset = assets.get(ip)

        if asset is None:
            return {
                "allowed": False,
                "decision": "DENY",
                "reason": (
                    "Target asset does not exist."
                ),
            }

        if asset["criticality"] == "high":
            return {
                "allowed": False,
                "decision": "DENY",
                "reason": (
                    "Ownership changes for "
                    "high-criticality assets "
                    "require manual approval."
                ),
            }

    return {
        "allowed": True,
        "decision": "ALLOW",
        "reason": (
            "Requester role and arguments "
            "satisfy authorization policy."
        ),
    }


# ============================================================
# READ-ONLY TOOLS
# ============================================================

def lookup_user(username):
    user = users.get(username)

    if user is None:
        return {
            "success": False,
            "error": (
                f"User '{username}' "
                "was not found."
            ),
        }

    return {
        "success": True,
        "user": deepcopy(user),
    }


def lookup_asset(ip):
    asset = assets.get(ip)

    if asset is None:
        return {
            "success": False,
            "error": (
                f"Asset '{ip}' "
                "was not found."
            ),
        }

    return {
        "success": True,
        "asset": deepcopy(asset),
    }


# ============================================================
# STATE-CHANGING TOOLS
# ============================================================

def change_asset_owner(
    ip,
    new_owner,
):
    if ip not in assets:
        return {
            "success": False,
            "error": (
                f"Asset '{ip}' "
                "was not found."
            ),
        }

    if new_owner not in users:
        return {
            "success": False,
            "error": (
                f"User '{new_owner}' "
                "was not found."
            ),
        }

    previous_owner = assets[
        ip
    ]["owner"]

    assets[
        ip
    ]["owner"] = new_owner

    return {
        "success": True,
        "message": (
            "Asset ownership changed."
        ),
        "ip": ip,
        "previous_owner": previous_owner,
        "new_owner": new_owner,
    }


def set_user_role(
    username,
    role,
    reason,
):
    if username not in users:
        return {
            "success": False,
            "error": (
                f"User '{username}' "
                "was not found."
            ),
        }

    previous_role = users[
        username
    ]["role"]

    users[
        username
    ]["role"] = role

    return {
        "success": True,
        "message": (
            "User role changed."
        ),
        "username": username,
        "previous_role": previous_role,
        "new_role": role,
        "reason": reason,
    }


def disable_user(
    username,
    reason,
):
    if username not in users:
        return {
            "success": False,
            "error": (
                f"User '{username}' "
                "was not found."
            ),
        }

    previous_status = users[
        username
    ]["status"]

    users[
        username
    ]["status"] = "disabled"

    return {
        "success": True,
        "message": (
            "User account disabled."
        ),
        "username": username,
        "previous_status": previous_status,
        "new_status": "disabled",
        "reason": reason,
    }


# ============================================================
# TOOL DEFINITIONS
# ============================================================

TOOLS = [
    {
        "type": "function",

        "name": "lookup_user",

        "description": (
            "Look up an employee account."
        ),

        "parameters": {
            "type": "object",

            "properties": {
                "username": {
                    "type": "string",
                },
            },

            "required": [
                "username",
            ],

            "additionalProperties": False,
        },

        "strict": True,
    },

    {
        "type": "function",

        "name": "lookup_asset",

        "description": (
            "Look up an internal computer "
            "asset by IP address."
        ),

        "parameters": {
            "type": "object",

            "properties": {
                "ip": {
                    "type": "string",
                },
            },

            "required": [
                "ip",
            ],

            "additionalProperties": False,
        },

        "strict": True,
    },

    {
        "type": "function",

        "name": "change_asset_owner",

        "description": (
            "Request a change to the "
            "assigned owner of an internal "
            "computer asset."
        ),

        "parameters": {
            "type": "object",

            "properties": {
                "ip": {
                    "type": "string",
                },

                "new_owner": {
                    "type": "string",
                },
            },

            "required": [
                "ip",
                "new_owner",
            ],

            "additionalProperties": False,
        },

        "strict": True,
    },

    {
        "type": "function",

        "name": "set_user_role",

        "description": (
            "Request a change to an "
            "employee's application role."
        ),

        "parameters": {
            "type": "object",

            "properties": {
                "username": {
                    "type": "string",
                },

                "role": {
                    "type": "string",
                },

                "reason": {
                    "type": "string",
                },
            },

            "required": [
                "username",
                "role",
                "reason",
            ],

            "additionalProperties": False,
        },

        "strict": True,
    },

    {
        "type": "function",

        "name": "disable_user",

        "description": (
            "Request that an employee "
            "account be disabled."
        ),

        "parameters": {
            "type": "object",

            "properties": {
                "username": {
                    "type": "string",
                },

                "reason": {
                    "type": "string",
                },
            },

            "required": [
                "username",
                "reason",
            ],

            "additionalProperties": False,
        },

        "strict": True,
    },
]


# ============================================================
# RAW TOOL DISPATCHER
#
# IMPORTANT:
# This function performs NO authorization itself.
#
# It must only be reached AFTER authorize_tool_call()
# returns ALLOW.
# ============================================================

def execute_tool(
    tool_name,
    arguments,
):
    if tool_name == "lookup_user":
        return lookup_user(
            **arguments
        )

    if tool_name == "lookup_asset":
        return lookup_asset(
            **arguments
        )

    if tool_name == "change_asset_owner":
        return change_asset_owner(
            **arguments
        )

    if tool_name == "set_user_role":
        return set_user_role(
            **arguments
        )

    if tool_name == "disable_user":
        return disable_user(
            **arguments
        )

    return {
        "success": False,
        "error": (
            f"Unknown tool: {tool_name}"
        ),
    }


# ============================================================
# SECURE TOOL GATEWAY
# ============================================================

def secure_execute_tool(
    requester,
    tool_name,
    arguments,
):
    authorization = authorize_tool_call(
        requester,
        tool_name,
        arguments,
    )

    if not authorization["allowed"]:

        blocked_result = {
            "success": False,
            "executed": False,
            "decision": (
                authorization["decision"]
            ),
            "error": (
                authorization["reason"]
            ),
        }

        record_event(
            event_type=(
                "authorization_decision"
            ),
            requester=requester,
            tool_name=tool_name,
            arguments=arguments,
            decision=(
                authorization["decision"]
            ),
            reason=(
                authorization["reason"]
            ),
            result=blocked_result,
        )

        return blocked_result

    result = execute_tool(
        tool_name,
        arguments,
    )

    record_event(
        event_type="tool_execution",
        requester=requester,
        tool_name=tool_name,
        arguments=arguments,
        decision="ALLOW",
        reason=(
            authorization["reason"]
        ),
        result=result,
    )

    return result


# ============================================================
# AGENT
# ============================================================

SYSTEM_PROMPT = """
You are an internal IT Operations AI assistant.

You may propose available tools when they are useful for
completing a user's request.

The application independently enforces authorization policy.

If a tool request is denied or requires approval, clearly
tell the user that the action was not executed.

Never claim that an operation succeeded unless the tool
result explicitly says that it succeeded.

Be concise and helpful.
"""


def run_agent(
    user_message,
    requester,
):
    identity_context = (
        "Authenticated requester:\n"
        f"username: {requester['username']}\n"
        f"role: {requester['role']}\n\n"
        "User request:\n"
        f"{user_message}"
    )

    response = client.responses.create(
        model=MODEL,
        instructions=SYSTEM_PROMPT,
        input=identity_context,
        tools=TOOLS,
    )

    while True:
        tool_outputs = []

        for item in response.output:

            if item.type != "function_call":
                continue

            try:
                arguments = json.loads(
                    item.arguments
                )

            except json.JSONDecodeError:

                result = {
                    "success": False,
                    "executed": False,
                    "decision": "DENY",
                    "error": (
                        "Invalid tool arguments."
                    ),
                }

                record_event(
                    event_type=(
                        "argument_validation"
                    ),
                    requester=requester,
                    tool_name=item.name,
                    arguments={
                        "raw": item.arguments,
                    },
                    decision="DENY",
                    reason=(
                        "Tool arguments were "
                        "not valid JSON."
                    ),
                    result=result,
                )

            else:

                # =============================================
                # SECURITY BOUNDARY
                #
                # The model proposes.
                # The application authorizes.
                # =============================================

                result = secure_execute_tool(
                    requester,
                    item.name,
                    arguments,
                )

            tool_outputs.append(
                {
                    "type": (
                        "function_call_output"
                    ),

                    "call_id": item.call_id,

                    "output": json.dumps(
                        result
                    ),
                }
            )

        if not tool_outputs:
            break

        response = client.responses.create(
            model=MODEL,

            previous_response_id=(
                response.id
            ),

            input=tool_outputs,

            tools=TOOLS,

            instructions=SYSTEM_PROMPT,
        )

    return response.output_text


# ============================================================
# FLASK ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template(
        "index.html"
    )


@app.route(
    "/api/chat",
    methods=["POST"],
)
def chat():
    body = (
        request.get_json(
            silent=True
        )
        or {}
    )

    message = (
        body
        .get(
            "message",
            "",
        )
        .strip()
    )

    requester_username = (
        body
        .get(
            "requester",
            DEFAULT_LAB_USER,
        )
        .strip()
    )

    if not message:
        return jsonify(
            {
                "success": False,
                "error": (
                    "Message is required."
                ),
            }
        ), 400

    requester = get_requester(
        requester_username
    )

    if requester is None:
        return jsonify(
            {
                "success": False,
                "error": (
                    "Requester is not "
                    "authenticated or active."
                ),
            }
        ), 401

    try:
        reply = run_agent(
            message,
            requester,
        )

        return jsonify(
            {
                "success": True,
                "reply": reply,
                "requester": requester,
                "users": users,
                "assets": assets,
                "audit_log": audit_log,
            }
        )

    except Exception as exc:
        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 500


@app.route(
    "/api/state"
)
def state():
    return jsonify(
        {
            "users": users,
            "assets": assets,
            "audit_log": audit_log,
        }
    )


@app.route(
    "/api/reset",
    methods=["POST"],
)
def reset():
    global users
    global assets
    global audit_log

    users = deepcopy(
        INITIAL_USERS
    )

    assets = deepcopy(
        INITIAL_ASSETS
    )

    audit_log = []

    return jsonify(
        {
            "success": True,
            "message": (
                "Lab state reset."
            ),
            "users": users,
            "assets": assets,
            "audit_log": audit_log,
        }
    )


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )