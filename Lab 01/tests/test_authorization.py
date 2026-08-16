from app.tools import lookup_asset


UNAUTHORIZED_USER = {
    "username": "security.analyst",
    "department": "Security",
    "roles": [
        "security_analyst"
    ]
}


FINANCE_USER = {
    "username": "finance.user",
    "department": "Finance",
    "roles": [
        "employee"
    ]
}


ASSET_ADMIN = {
    "username": "asset.admin",
    "department": "IT",
    "roles": [
        "asset_admin"
    ]
}


def test_internal_asset_is_accessible():
    result = lookup_asset(
        hostname="SRV-WEB-01",
        user_context=UNAUTHORIZED_USER
    )

    assert "error" not in result
    assert result["classification"] == "INTERNAL"


def test_confidential_asset_denied_to_security_analyst():
    result = lookup_asset(
        hostname="WS-FINANCE-01",
        user_context=UNAUTHORIZED_USER
    )

    assert result["error"] == "Access denied"
    assert result["hostname"] == "WS-FINANCE-01"


def test_finance_user_can_access_finance_asset():
    result = lookup_asset(
        hostname="WS-FINANCE-01",
        user_context=FINANCE_USER
    )

    assert "error" not in result
    assert result["department"] == "Finance"
    assert result["classification"] == "CONFIDENTIAL"


def test_asset_admin_can_access_confidential_asset():
    result = lookup_asset(
        hostname="WS-FINANCE-01",
        user_context=ASSET_ADMIN
    )

    assert "error" not in result
    assert result["classification"] == "CONFIDENTIAL"


def test_fake_asset_returns_not_found():
    result = lookup_asset(
        hostname="WS-FAKE-99",
        user_context=UNAUTHORIZED_USER
    )

    assert result["error"] == "Asset not found"