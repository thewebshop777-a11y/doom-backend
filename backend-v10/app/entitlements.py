"""Plan baselines. Web Shop writes subscriptions. DOOM only reads them."""

PLANS = {
    "free": {"tokens": 2_000_000, "tools": 50, "seats": 1, "storage": 100_000_000, "local": False},
    "basic": {"tokens": 100_000_000, "tools": 1_000, "seats": 3, "storage": 5_000_000_000, "local": True},
    "pro": {"tokens": 200_000_000, "tools": 4_000, "seats": 5, "storage": 20_000_000_000, "local": True},
    "business": {"tokens": 500_000_000, "tools": 6_000, "seats": 15, "storage": 50_000_000_000, "local": True},
    "enterprise": {"tokens": 900_000_000, "tools": 10_000, "seats": 40, "storage": 200_000_000_000, "local": True},
}

POWERS = ["business", "website", "content", "founder", "predictor", "local"]


def apply_plan(tier: str, status: str) -> dict:
    if status not in ("active", "trialing"):
        tier = "free"
    plan = PLANS.get(tier, PLANS["free"])
    return {
        "tier": tier if status in ("active", "trialing") else "free",
        "status": status,
        "monthly_tokens": plan["tokens"],
        "daily_tool_limit": plan["tools"],
        "seats": plan["seats"],
        "storage_bytes": plan["storage"],
        "local_unlocked": plan["local"],
        "powers": [p for p in POWERS if p != "local" or plan["local"]],
    }
