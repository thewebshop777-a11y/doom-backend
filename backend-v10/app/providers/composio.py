"""Composio execution boundary.
Only allowlisted DOOM actions reach Composio, and execution is bound to the
exact connected account recorded for the authenticated DOOM user.
"""
import os
import httpx

ACTIONS = {
    "gmail": "GMAIL_SEND_EMAIL",
    "slack": "SLACK_SENDS_A_MESSAGE_TO_A_SLACK_CHANNEL",
    "notion": "NOTION_CREATE_NOTION_PAGE",
    "x": "TWITTER_CREATION_OF_A_POST",
    "twitter": "TWITTER_CREATION_OF_A_POST",
    "linkedin": "LINKEDIN_CREATE_LINKED_IN_POST",
    "instagram": "INSTAGRAM_POST_IG_USER_MEDIA",
}
ACTION_ALIASES = {
    ("gmail", "send"): "GMAIL_SEND_EMAIL", ("gmail", "send_email"): "GMAIL_SEND_EMAIL",
    ("slack", "send"): "SLACK_SENDS_A_MESSAGE_TO_A_SLACK_CHANNEL", ("slack", "send_message"): "SLACK_SENDS_A_MESSAGE_TO_A_SLACK_CHANNEL",
    ("notion", "create_page"): "NOTION_CREATE_NOTION_PAGE", ("x", "post"): "TWITTER_CREATION_OF_A_POST", ("twitter", "post"): "TWITTER_CREATION_OF_A_POST",
    ("linkedin", "post"): "LINKEDIN_CREATE_LINKED_IN_POST", ("instagram", "post"): "INSTAGRAM_POST_IG_USER_MEDIA",
}

async def run_action(user_id: str, app: str, params: dict, action: str | None = None, connected_account_id: str | None = None) -> dict:
    key = os.environ.get("COMPOSIO_API_KEY")
    if not key:
        raise RuntimeError("COMPOSIO_API_KEY missing")
    app = app.lower()
    slug = ACTION_ALIASES.get((app, (action or "").lower())) or ACTIONS.get(app)
    if not slug:
        return {"ok": False, "detail": f"No approved Composio action for {app}/{action or 'default'}."}
    if not connected_account_id:
        return {"ok": False, "detail": "No connected account is bound to this user and tool."}
    payload = {"connected_account_id": connected_account_id, "arguments": params, "version": "latest"}
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(
            f"https://backend.composio.dev/api/v3/tools/execute/{slug}",
            headers={"x-api-key": key, "Content-Type": "application/json"},
            json=payload,
        )
    try:
        body = r.json() if r.content else {}
    except Exception:
        body = {"raw": r.text[:1000]}
    if r.status_code >= 400:
        return {"ok": False, "detail": "Composio rejected the requested action. Check the connected account and requested permissions.", "status": r.status_code, "provider": body}
    return {"ok": True, "status": r.status_code, "body": body, "action": slug, "connected_account_id": connected_account_id}
