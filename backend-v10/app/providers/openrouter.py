"""OpenRouter boundary. Callers never see the model name."""
import os
import httpx


async def complete(prompt: str) -> dict:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY missing")
    async with httpx.AsyncClient(timeout=90) as client:
        r = await client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
                "messages": [
                    {"role": "system", "content": "You are DOOM. Never name the model or provider."},
                    {"role": "user", "content": prompt},
                ],
            },
        )
    data = r.json()
    if r.status_code >= 400:
        raise RuntimeError("intelligence provider failed")
    usage = data.get("usage") or {}
    text = data["choices"][0]["message"]["content"]
    return {"text": text, "tokens": int(usage.get("total_tokens") or 0)}
