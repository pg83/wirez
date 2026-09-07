"""ASGI application for the HTTP/2 streaming test: a response that arrives
in chunks with a pause between them, and an upload that is counted as it
streams in."""

import asyncio


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    if scope["method"] == "POST":
        total = 0
        while True:
            message = await receive()
            total += len(message.get("body", b""))
            if not message.get("more_body"):
                break
        body = f"received {total}\n".encode()
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": body})
        return
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    for index in range(5):
        await send({"type": "http.response.body", "body": f"tick {index}\n".encode(), "more_body": True})
        await asyncio.sleep(1)
    await send({"type": "http.response.body", "body": b"done\n", "more_body": False})
