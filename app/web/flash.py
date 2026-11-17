from fastapi import Request

def flash(request: Request, message: str, category: str = "info") -> None:
    if "_flash_messages" not in request.session:
        request.session["_flash_messages"] = []
    request.session["_flash_messages"].append({"category": category, "message": message})

def get_flashed_messages(request: Request) -> list:
    messages = request.session.pop("_flash_messages", [])
    return messages