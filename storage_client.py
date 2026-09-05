"""Local Disk Storage Client for VPS (Replaces Emergent Storage)."""
import os
from pathlib import Path
from typing import Tuple

# VPS path where images will be stored
UPLOAD_DIR = Path("/var/www/dheeraja/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def init_storage() -> str:
    # No remote init needed for local storage
    return "local"

def put_object(path: str, data: bytes, content_type: str) -> dict:
    file_path = UPLOAD_DIR / path
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "wb") as f:
        f.write(data)

    return {"status": "success", "path": path}

def get_object(path: str) -> Tuple[bytes, str]:
    file_path = UPLOAD_DIR / path
    if not file_path.exists():
        raise FileNotFoundError("Image not found")

    with open(file_path, "rb") as f:
        content = f.read()

    # Guess content type based on extension
    ext = file_path.suffix.lower()
    ctype = "image/jpeg" if ext in [".jpg", ".jpeg"] else "image/png"

    return content, ctype

def build_path(user_id: str, ext: str) -> str:
    import uuid
    ext = (ext or "jpg").lstrip(".").lower()
    return f"uploads/{user_id}/{uuid.uuid4().hex}.{ext}"
