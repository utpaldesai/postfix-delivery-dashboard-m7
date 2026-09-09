from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
req = ROOT / "requirements.txt"
dockerfile = ROOT / "Dockerfile"

assert req.is_file(), "requirements.txt is missing from full build"
text = req.read_text(encoding="utf-8")
for dependency in ("fastapi", "uvicorn", "PyMySQL"):
    assert dependency.lower() in text.lower(), f"{dependency} missing from requirements.txt"

docker = dockerfile.read_text(encoding="utf-8")
assert "COPY requirements.txt ." in docker
assert "-r requirements.txt" in docker
print("M7 requirements packaging regression passed")
