from __future__ import annotations

import base64
import lzma
import subprocess
import tempfile
from pathlib import Path

PATCH_DIR = Path("tools/r1153-patch")
README = Path("README.md")

README_SECTION = """

## R1.1.52 — Clean Training Provenance + Provider-Aware Hop Intelligence

- AI candidate fitting and auto-train eligibility are restricted to explicit authoritative Mail Admin Ground Truth for the current independent generation/schema.
- Historical `sa-learn`, Bayes/learning-correction, legacy-feature and superseded rows remain preserved for audit but are excluded from clean Set-2 candidate fitting.
- SpamAssassin Learn HAM / Learn SPAM actions no longer silently create AI training labels.
- Infrastructure AI adds provider-aware trusted-hop context for Google Workspace, Microsoft 365 and other observed routes. MX/provider/authentication evidence is contextual only and never independently implies HAM or SPAM.
- Missing SPF/DKIM/DMARC/DNS evidence remains UNKNOWN rather than negative evidence.
- Feature schema v4, seven independent feature families, Hard-HAM weight 1.75 and SHADOW ONLY behavior remain unchanged.

## R1.1.53 — Semantic Impersonation & Action-Intent Intelligence

R1.1.53 keeps schema v4, the seven independent feature families, Hard-HAM weight 1.75, SHADOW ONLY operation, and the R1.1.52 clean-training-provenance boundary. Message AI adds relationship-derived features for recipient-domain mail-service impersonation, delivery/release lures, credential-action language, and action URLs external to both sender and recipient domains. A high-confidence semantic overlay requires multiple independent relationships and can only raise a shadow SPAM/CREDENTIAL_PHISHING proposal; it never changes Postfix/Amavis/SpamAssassin behavior and never creates Ground Truth. The underlying learned-model verdict/confidence is preserved alongside the overlay for calibration and audit.
"""


def apply_patch() -> None:
    parts = sorted(PATCH_DIR.glob("part*.b64"))
    if len(parts) != 7:
        raise RuntimeError(f"expected 7 R1.1.53 patch parts, found {len(parts)}")
    encoded = "".join(p.read_text(encoding="ascii").strip() for p in parts)
    patch = lzma.decompress(base64.b64decode(encoded))
    with tempfile.NamedTemporaryFile(prefix="r1153-", suffix=".patch", delete=False) as tmp:
        tmp.write(patch)
        patch_path = Path(tmp.name)
    try:
        subprocess.run(["git", "apply", "--whitespace=nowarn", str(patch_path)], check=True)
    finally:
        patch_path.unlink(missing_ok=True)


def update_readme() -> None:
    text = README.read_text(encoding="utf-8")
    lines = text.splitlines()
    if lines and lines[0].startswith("# Postfix Delivery Dashboard"):
        lines[0] = "# Postfix Delivery Dashboard — R1.1.53 Semantic Impersonation + Action-Intent Intelligence"
        text = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    if "## R1.1.53 — Semantic Impersonation & Action-Intent Intelligence" not in text:
        text = text.rstrip() + README_SECTION + "\n"
    README.write_text(text, encoding="utf-8")


def main() -> None:
    apply_patch()
    update_readme()


if __name__ == "__main__":
    main()
