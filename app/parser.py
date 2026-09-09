import hashlib
import re
from datetime import datetime
from typing import Any

ALLOWED = {
    "DELIVERED",
    "DEFERRED",
    "BOUNCED",
    "BLOCKED",
    "SPAM",
    "QUARANTINED",
    "REJECTED",
    "UNDELIVERED",
}

SYS = re.compile(
    r"^(?P<t>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<h>\S+)\s+"
    r"(?P<p>postfix(?:-\w+)?(?:/[\w-]+)+)\[(?P<pid>\d+)\]:\s+"
    r"(?P<m>.*)$"
)

QUEUE = re.compile(r"^(?P<q>NOQUEUE|[A-Za-z0-9]{5,}):\s*(?P<b>.*)$")
ANGLE = re.compile(r"([A-Za-z_]+)=<([^>]*)>")
PLAIN = re.compile(r"([A-Za-z_]+)=([^,\s]+)")
STATUS = re.compile(r"status=(\w+)(?:\s+\((.*)\))?")
RELAY = re.compile(r"relay=([^,]+)")
CLIENT = re.compile(r"(?:from|client)(?:=|\s+)[^\[]*\[([0-9A-Fa-f:.]+)\]")
QUEUED_AS = re.compile(r"queued as\s+([A-Za-z0-9]{5,})", re.IGNORECASE)

BLOCK = (
    "blocked using",
    "blacklist",
    "blacklisted",
    "rbl",
    "dnsbl",
    "spamhaus",
    "barracuda",
    "client host rejected",
    "access denied",
)


SPAM_MARKERS = (
    "blocked spam",
    "spam detected",
    "spam message",
    "spamassassin",
    "x-spam-status: yes",
    "quarantined as spam",
    "discarded as spam",
    "content rejected as spam",
    "spam score",
)

UNDEL = (
    "expired",
    "undeliverable",
    "queue file write error",
    "mail system configuration error",
)

INTERNAL_REINJECTION_PORTS = {
    "10024",
    "10025",
    "10026",
}

def _is_internal_reinjection(
    service: str,
    delivery_target: str,
    status_detail: str,
) -> bool:
    service_lower = service.lower()
    target_lower = delivery_target.lower()
    detail_lower = status_detail.lower()

    localhost_target = (
        "127.0.0.1[127.0.0.1]:" in target_lower
        or "localhost[127.0.0.1]:" in target_lower
    )

    target_port = (
        target_lower.rsplit(":", 1)[-1]
        if ":" in target_lower
        else ""
    )

    return (
        localhost_target
        and target_port in INTERNAL_REINJECTION_PORTS
        and "queued as" in detail_lower
        and (
            "from mta(" in detail_lower
            or "amavis" in service_lower
        )
    )

def _timestamp_with_year(stamp: str) -> str:
    now = datetime.now()
    parsed = datetime.strptime(f"{now.year} {stamp}", "%Y %b %d %H:%M:%S")

    # Handle year rollover when importing late-December logs in early January.
    if parsed > now.replace(tzinfo=None) and (parsed - now.replace(tzinfo=None)).days > 180:
        parsed = parsed.replace(year=now.year - 1)

    return parsed.strftime("%Y %b %d %H:%M:%S")

def _fields(body: str) -> dict[str, str]:
    fields = {k: v for k, v in ANGLE.findall(body)}

    for key, value in PLAIN.findall(body):
        fields.setdefault(key, value)

    relay = RELAY.search(body)
    client = CLIENT.search(body)

    if relay:
        fields["relay"] = relay.group(1)

    if client:
        fields["client_ip"] = client.group(1)

    return fields

def parse_line(line: str) -> dict[str, Any] | None:
    raw = line.rstrip("\n")
    match = SYS.match(raw)

    if not match:
        return None

    data = match.groupdict()
    body = data["m"]
    queue_id = ""

    queue_match = QUEUE.match(body)
    if queue_match:
        queue_id = queue_match["q"]
        body = queue_match["b"]

    fields = _fields(body)
    service = data["p"].split("/", 1)[1]
    timestamp = _timestamp_with_year(data["t"])

    # Metadata records are retained only in the queue-metadata table.
    if service == "qmgr" and queue_id not in {"", "NOQUEUE"} and "from=<" in body.lower():
        try:
            size = int(fields["size"]) if fields.get("size") else None
        except (TypeError, ValueError):
            size = None

        return {
            "kind": "metadata",
            "queue_id": queue_id,
            "sender": fields.get("from", "").strip(),
            "message_size_bytes": size,
            "timestamp": timestamp,
            "raw_log": raw,
        }

    status_match = STATUS.search(body)
    status = status_match.group(1).lower() if status_match else ""
    low = raw.lower()

    state = {
        "sent": "DELIVERED",
        "deferred": "DEFERRED",
        "bounced": "BOUNCED",
        "expired": "UNDELIVERED",
    }.get(status)

    if not state and "reject:" in low:
        if any(marker in low for marker in SPAM_MARKERS):
            state = "QUARANTINED"
        elif any(marker in low for marker in BLOCK):
            state = "BLOCKED"
        else:
            state = "REJECTED"

    if not state and any(marker in low for marker in SPAM_MARKERS):
        state = "QUARANTINED"

    if not state and any(marker in low for marker in UNDEL):
        state = "UNDELIVERED"

    if state not in ALLOWED:
        return None

    if queue_id in {"", "NOQUEUE"} and state not in {"BLOCKED", "SPAM", "QUARANTINED", "REJECTED"}:
        return None

    sender = fields.get("from", "").strip()
    recipient = fields.get("to", "").strip()
    target = fields.get("relay") or fields.get("client_ip", "")

    try:
        size = int(fields["size"]) if fields.get("size") else None
    except (TypeError, ValueError):
        size = None

    detail = status_match.group(2).strip() if status_match and status_match.group(2) else body.strip()

    queued_as_match = QUEUED_AS.search(detail)
    queued_as = queued_as_match.group(1) if queued_as_match else ""

    target_lower = target.lower()
    detail_lower = detail.lower()
    service_lower = service.lower()

    localhost_content_filter = (
        (
            "127.0.0.1[127.0.0.1]:" in target_lower
            or "localhost[127.0.0.1]:" in target_lower
        )
        and target_lower.rsplit(":", 1)[-1]
        in INTERNAL_REINJECTION_PORTS
    )

    amavis_spam_decision = (
        localhost_content_filter
        and "spam" in detail_lower
        and (
            "discarded" in detail_lower
            or "quarantined" in detail_lower
            or "blocked" in detail_lower
            or "rejected" in detail_lower
        )
        and (
            "amavis" in service_lower
            or "2.7.0" in detail_lower
        )
    )

    if amavis_spam_decision:
        state = "QUARANTINED"
        target = "Amavis content filter"
        detail = "Message quarantined as spam"
        queued_as = ""
    elif _is_internal_reinjection(service, target, detail):
        # Ordinary localhost reinjection is not final delivery.
        return None

    event_key = "|".join([
        queue_id or "NOQUEUE",
        recipient,
        sender,
        state,
        raw,
    ])

    event_hash = hashlib.sha256(
        event_key.encode("utf-8", errors="replace")
    ).hexdigest()

    # Give every meaningful NOQUEUE rejection a stable unique reference.
    stored_queue_id = queue_id or "NOQUEUE"
    if stored_queue_id == "NOQUEUE":
        stored_queue_id = f"NOQUEUE-{event_hash[:12]}"

    return {
        "kind": "delivery",
        "event_hash": event_hash,
        "timestamp": timestamp,
        "host": data["h"],
        "service": service,
        "pid": data["pid"],
        "queue_id": stored_queue_id,
        "sender": sender,
        "recipient": recipient,
        "message_size_bytes": size,
        "final_status": state,
        "delivery_target": target,
        "status_detail": detail,
        "raw_log": raw,
        "queued_as": queued_as,
    }
