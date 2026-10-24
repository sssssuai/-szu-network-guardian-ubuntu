"""Keep credentials and authentication URLs out of UI, console and log files."""
import re
from urllib.parse import quote, quote_plus


def redact_message(message: str, password: str = "") -> str:
    message = str(message)
    message = re.sub(r"(https?://[^\s?]+)\?[^\s]*", r"\1?[redacted]", message)
    message = re.sub(
        r"(?i)\b(password|user_password|password_dpapi|password_fernet|challenge|info|chksum)\s*[=:]\s*[^\s&,;]+",
        r"\1=[redacted]", message,
    )
    if password:
        for value in sorted({password, quote(password, safe=""), quote_plus(password, safe="")}, key=len, reverse=True):
            message = message.replace(value, "[redacted]")
    return message
