from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

_B32_ALPHABET = re.compile(r"^[A-Z2-7]+=*$")


@dataclass
class TotpConfig:
    secret: str                 # base32
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    issuer: str = ""
    account: str = ""


class TotpError(ValueError):
    """Segredo TOTP inválido."""


def normalize_secret(secret: str) -> str:
    cleaned = re.sub(r"[\s-]", "", secret or "").upper()
    if not cleaned:
        raise TotpError("Segredo vazio.")
    padded = cleaned + "=" * (-len(cleaned) % 8)
    if not _B32_ALPHABET.match(padded):
        raise TotpError("Segredo TOTP inválido: use apenas letras A-Z e dígitos 2-7.")
    try:
        base64.b32decode(padded, casefold=True)
    except Exception as exc:
        raise TotpError("Segredo TOTP inválido (Base32 malformado).") from exc
    return cleaned


def parse_otpauth_uri(uri: str) -> TotpConfig:
    parsed = urlparse(uri.strip())
    if parsed.scheme.lower() != "otpauth" or parsed.netloc.lower() != "totp":
        raise TotpError("URI inválida: esperado otpauth://totp/...")
    params = {k.lower(): v[0] for k, v in parse_qs(parsed.query).items()}
    if "secret" not in params:
        raise TotpError("URI não contém o parâmetro 'secret'.")

    label = unquote(parsed.path.lstrip("/"))
    issuer, _, account = label.partition(":")
    if not account:
        issuer, account = params.get("issuer", ""), issuer

    return TotpConfig(
        secret=normalize_secret(params["secret"]),
        digits=int(params.get("digits", 6)),
        period=int(params.get("period", 30)),
        algorithm=params.get("algorithm", "SHA1").upper(),
        issuer=params.get("issuer", issuer),
        account=account,
    )


def parse_secret_or_uri(value: str) -> TotpConfig:
    value = (value or "").strip()
    if value.lower().startswith("otpauth://"):
        return parse_otpauth_uri(value)
    return TotpConfig(secret=normalize_secret(value))


def generate_code(config: TotpConfig, at: Optional[float] = None) -> str:
    now = time.time() if at is None else at
    counter = int(now // config.period)
    key = base64.b32decode(config.secret + "=" * (-len(config.secret) % 8), casefold=True)

    digest_mod = {
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }.get(config.algorithm.upper(), hashlib.sha1)

    mac = hmac.new(key, struct.pack(">Q", counter), digest_mod).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** config.digits)).zfill(config.digits)


def seconds_remaining(config: TotpConfig, at: Optional[float] = None) -> int:
    now = time.time() if at is None else at
    return int(config.period - (now % config.period))


def format_code(code: str) -> str:
    """``123456`` -> ``123 456`` (mais fácil de transcrever)."""
    mid = len(code) // 2
    return f"{code[:mid]} {code[mid:]}"
