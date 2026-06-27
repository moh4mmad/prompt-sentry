import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH_PATTERN = re.compile(r"[​-‍﻿⁠]")
HTML_COMMENT_PATTERN = re.compile(r"<!--[\s\S]*?-->")
BASE64_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{16,}={0,2})\b")
HEX_PATTERN = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
# Spaced-out characters: "i g n o r e" -> "ignore"
SPACED_CHARS_PATTERN = re.compile(r"(?:(?:\b\w\b\s){3,}\b\w\b)")

# Leetspeak substitution map
_LEET: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
}
_LEET_RE = re.compile("[" + re.escape("".join(_LEET)) + "]")

# Homoglyph map — Cyrillic/Greek/fullwidth lookalikes → ASCII
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ο": "o", "ρ": "p", "τ": "t",
    # Fullwidth ASCII (ｉｇｎｏｒｅ → ignore)
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
}
_HOMOGLYPH_RE = re.compile("[" + re.escape("".join(_HOMOGLYPHS)) + "]")


@dataclass(frozen=True)
class NormalizedText:
    original: str
    normalized: str
    variants: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


def normalize_text(text: str) -> NormalizedText:
    evidence: list[str] = []
    normalized = unicodedata.normalize("NFKC", text)

    if ZERO_WIDTH_PATTERN.search(normalized):
        evidence.append("zero-width characters removed")
    normalized = ZERO_WIDTH_PATTERN.sub("", normalized)

    if HTML_COMMENT_PATTERN.search(normalized):
        evidence.append("html comments removed")
    normalized = HTML_COMMENT_PATTERN.sub("", normalized)

    decoded_html = html.unescape(normalized)
    if decoded_html != normalized:
        evidence.append("html entities decoded")
    normalized = decoded_html

    # Homoglyph collapse
    collapsed = _HOMOGLYPH_RE.sub(lambda m: _HOMOGLYPHS[m.group()], normalized)
    if collapsed != normalized:
        evidence.append("unicode homoglyphs collapsed")
    normalized = collapsed

    normalized = re.sub(r"\s+", " ", normalized).strip()
    variants = _decode_variants(normalized, evidence)

    return NormalizedText(original=text, normalized=normalized, variants=variants, evidence=evidence)


def _decode_variants(text: str, evidence: list[str]) -> list[str]:
    variants: list[str] = []

    # Base64 decoding
    for match in BASE64_PATTERN.finditer(text):
        token = match.group(0)
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.b64decode(padded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if _looks_textual(decoded):
            variants.append(decoded)
            evidence.append("base64-looking payload decoded")

    # Hex decoding
    for match in HEX_PATTERN.finditer(text):
        token = match.group(0)
        if token.lower().startswith("0x"):
            token = token[2:]
        try:
            decoded = bytes.fromhex(token).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_textual(decoded):
            variants.append(decoded)
            evidence.append("hex-looking payload decoded")

    # ROT13 decoding
    rot13 = text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))
    if rot13 != text and _looks_textual(rot13):
        variants.append(rot13)
        evidence.append("rot13 variant generated")

    # Leetspeak normalisation variant
    deleet = _LEET_RE.sub(lambda m: _LEET[m.group()], text)
    if deleet != text and _looks_textual(deleet):
        variants.append(deleet)
        evidence.append("leetspeak variant normalised")

    # Spaced-out character collapse ("i g n o r e" → "ignore")
    def _collapse_spaced(m: re.Match) -> str:
        return m.group().replace(" ", "")

    collapsed_spaced = SPACED_CHARS_PATTERN.sub(_collapse_spaced, text)
    if collapsed_spaced != text and _looks_textual(collapsed_spaced):
        variants.append(collapsed_spaced)
        evidence.append("space-separated character payload collapsed")

    return variants


def _looks_textual(text: str) -> bool:
    if not text or len(text.strip()) < 4:
        return False
    printable = sum(1 for char in text if char.isprintable() or char.isspace())
    return printable / len(text) > 0.85
