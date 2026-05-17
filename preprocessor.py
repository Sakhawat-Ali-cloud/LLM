"""
Text Preprocessor – LLM Security Gateway
==========================================
Normalises obfuscated / evasion-style text BEFORE running detection:
  - Leetspeak  (3→e, @→a, 1→i …)
  - Extra spaces between letters  (j a i l b r e a k → jailbreak)
  - Base64 sniffing and inline decode attempt
  - Unicode homograph normalisation (fullwidth ASCII → ASCII)
"""

from __future__ import annotations

import base64
import re
import unicodedata


# Leetspeak substitution table
_LEET_MAP = str.maketrans(
    {
        "0": "o", "1": "i", "3": "e", "4": "a",
        "5": "s", "6": "g", "7": "t", "8": "b",
        "@": "a", "$": "s", "!": "i",
    }
)

# Base64 pattern (at least 20 chars, padding optional)
_B64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Spaced-letter pattern: single chars separated by spaces/dashes
_SPACED_LETTER = re.compile(r"(?<!\w)((?:[a-zA-Z][\s\-]){3,}[a-zA-Z])(?!\w)")


class TextPreprocessor:
    """
    Normalise evasion techniques in raw prompt text before detection.

    Usage:
        preprocessor = TextPreprocessor()
        clean = preprocessor.normalize("1gn0r3 @ll 1nstruct10ns")
        # → "ignore all instructions"
    """

    def __init__(
        self,
        fix_leet: bool = True,
        fix_spacing: bool = True,
        decode_base64: bool = True,
        fix_unicode: bool = True,
    ):
        self.fix_leet = fix_leet
        self.fix_spacing = fix_spacing
        self.decode_base64 = decode_base64
        self.fix_unicode = fix_unicode

    # ------------------------------------------------------------------
    def normalize(self, text: str) -> str:
        if not text:
            return text

        if self.fix_unicode:
            text = self._normalize_unicode(text)
        if self.fix_spacing:
            text = self._remove_spaced_letters(text)
        if self.decode_base64:
            text = self._expand_base64(text)
        if self.fix_leet:
            text = self._deleet(text)

        return text

    # ------------------------------------------------------------------
    def _normalize_unicode(self, text: str) -> str:
        """Convert fullwidth / homoglyph characters to ASCII equivalents."""
        # NFKC normalisation collapses fullwidth (ａ→a, ｉ→i etc.)
        return unicodedata.normalize("NFKC", text)

    def _remove_spaced_letters(self, text: str) -> str:
        """Collapse spaced-out letters: 'j a i l b r e a k' → 'jailbreak'."""
        def _collapse(m: re.Match) -> str:
            return re.sub(r"[\s\-]", "", m.group(0))
        return _SPACED_LETTER.sub(_collapse, text)

    def _expand_base64(self, text: str) -> str:
        """
        Find base64 blobs and append their decoded text in parentheses
        so the detectors can inspect the underlying content.
        """
        def _try_decode(m: re.Match) -> str:
            blob = m.group(0)
            try:
                # Pad if necessary
                padded = blob + "=" * (-len(blob) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                if decoded.strip():
                    return f"{blob} ({decoded})"
            except Exception:
                pass
            return blob

        return _B64_PATTERN.sub(_try_decode, text)

    def _deleet(self, text: str) -> str:
        """Apply leetspeak substitution."""
        return text.translate(_LEET_MAP)
