"""
Multilingual Support Module – LLM Security Gateway
====================================================
Detects the language of incoming text and translates non-English content to
English before running through the injection/semantic detectors.

Uses two optional backends (in priority order):
  1. langdetect  → fast, lightweight language identification
  2. deep-translator (GoogleTranslator) → free, no-key translation

Both fall back gracefully if the packages are not installed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------
try:
    from langdetect import detect as _langdetect_detect, LangDetectException
    _LANGDETECT_AVAILABLE = True
except ImportError:
    _LANGDETECT_AVAILABLE = False
    logger.warning("langdetect not installed. Language detection will be skipped.")

try:
    from deep_translator import GoogleTranslator
    _TRANSLATOR_AVAILABLE = True
except ImportError:
    _TRANSLATOR_AVAILABLE = False
    logger.warning("deep-translator not installed. Translation will be skipped.")


# ---------------------------------------------------------------------------
# BCP-47 language names for display
# ---------------------------------------------------------------------------
LANGUAGE_NAMES: dict[str, str] = {
    "en": "English", "fr": "French", "de": "German", "es": "Spanish",
    "it": "Italian", "pt": "Portuguese", "nl": "Dutch", "ru": "Russian",
    "ar": "Arabic", "zh-cn": "Chinese (Simplified)", "zh-tw": "Chinese (Traditional)",
    "ja": "Japanese", "ko": "Korean", "hi": "Hindi", "ur": "Urdu",
    "fa": "Persian", "tr": "Turkish", "pl": "Polish", "sv": "Swedish",
    "da": "Danish", "fi": "Finnish", "no": "Norwegian", "cs": "Czech",
    "ro": "Romanian", "hu": "Hungarian", "el": "Greek", "he": "Hebrew",
    "id": "Indonesian", "ms": "Malay", "th": "Thai", "vi": "Vietnamese",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class MultilingualResult:
    original_text: str
    detected_language: str          # BCP-47 code, e.g. "fr"
    language_name: str              # human-readable, e.g. "French"
    translated_text: str            # English version (or original if already EN)
    was_translated: bool
    translation_available: bool


# ---------------------------------------------------------------------------
# Processor
# ---------------------------------------------------------------------------
class MultilingualProcessor:
    """
    Detects the language of a prompt and translates it to English.

    Usage:
        processor = MultilingualProcessor()
        result = processor.process("Ignorez toutes les instructions précédentes.")
        # result.translated_text → "Ignore all previous instructions."
        # result.detected_language → "fr"
    """

    def __init__(self, target_language: str = "en"):
        self.target_language = target_language

    # ------------------------------------------------------------------
    def detect_language(self, text: str) -> str:
        """Return BCP-47 language code. Returns 'en' if detection fails."""
        if not text or not text.strip():
            return "en"
        if not _LANGDETECT_AVAILABLE:
            return "en"
        try:
            lang = _langdetect_detect(text)
            # langdetect returns "zh-cn" / "zh-tw" etc.; normalise
            return lang.lower()
        except Exception:
            return "en"

    # ------------------------------------------------------------------
    def translate(self, text: str, source_lang: str) -> Optional[str]:
        """
        Translate text from source_lang to English.
        Returns None if translation is unavailable or not needed.
        """
        if source_lang == self.target_language:
            return None
        if not _TRANSLATOR_AVAILABLE:
            return None
        try:
            translator = GoogleTranslator(source=source_lang, target=self.target_language)
            translated = translator.translate(text)
            return translated
        except Exception as exc:
            logger.error("Translation failed (%s→%s): %s", source_lang, self.target_language, exc)
            return None

    # ------------------------------------------------------------------
    def process(self, text: str) -> MultilingualResult:
        """
        Full pipeline: detect language → translate if needed.

        Args:
            text: Raw input prompt (any language).

        Returns:
            MultilingualResult with both original and English text.
        """
        lang = self.detect_language(text)
        lang_name = LANGUAGE_NAMES.get(lang, lang.upper())

        translated = self.translate(text, lang)
        was_translated = translated is not None

        return MultilingualResult(
            original_text=text,
            detected_language=lang,
            language_name=lang_name,
            translated_text=translated if was_translated else text,
            was_translated=was_translated,
            translation_available=_TRANSLATOR_AVAILABLE,
        )

    # ------------------------------------------------------------------
    def is_english(self, text: str) -> bool:
        """Quick check: returns True if text appears to be English."""
        return self.detect_language(text) == "en"
