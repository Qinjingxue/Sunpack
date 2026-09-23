from dataclasses import dataclass
from string import Formatter
from typing import Any

from sunpack.core.i18n.catalog import CATALOG

DEFAULT_LANGUAGE = "en"


def normalize_language(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return "zh" if normalized == "zh" else DEFAULT_LANGUAGE


@dataclass(frozen=True)
class I18nContext:
    language: str = DEFAULT_LANGUAGE

    def __post_init__(self) -> None:
        object.__setattr__(self, "language", normalize_language(self.language))

    def t(self, key: str, **params: Any) -> str:
        text = CATALOG.get(self.language, {}).get(key)
        if text is None:
            text = CATALOG[DEFAULT_LANGUAGE].get(key, key)
        return text.format(**params) if params else text

    def format_duration(self, seconds: float) -> str:
        total_seconds = int(max(0.0, seconds))
        minutes, secs = divmod(total_seconds, 60)
        if minutes:
            return self.t("duration.minutes_seconds", minutes=minutes, seconds=secs)
        return self.t("duration.seconds", seconds=secs)


def validate_catalog() -> None:
    base_keys = set(CATALOG[DEFAULT_LANGUAGE])
    formatter = Formatter()
    for language, texts in CATALOG.items():
        missing = sorted(base_keys - set(texts))
        extra = sorted(set(texts) - base_keys)
        if missing or extra:
            raise ValueError(f"Catalog key mismatch for {language}: missing={missing} extra={extra}")
        for key in sorted(base_keys):
            base_fields = {name for _, name, _, _ in formatter.parse(CATALOG[DEFAULT_LANGUAGE][key]) if name}
            translated_fields = {name for _, name, _, _ in formatter.parse(texts[key]) if name}
            if translated_fields != base_fields:
                raise ValueError(
                    f"Catalog placeholder mismatch for {language}.{key}: "
                    f"expected={sorted(base_fields)} actual={sorted(translated_fields)}"
                )
