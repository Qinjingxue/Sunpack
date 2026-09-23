from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField
from sunpack.core.i18n import normalize_language


DEFAULT_CLI_LANGUAGE = advanced_config_value(("cli", "language"))


CONFIG_FIELDS = (
    ConfigField(
        path=("cli", "language"),
        default=DEFAULT_CLI_LANGUAGE,
        normalize=normalize_language,
        owner=__name__,
    ),
)
