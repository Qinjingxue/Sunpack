from sunpack.core.config.advanced_defaults import advanced_config_value


def test_advanced_default_values_are_returned_as_independent_copies():
    first = advanced_config_value(("analysis",))
    second = advanced_config_value(("analysis",))
    first["modules"][0]["enabled"] = False
    first["modules"].clear()
    assert second["modules"][0] == {"name": "zip", "enabled": True}
