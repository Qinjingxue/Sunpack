from sunpack.core.config.advanced_defaults import advanced_config_value


def test_advanced_default_values_are_returned_as_independent_copies():
    first = advanced_config_value(("watch",))
    second = advanced_config_value(("watch",))
    first["roots"].append("changed")
    assert second["roots"] == []
