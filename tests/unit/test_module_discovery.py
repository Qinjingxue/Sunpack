from sunpack.core.support.module_discovery import discover_package_modules, import_static_modules


def test_module_discovery_caches_are_bounded():
    assert discover_package_modules.cache_info().maxsize == 32
    assert import_static_modules.cache_info().maxsize == 32
