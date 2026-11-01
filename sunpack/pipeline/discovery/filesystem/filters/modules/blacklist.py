from sunpack.pipeline.discovery.filesystem.filters.path_rule import PathRuleScanFilter


class BlacklistScanFilter(PathRuleScanFilter):
    name = "blacklist"
    whitelist = False
