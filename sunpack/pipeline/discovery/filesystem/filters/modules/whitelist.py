from sunpack.pipeline.discovery.filesystem.filters.path_rule import PathRuleScanFilter


class WhitelistScanFilter(PathRuleScanFilter):
    name = "whitelist"
    whitelist = True
