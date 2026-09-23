"""Registry of single-file format confirmation plugins."""

from sunpack.pipeline.discovery.detection.formats import tar, gzip, bzip2, xz, zstd


CONFIRMERS = {
    module.FORMAT: module
    for module in (tar, gzip, bzip2, xz, zstd)
}
