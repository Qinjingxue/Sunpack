# Vendored LZ4

Source: https://github.com/lz4/lz4/tree/v1.10.0/lib

Tag: v1.10.0. Library sources are unmodified. See LICENSE (BSD 2-Clause).
Both the Rust extension and the C++ archive worker compile this same source
set. xxHash symbols use SUNPACK_LZ4_ to avoid collisions with other codecs.
The surrounding stream adapter is SunPack code in ../../lz4_stream.
