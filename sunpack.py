import os
import sys

# Ensure import path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sys

from sunpack.runtime.entrypoint import main
from sunpack.core.support.runtime_identity import ensure_source_runtime_id


sys.argv[:] = [sys.argv[0], *ensure_source_runtime_id(sys.argv[1:])]

if __name__ == "__main__":
    raise SystemExit(main())
