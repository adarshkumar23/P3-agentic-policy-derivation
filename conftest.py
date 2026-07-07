import sys
from pathlib import Path

CORE_PATCH_DIR = Path(__file__).parent / "core-side-patch"
if str(CORE_PATCH_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_PATCH_DIR))

import os
os.environ.setdefault("PATH", "")
_BIN_DIR = str(Path(__file__).parent / ".bin")
if _BIN_DIR not in os.environ["PATH"]:
    os.environ["PATH"] = _BIN_DIR + os.pathsep + os.environ["PATH"]
