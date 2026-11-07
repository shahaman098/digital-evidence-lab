"""Compatibility shim; the generator lives in evidence_lab.demo now."""

import sys

from evidence_lab.demo import make_demo

if __name__ == "__main__":
    make_demo(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
