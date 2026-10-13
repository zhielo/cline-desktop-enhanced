"""Fail early on incompatible angr dependencies in source and packaged Python.

This checks installed dependency APIs, not target code. The separate owned
angr execution fixture remains mandatory after packaging.
"""
import importlib.metadata
import sys

EXPECTED_BITSTRING = "4.3.1"


def main():
    version = importlib.metadata.version("bitstring")
    print(f"angr dependency contract: python={sys.executable}; bitstring={version}", flush=True)
    if version != EXPECTED_BITSTRING:
        raise RuntimeError(
            f"Expected bitstring=={EXPECTED_BITSTRING}, found {version}; "
            "rebuild from requirements-advanced-angr.txt"
        )
    import bitstring

    print(f"angr dependency contract: module={bitstring.__file__}", flush=True)
    for name in ("ConstBitStream", "BitStream"):
        if not callable(getattr(bitstring, name, None)):
            raise RuntimeError(f"bitstring {version} is missing required API {name}")
    stream = bitstring.ConstBitStream(bytes=b"\x2a\x01")
    if stream.read("uint:8") != 42 or stream.pos != 8:
        raise RuntimeError("ConstBitStream read/position contract failed")
    if stream.peek("uint:8") != 1 or stream.pos != 8:
        raise RuntimeError("ConstBitStream peek contract failed")
    mutable = bitstring.BitStream(bytes=b"\x2a")
    if mutable.read("uint:8") != 42:
        raise RuntimeError("BitStream read contract failed")
    # Exercise the actual consumer import that previously failed in packaging.
    import pyvex

    print(f"angr dependency contract passed: pyvex={importlib.metadata.version('pyvex')}", flush=True)


if __name__ == "__main__":
    main()
