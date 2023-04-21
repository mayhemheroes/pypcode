#! /usr/bin/env python3
from random import random

import atheris
import sys

import fuzz_helpers as fh

with atheris.instrument_imports():
    import pypcode

# Too expensive to create all contexts, so we'll just test a few
arch_slice = list(pypcode.Arch.enumerate())[:7]
contexts: list[pypcode.Context] = [
    pypcode.Context(lang) for arch in arch_slice for lang in arch.languages
]

contexts_initialized = False

def TestOneInput(data):
    fdp = fh.EnhancedFuzzedDataProvider(data)
    ctx = fdp.PickValueInList(contexts)

    try:
        base = fdp.ConsumeInt(32)
        pypcode.TranslationResult = ctx.translate(fdp.ConsumeRemainingBytes(), base)
    except OverflowError:
        # Raise sometimes, as it occurs too often
        if random() > 0.99:
            raise

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
