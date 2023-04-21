#! /usr/bin/env python3
import io
from contextlib import contextmanager
from random import random

import atheris
import sys

import mmap
import fuzz_helpers as fh

with atheris.instrument_imports():
    import pypcode

# Exceptions

@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr

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
