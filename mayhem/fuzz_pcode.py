#! /usr/bin/env python3
from random import random
from typing import Optional

import atheris
import sys

import fuzz_helpers as fh

with atheris.instrument_imports():
    import pypcode


context: Optional[pypcode.Context] = None
contexts_initialized = False

def TestOneInput(data):
    global context, contexts_initialized

    fdp = fh.EnhancedFuzzedDataProvider(data)
    if not contexts_initialized:
        chosen_arch: pypcode.Arch = fdp.PickValueInList(list(pypcode.Arch.enumerate()))
        chosen_lang = fdp.PickValueInList(list(chosen_arch.languages))
        context = pypcode.Context(chosen_lang)
        contexts_initialized = True

    try:
        base = fdp.ConsumeInt(32)
        pypcode.TranslationResult = context.translate(fdp.ConsumeRemainingBytes(), base)
    except OverflowError:
        # Raise sometimes, as it occurs too often
        if random() > 0.999:
            raise

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
