#! /usr/bin/env python3
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

    try:
        if not contexts_initialized:
            chosen_arch: pypcode.Arch = fdp.PickValueInList(list(pypcode.Arch.enumerate()))
            chosen_lang = fdp.PickValueInList(list(chosen_arch.languages))
            context = pypcode.Context(chosen_lang)
            contexts_initialized = True
        if fdp.ConsumeBool():
            context.translate(fdp.ConsumeRemainingBytes())
        else:
            context.disassemble(fdp.ConsumeRemainingBytes())
    except IndexError:
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
