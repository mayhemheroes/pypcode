#! /usr/bin/env python3
from typing import Optional

import atheris
import sys

import fuzz_helpers as fh

with atheris.instrument_imports():
    import pypcode

ctr = 0
context: Optional[pypcode.Context] = None
contexts_initialized = False

def TestOneInput(data):
    global context, contexts_initialized, ctr
    fdp = fh.EnhancedFuzzedDataProvider(data)

    ctr += 1

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
        if ctr > 10_000:
            raise

def main():
    print('Starting fuzzing')
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
