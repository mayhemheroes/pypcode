#! /usr/bin/env python3
import atheris
import sys

import fuzz_helpers as fh

with atheris.instrument_imports():
    import pypcode

chosen_arch: pypcode.Arch = list(pypcode.Arch.enumerate())[0]
chosen_lang = list(chosen_arch.languages)[0]
context = pypcode.Context(chosen_lang)


possible_flags = [pypcode.TranslateFlags.BB_TERMINATING, None]
def TestOneInput(data):
    fdp = fh.EnhancedFuzzedDataProvider(data)

    try:
        buff = fdp.ConsumeRandomBytes()
        buff_len = len(buff)
        base_addr = fdp.ConsumeInt(64 if '64' in chosen_arch.archname else 32)
        off = fdp.ConsumeIntInRange(0, buff_len)
        max_bytes = fdp.ConsumeIntInRange(0, buff_len - off)
        max_ins = fdp.ConsumeIntInRange(0, 100)
        flag = fdp.PickValueInList(possible_flags)
        if fdp.ConsumeBool():
            context.translate(buff, base_addr, off, max_bytes, max_ins, flag)
        else:
            context.disassemble(buff, base_addr, off, max_bytes, max_ins)
    except IndexError:
        return -1
    except TypeError as e:
        if 'incompatible' in str(e):
            return -1
        raise e

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
