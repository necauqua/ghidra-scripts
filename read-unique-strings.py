# Just read the unique string literals of the current function,
# in order of appearance
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath Scripts.Read unique strings
# @runtime Jython

try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass

def main():
    f = getFunctionContaining(currentLocation.getAddress())
    instr = currentProgram.getListing().getInstructionAt(f.getEntryPoint())

    seen = set()
    ordered = []

    while instr and f.getBody().contains(instr.getAddress()):
        if instr.getMnemonicString() != 'PUSH':
            instr = instr.getNext()
            continue
        ref = instr.getPrimaryReference(0)
        data = ref and getDataAt(ref.getToAddress())
        data = data and data.getValue()
        if isinstance(data, unicode) and data not in seen:
            seen.add(data)
            ordered.append(data)
        instr = instr.getNext()

    print('\n'.join(ordered))

if __name__ == '__main__':
    main()
