# Put the cursor in the Lua API setup function and run this
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath Scripts.Analyze Lua APIs
# @toolbar
# @runtime Jython

from ghidra.program.model.lang import OperandType
from ghidra.program.model.symbol import SourceType

try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass


def main():
    func = getFunctionContaining(currentLocation.address)
    if func is None:
        popup('Not inside of a function!')
        return

    listing = currentProgram.getListing()
    ns = getNamespace(currentProgram.getGlobalNamespace(), 'lua_api')
    
    instrs = listing.getInstructions(func.getBody(), True)
    for instr in instrs:
        # look for PUSH 0x0
        if instr.getMnemonicString() != "PUSH":
            continue
        if not OperandType.isScalar(instr.getOperandType(0)) or instr.getOpObjects(0)[0].getValue() != 0:
            continue

        # followed by PUSH <lua callback function>
        instr = instrs.next()
            
        f = getFunctionAt(instr.getOperandReferences(0)[0].getToAddress())

        # followed by a CALL (lua_pushcclosure)
        while instr.getMnemonicString() != "CALL":
            instr = instrs.next()
        # and first PUSH after that is the name
        while instr.getMnemonicString() != "PUSH":
            instr = instrs.next()

        ref = instr.getOperandReferences(0)[0]
        addr = ref.getToAddress()
        data = getDataAt(addr)
        name = data.getValue()

        f.setParentNamespace(ns)
        f.setName(name, SourceType.ANALYSIS)

if __name__ == '__main__':
    main()
