# Name all empty functions '_noop' and all identity functions '_identity'
# Also all thunks (functions that immediately jump to another function)
# will be renamed to the target function name
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath Scripts.Analyze noops
# @toolbar
# @runtime Jython

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.lang import OperandType
from ghidra.program.model.listing import Instruction, Function  # noqa: F401

try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass


listing = currentProgram.getListing()
noops = 0
identities = 0


def analyze_function(f):
    # type: (Function) -> None
    global noops, identities

    instrs = listing.getInstructions(f.getBody(), True)
    instr = next(instrs) # type: Instruction
    if instr.getMnemonicString() == 'RET':
        f.setName('_noop', SourceType.ANALYSIS)
        f.setParentNamespace(currentProgram.getGlobalNamespace())
        f.setInline(True)
        noops += 1
        return

    if instr.getMnemonicString() == 'JMP':
        # we only look at rel jumps
        if not OperandType.isCodeReference(instr.getOperandType(0)):
            return
        jump_to = getFunctionAt(instr.getOpObjects(0)[0])
        if jump_to is not None:
            analyze_function(jump_to)
            # this will rename all thunks, not just noops/identities, 
            f.setName(jump_to.getName(), SourceType.ANALYSIS)
            f.setInline(True)

        return

    second = next(instrs)
    if second is None:
        printerr('function %s (%s) only instruction was %s' %(f.getName(), f.getBody().getMinAddress(), instr))
        return

    # meh after seeing noops I expected more than a hundred identities
    if second.getMnemonicString() == 'RET' and str(instr) == 'MOV EAX,ECX':
        f.setName('_identity', SourceType.ANALYSIS)
        f.setParentNamespace(currentProgram.getGlobalNamespace())
        f.setInline(True)
        identities += 1


def main():
    fm = currentProgram.getFunctionManager()
    monitor.initialize(fm.getFunctionCount())

    for f in fm.getFunctions(True):
        monitor.setMessage('Checking ' + f.getName())
        monitor.increment()
        analyze_function(f)

    popup('Found and named %d noops and %d identities' % (noops, identities))

if __name__ == '__main__':
    main()
