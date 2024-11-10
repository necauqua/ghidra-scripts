# Simple analysis to find and namespace a few stb_image functions
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath Scripts.Analyze stb_image
# @toolbar
# @runtime Jython

try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass

ERROR_STRING = 'unknown image type'

def main():
    addr = findBytes(currentProgram.minAddress, ERROR_STRING + '\0')
    if addr is None:
        popup('Did not find an stb_image error string')
        return

    println('Found "%s\\0" at %s' % (ERROR_STRING, addr))

    ref_manager = currentProgram.getReferenceManager()

    ref = ref_manager.getReferencesTo(addr).next()
    if ref is None:
        popup('No references found to an stb_image error string')
        return

    instr = getInstructionAt(ref.getFromAddress())
    if instr is None:
        popup('Reference to an stb_image error string is not an instruction?.')
        return

    # ok I'm tired of null checks, if it crashes here fuck you I guess
    failure_addr = instr.getOperandReferences(0)[0].getToAddress()
    println('Found stbi__g_failure_reason at ' + str(failure_addr))

    createLabel(failure_addr, 'stbi__g_failure_reason', True)

    ns = getNamespace(currentProgram.getGlobalNamespace(), 'stb_image')

    refs = ref_manager.getReferencesTo(failure_addr)
    ctr = 0
    while refs.hasNext():
        ref = refs.next().getFromAddress()
        func = getFunctionContaining(ref)
        if func is not None:
            func.setParentNamespace(ns)
            ctr += 1

    popup('Moved %d functions to stb_image namespace' % ctr)

if __name__ == '__main__':
    main()
