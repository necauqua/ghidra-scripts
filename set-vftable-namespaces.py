# Assign namespaces to vftable methods
# Yes I know the current implementation is racey
# cuz we don't account for hierarchies, better than nothing anyway
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath Scripts.Set vftable namespaces
# @toolbar
# @runtime Jython

from ghidra.program.model.symbol import SourceType

try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass


def main():
    cm = currentProgram.getCodeManager()
    table = currentProgram.getSymbolTable()

    monitor.setIndeterminate(True)

    for vftable in table.getSymbols('vftable'):
        monitor.setMessage('Working on ' + vftable.getName(True))

        data = cm.getDataAt(vftable.address)

        destructor = getFunctionAt(data.getComponent(0).getValue())
        if not skip(destructor, vftable, 0):
            destructor.setParentNamespace(vftable.getParentNamespace())
            destructor.setName('destroy', SourceType.ANALYSIS)

        for i in range(1, data.getNumComponents()):
            monitor.increment()
            func = getFunctionAt(data.getComponent(i).getValue())
            if not skip(func, vftable, i):
                func.setParentNamespace(vftable.getParentNamespace())


def skip(func, vftable, idx):
    if func is None:
        printerr('no func at ' + vftable.getName(True) + '[' + str(idx) + ']')
        return True
    return func.getName() == '_purecall' or func.getName() == '_noop' or func.getName() == '_identity'


if __name__ == '__main__':
    main()
