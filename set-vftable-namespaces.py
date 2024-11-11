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
from ghidra.program.model.data import PointerDataType, BooleanDataType
try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass


def main():
    cm = currentProgram.getCodeManager()
    dtm = currentProgram.getDataTypeManager()
    table = currentProgram.getSymbolTable()

    monitor.setIndeterminate(True)

    for vftable in table.getSymbols('vftable'):
        monitor.setMessage('Working on ' + vftable.getName(True))

        data = cm.getDataAt(vftable.address)

        first = getFunctionAt(data.getComponent(0).getValue())
        if not skip(first, vftable, 0):
            first.setName('destroy', SourceType.ANALYSIS)
            second_param = first.getParameter(1)
            if second_param is not None:
                second_param.setName('dealloc', SourceType.ANALYSIS)
                second_param.setDataType(BooleanDataType(), SourceType.ANALYSIS)

        for i in range(data.getNumComponents()):
            monitor.increment()
            func = getFunctionAt(data.getComponent(i).getValue())
            if skip(func, vftable, i):
                continue

            func.setParentNamespace(vftable.getParentNamespace())

            if func.getCallingConventionName() != '__thiscall':
                continue

            func.setCustomVariableStorage(True)

            this_param = func.getParameter(0)
            if this_param is None:
                continue

            this_param.setName("this", SourceType.ANALYSIS)

            result = []
            ns_name = vftable.getParentNamespace().getName(True)
            dtm.findDataTypes(ns_name, result, True, monitor)
            if len(result) == 1:
                this_param.setDataType(PointerDataType(result[0]), SourceType.ANALYSIS)
            elif len(result) != 0:
                printerr('Found multiple (%d) datatypes for %s' % (len(result), ns_name))


def skip(func, vftable, idx):
    if func is None:
        printerr('no func at ' + vftable.getName(True) + '[' + str(idx) + ']')
        return True
    return func.getName() == '_purecall' or func.getName() == '_noop' or func.getName() == '_identity'


if __name__ == '__main__':
    main()
