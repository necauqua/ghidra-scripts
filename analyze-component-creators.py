# Analyze Noita component creators
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath Scripts.Analyze component creators
# @runtime Jython

try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass

from ghidra.program.model.listing import Function  # noqa: F401

from common import run, check
from ghidra.program.model.data import (
    PointerDataType, CharDataType, StructureDataType, CategoryPath
)
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.lang import OperandType

@run(this)
def main():
    table = currentProgram.getSymbolTable()
    dtm = currentProgram.getDataTypeManager()
    ref_manager = currentProgram.getReferenceManager()
    addr_factory = currentProgram.getAddressFactory()
    listing = currentProgram.getListing()

    comp_ns = table.getNamespace('Component', currentProgram.getGlobalNamespace())
    check(comp_ns, 'No Component namespace, have you analyzed Noita RTTI?')
    vftable = table.getSymbols('vftable', comp_ns).unwrap('No Component::vftable')

    comps = []
    dtm.findDataTypes('Component', comps)
    if len(comps) == 0:
        printerr('No Component data type found, creating')
        dt = StructureDataType('Component', 0x48)
        cat = CategoryPath('/auto_structs/components')
        dtm.createCategory(cat)
        dt.setCategoryPath(cat)
        comp_dt = dtm.addDataType(dt)
    else:
        comp_dt = comps[0]

    init_ref = ref_manager.getReferencesTo(vftable.getAddress()).unwrap('No references to Component::vftable found')
    init_fn = getFunctionContaining(init_ref.getFromAddress())
    check(init_fn.getParameterCount() == 2, 'Component::init function has wrong number of params (expected 2)')

    init_fn.setCustomVariableStorage(True)
    init_fn.setParentNamespace(comp_ns)
    init_fn.setName('init', SourceType.ANALYSIS)

    comp_ptr = PointerDataType(comp_dt)
    init_fn.setReturnType(comp_ptr, SourceType.ANALYSIS)
    init_fn.getParameter(0).setDataType(comp_ptr, SourceType.ANALYSIS)
    init_fn.getParameter(1).setDataType(PointerDataType(CharDataType()), SourceType.ANALYSIS)

    for init_ref in ref_manager.getReferencesTo(init_fn.getEntryPoint()):
        comp_init_fn = getFunctionContaining(init_ref.getFromAddress())
        instr = getInstructionAfter(init_ref.getFromAddress())

        found = None
        while instr is not None and comp_init_fn.getBody().contains(instr.getAddress()):
            if instr.getMnemonicString() == 'MOV' and OperandType.isAddress(instr.getOperandType(1)):
                found = instr.getOpObjects(1)[0]
                break
            instr = instr.getNext()

        if not found:
            printerr('Not found the vftable assignment in %s' % comp_init_fn)
            continue

        symbols = table.getSymbols(addr_factory.getDefaultAddressSpace().getAddress(found.getValue()))
        if len(symbols) == 0 or symbols[0].getName(False) != 'vftable':
            printerr('Not found the vftable assignment in %s' % comp_init_fn)
            continue

        symbol = symbols[0]
        ns = symbol.getParentNamespace()
        
        comps = []
        dtm.findDataTypes(ns.getName(True), comps)
        if len(comps) == 0:
            printerr('Did not find %s data type' % ns.getName(True))
            continue
        comp_ptr = PointerDataType(comps[0])

        param = comp_init_fn.getParameter(0)

        # some inits are inlined into news
        if param is not None:
            comp_init_fn.setParentNamespace(ns)
            comp_init_fn.setReturnType(comp_ptr, SourceType.ANALYSIS)
            comp_init_fn.setName('init', SourceType.ANALYSIS)

            param.setName('this', SourceType.ANALYSIS)
            param.setDataType(comp_ptr, SourceType.ANALYSIS)
            comp_init_fn = comp_init_fn.getCallingFunctions(monitor)
            if len(comp_init_fn) == 0:
                printerr('%s is not called from anywhere' % comp_init_fn)
                continue
            comp_init_fn = next(iter(comp_init_fn))

        comp_init_fn.setParentNamespace(ns)
        comp_init_fn.setReturnType(comp_ptr, SourceType.ANALYSIS)
        comp_init_fn.setName('new', SourceType.ANALYSIS)

        refs = ref_manager.getReferencesTo(comp_init_fn.getEntryPoint())
        if not refs.hasNext():
            printerr('%s is not called from anywhere ' % comp_init_fn)
            continue

        creator_setup_fn = getFunctionContaining(refs.next().getFromAddress())
        creator_setup_fn.setParentNamespace(ns)
        creator_setup_fn.setName('register_creator', SourceType.ANALYSIS)        

        param = creator_setup_fn.getParameter(0)
        if param is not None:
            param.setName('name', SourceType.ANALYSIS)

        callers = creator_setup_fn.getCallingFunctions(monitor).iterator()

        if callers.hasNext():
            init_fn = callers.next() # type: Function
            init_fn.setParentNamespace(ns)
            init_fn.setName('register_creator_static', SourceType.ANALYSIS)

            # stupid Function.getCalledFunctions returns a set, aka not in order
            # pretty sure I renamed a bunch of shit weirdly in my noita ghidra project lolol
            # anyway, look for THE FIRST call in the init function
            instr = listing.getInstructionAt(init_fn.getEntryPoint())
            found = None
            while instr is not None and init_fn.getBody().contains(instr.getAddress()):
                if instr.getMnemonicString() == 'CALL':
                    found = instr.getOpObjects(0)[0]
                    break
                instr = instr.getNext()

            if found is not None:
                name_fn = getFunctionAt(found) 
                name_fn.setParentNamespace(ns)
                name_fn.setName('get_type_name', SourceType.ANALYSIS)

                # get whatever string type you have if any, lolol
                if param is not None:
                    name_fn.setReturnType(param.getDataType(), SourceType.ANALYSIS)
                    param2 = name_fn.getParameter(0)
                    if param2 is not None:
                        param2.setDataType(param.getDataType(), SourceType.ANALYSIS)
                        param2.setName('out', SourceType.ANALYSIS)

        # idk what is this lul, seems identical to the above
        if callers.hasNext():
            init_fn = callers.next() # type: Function
            init_fn.setParentNamespace(ns)
            init_fn.setName('register_creator_static_2', SourceType.ANALYSIS)
