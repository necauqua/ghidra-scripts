# IConfigBase descendants implement a very nice function "#7 in the vftable",
# from which structure field names and offsets could be recovered easily,
# along with a templated function that you could use to get their types as well
# - aka the entire datatype recovered.
# Given that those template functions have the parameter types set accordingly,
# this script can recover those descendants, which includes all component types.
#@author necauqua
#@category _My Scripts
#@keybinding 
#@menupath Scripts.Analyze IConfigBase
#@toolbar
#@runtime Jython

from collections import OrderedDict
from math import ceil

from ghidra.program.database.data import PointerDB
from ghidra.program.model.data import (
    StructureDataType,
    PointerDataType,
    IntegerDataType,
    Undefined,
    Undefined1DataType,
    AlignmentDataType,
    DataTypeConflictHandler,
    CategoryPath,
    VoidDataType,
    StringDataType,
)
from ghidra.program.model.lang import OperandType
from ghidra.program.model.symbol import RefType, SourceType


try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass

table = currentProgram.getSymbolTable()
cm = currentProgram.getCodeManager()
dtm = currentProgram.getDataTypeManager()


def find_base_class_desc(symbol_path):
    # type: (str) -> Optional[Symbol]
    ns = currentProgram.getGlobalNamespace()
    for part in symbol_path.split('::'):
        ns = table.getNamespace(part, ns)
        if ns is None:
            return

    for child in table.getChildren(ns.getSymbol()):
        if child.getName().startswith('RTTI_Base_Class_Descriptor'):
            return child


def main():
    base_class = find_base_class_desc('ceng::IConfigBase')
    if base_class is None:
        popup('ceng::IConfigBase base class not found :shrug:')       
        return
    component_class = find_base_class_desc('Component')
    if component_class is None:
        popup('Component base class not found :shrug:')
        return

    components_cat = dtm.createCategory(CategoryPath('/auto_structs/components'))\
        .getCategoryPath()
    config_base_cat = dtm.createCategory(CategoryPath('/auto_structs/config_base'))\
        .getCategoryPath()

    components = 0
    total = 0
    
    for sym in table.getSymbols('RTTI_Base_Class_Array'):
        main_ns = sym.getParentNamespace()
        data = cm.getDataAt(sym.address)

        first_ancestor = data.getComponent(data.getNumComponents() - 1)
        if not first_ancestor:
            print('no ancestors', main_ns.getName(True))
            continue

        addr = first_ancestor.getValue()
        if addr != base_class.getAddress():
            # not an IConfigBase descendant
            continue

        second_ancestor = data.getComponent(data.getNumComponents() - 2)
        is_component = second_ancestor and second_ancestor.getValue() == component_class.getAddress()
        if is_component:
            components += 1
        
        vftable = table.getSymbols('vftable', main_ns)[0]
        if vftable is None:
            print('no vftable for', main_ns.getName(True))
            continue

        data = cm.getDataAt(vftable.address)

        # the magic 7th function
        addr = data.getComponent(6).getValue()

        func = getFunctionAt(addr)
        if func is None:
            print('no function at', addr, main_ns.getName(True))
            continue

        if func.getName() == '_purecall':
            print('skipping abstract class', main_ns.getName(True))
            continue

        func.setParentNamespace(main_ns)
        func.setName('get_value', SourceType.ANALYSIS)

        auto_type = dtm.getDataType('/' + main_ns.getName())
        if auto_type is not None and auto_type.isNotYetDefined():
            print('removing placeholder type', main_ns.getName(True))
            dtm.remove(auto_type, None)

        our_type = StructureDataType(main_ns.getName(), 0)
        our_type.setCategoryPath(is_component and components_cat or config_base_cat)
        our_type = dtm.addDataType(our_type, DataTypeConflictHandler.REPLACE_HANDLER)

        func.setCustomVariableStorage(True)
        this_param = func.getParameter(0)
        if this_param is None:
            print('no this param?', main_ns.getName(True))
        else:
            this_param.setDataType(PointerDataType(our_type), SourceType.ANALYSIS)
            this_param.setName('this', SourceType.ANALYSIS)

        if is_component:
            c = dtm.getDataType('/auto_structs/components/Component')

            # eh, stub it if they don't have it here
            if c is None:
                c = StructureDataType('Component', 0x48)
                c.setCategoryPath(components_cat)
                c = dtm.addDataType(c, DataTypeConflictHandler.DEFAULT_HANDLER)

            end = c.getLength()
            if our_type.getLength() < end:
                our_type.setLength(end)
            our_type.replaceAtOffset(0, c, c.getLength(), "p", "")
        else:
            v = PointerDataType(VoidDataType())
            end = v.getLength()
            if our_type.getLength() < end:
                our_type.setLength(end)
            our_type.replaceAtOffset(0, v, v.getLength(), "vftable", "")

        data = analyze_function(func)

        field_type = None

        for name, (offset, f) in data.items():
            f = f # type: Function
            param = f.getParameter(1)
            if isinstance(param, IntegerDataType):
                param = f.getParameter(2)
            if param is None:
                continue

            field_type = param.getDataType()
            if isinstance(field_type, PointerDB):
                # happy path, unwrap one reference layer
                field_type = field_type.getDataType()
            else:
                field_type = Undefined1DataType()

            if Undefined.isUndefined(field_type):
                printerr('%s.%s is untyped :shrug:' % (our_type.getName(), name))
                # set the type to a real undefined so that we could have the field named still
                field_type = Undefined1DataType()

            end = offset + field_type.getLength()
            if our_type.getLength() < end:
                our_type.setLength(end)
            our_type.replaceAtOffset(offset, field_type, field_type.getLength(), name, "")

            add_padding_if_needed(our_type, field_type, offset)

        our_type.setLength(int(ceil(our_type.getLength() / 4.0)) * 4)
        if field_type:
            add_padding_if_needed(our_type, field_type, our_type.getLength())
        total += 1

    popup('Total: %d, components: %d' % (total, components))


# insane heuristics
def add_padding_if_needed(our_type, field_type, offset):
    # type: (StructureDataType, DataType, int) -> None
    i = 0
    immediate_prev = our_type.getComponentContaining(offset - 1) # type: DataTypeComponentDB
    while immediate_prev and Undefined.isUndefined(immediate_prev.getDataType()):
        i += 1
        immediate_prev = our_type.getComponentContaining(offset - 1 - i)

    if i == 0 or not immediate_prev:
        return

    # usually 4 bytes before longs/doubles
    if field_type.getLength() == 8 and i >= 4 and i < 8:
        our_type.replaceAtOffset(offset - i, AlignmentDataType(), i, '', '')
        return

    # 1-3 bytes after 1-2 byte types
    if immediate_prev.getDataType().getLength() < 4 and i < 4:
        our_type.replaceAtOffset(offset - i, AlignmentDataType(), i, '', '')


def analyze_function(func):
    # type: (Function) -> OrderedDict[str, (int, Function)]

    field_info = OrderedDict()

    instructions = currentProgram.getListing().getInstructions(func.getBody(), True)

    for instr in instructions:
        # look for MOV EDX, imm32
        if instr.getMnemonicString() != "MOV":
            continue
        if not OperandType.isRegister(instr.getOperandType(0)):
            continue
        if instr.getOpObjects(0)[0].getName() != "EDX":
            continue
        if not OperandType.isScalar(instr.getOperandType(1)):
            continue
        ref = instr.getOperandReferences(1)[0]
        if ref.getReferenceType() != RefType.DATA:
            continue

        # and get the data at that imm32
        addr = ref.getToAddress()
        data = getDataAt(addr)

        # handle strings that were untyped (<= 4 in length usually)
        if data is None:
            cm.createCodeUnit(addr, StringDataType(), -1)
            data = getDataAt(addr)

        field_name = data.getValue()

        # look for a LEA after that
        lea_instr = instr.getNext()
        offset = None
        while lea_instr is not None:
            if lea_instr.getMnemonicString() == "LEA":
                offset = lea_instr.getOpObjects(1)[1]
                break
            lea_instr = lea_instr.getNext()

        if offset is None:
            continue

        # and for a call after that
        call_instr = lea_instr.getNext() if lea_instr else None
        f = None
        while call_instr is not None:
            if call_instr.getMnemonicString() == "CALL":
                f = getFunctionAt(call_instr.getOpObjects(0)[0])
                break
            call_instr = call_instr.getNext()

        if f is not None:
            field_info[field_name] = (offset.getValue(), f)

    return field_info


if __name__ == '__main__':
    main()

