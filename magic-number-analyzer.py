# Put the cursor in the GetMagicNumber function and run this
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath Scripts.Analyze GetMagicNumber
# @toolbar
# @runtime Jython

from ghidra.program.database.data import PointerDB
from ghidra.program.model.data import StringDataType, IntegerDataType
from ghidra.program.model.lang import OperandType
from ghidra.program.model.symbol import RefType, SourceType

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
    table = currentProgram.getSymbolTable()
    global_ns = currentProgram.getGlobalNamespace()
    
    instrs = listing.getInstructions(func.getBody(), True)
    for instr in instrs:
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

        # and fixup the string in case it's borked lol
        if data is None:
            listing.createData(addr, StringDataType())
            data = getDataAt(addr)

        name = data.getValue()

        # look for the PUSH of the magic number address
        push_instr = instr.getNext()
        thing_address = None
        while push_instr is not None:
            if push_instr.getMnemonicString() == "PUSH":
                thing_address = push_instr.getOperandReferences(0)[0].getToAddress()
                break
            push_instr = push_instr.getNext()

        if thing_address is None:
            continue

        # then look for the call that the push was an arg for,
        # to extract the type from the CAnyContainer setter (which is that call)
        call_instr = push_instr.getNext() if push_instr else None
        f = None
        while call_instr is not None:
            if call_instr.getMnemonicString() == "CALL":
                f = getFunctionAt(call_instr.getOpObjects(0)[0])
                break
            call_instr = call_instr.getNext()

        # some of those setters have an extra unused int param, something's borked ig
        param = f.getParameter(1)
        if isinstance(param, IntegerDataType):
            param = f.getParameter(2)
        if param is None:
            continue

        # woo-hoo name the magic number
        table.createCodeSymbol(thing_address, name, global_ns, SourceType.ANALYSIS, None)

        # and try to type it, if the container setter was typed
        field_type = param.getDataType()
        if isinstance(field_type, PointerDB):
            field_type = field_type.getDataType()

            # this shit is racey af, idk how to sync clearing the type and then setting it
            # ...
            # yet createData throws without clearing before and doesn't when you clear,
            # only for the final result to be the clear, what the actual fuck tho lul
            # just run the script once with second line commented out, and once without the first one
            listing.clearCodeUnits(thing_address, thing_address.add(field_type.getLength()), True)
            listing.createData(thing_address, field_type)

if __name__ == '__main__':
    main()
