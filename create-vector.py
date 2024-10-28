# Create a vector<T>
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath Scripts.Templates.vector<T>
# @toolbar
# @runtime Jython

from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.program.model.data import (
    StructureDataType,
    DataTypeConflictHandler,
    CategoryPath,
    PointerDataType,
)
from ghidra.util.data.DataTypeParser import AllowedDataTypes

try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass


def main():
    dtm = currentProgram.getDataTypeManager()

    tool = state.getTool()
    dialog = DataTypeSelectionDialog(
        tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH
    )
    dialog.setStatusText('Choose the vector item type')
    tool.showDialog(dialog)
    item_type = dialog.getUserChosenDataType()
    if item_type is None:
        println('User chosen type is null, probably cancelled')
        return

    # ensure dir exists
    category = dtm.createCategory(CategoryPath('/auto_structs/vectors'))

    our_type = StructureDataType('vector<' + item_type.getName() + '>', 0)
    our_type.setCategoryPath(category.getCategoryPath())

    ptr = PointerDataType(item_type)
    our_type.add(ptr, 'start', '')
    our_type.add(ptr, 'end', '')
    our_type.add(ptr, 'cap', '')

    dtm.addDataType(our_type, DataTypeConflictHandler.DEFAULT_HANDLER)


if __name__ == '__main__':
    main()
