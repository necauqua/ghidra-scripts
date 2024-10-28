# Create a map<K,V>
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath Scripts.Templates.map<K,V>
# @toolbar
# @runtime Jython

from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.program.model.data import (
    StructureDataType,
    DataTypeConflictHandler,
    CategoryPath,
    PointerDataType,
    Undefined4DataType,
    IntegerDataType,
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
    dialog.setStatusText('Choose the key type')
    
    tool.showDialog(dialog)
    key_type = dialog.getUserChosenDataType()
    if key_type is None:
        println('User chosen key type is null, probably cancelled')
        return

    dialog.setStatusText('Choose the value type')
    tool.showDialog(dialog)
    value_type = dialog.getUserChosenDataType()
    if value_type is None:
        println('User chosen value type is null, probably cancelled')
        return

    # ensure dir exists
    category = dtm.createCategory(CategoryPath('/auto_structs/maps'))

    node_type = StructureDataType('map_node<' + key_type.getName() + ',' + value_type.getName() + '>', 0)
    node_type.setCategoryPath(category.getCategoryPath())

    ptr = PointerDataType(node_type)
    node_type.add(ptr, 'left', 'in root node this points to the smallest node')
    node_type.add(ptr, 'parent', 'in root node this points to actual tree root node')
    node_type.add(ptr, 'right', 'in root node this points to the largest node')
    node_type.add(Undefined4DataType(), 'meta', 'never figured out the meta exactly, red-black color, etc?.')
    node_type.add(key_type, 'key', '')
    node_type.add(value_type, 'value', '')

    map_type = StructureDataType('map<' + key_type.getName() + ',' + value_type.getName() + '>', 0)
    map_type.setCategoryPath(category.getCategoryPath())

    map_type.add(PointerDataType(node_type), 'root', '')
    map_type.add(IntegerDataType(), 'len', '')

    dtm.addDataType(node_type, DataTypeConflictHandler.DEFAULT_HANDLER)
    dtm.addDataType(map_type, DataTypeConflictHandler.DEFAULT_HANDLER)


if __name__ == '__main__':
    main()
