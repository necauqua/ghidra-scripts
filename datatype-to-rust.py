# Convert a datatype to a Rust struct (targeted at my Rust and Ghidra types)
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath Scripts.Datatype to Rust
# @toolbar
# @runtime Jython

from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.program.database.data import StructureDB
from ghidra.util.data.DataTypeParser import AllowedDataTypes
from ghidra.program.model.data import AlignmentDataType

import re

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
    dialog.setTitle("Select the datatype")
    dialog.setStatusText("Select the datatype")
    tool.showDialog(dialog)
    the_type = dialog.getUserChosenDataType()
    if the_type is None:
        println("User chosen type is null, probably cancelled")
        return

    if not isinstance(the_type, StructureDB):
        popup("Not a struct")
        return

    the_type = the_type # type: StructureDB

    type_map = {
        'byte': 'i8',
        'short': 'i16',
        'int': 'i32',
        'longlong': 'i64',
        'char': 'u8',
        'unsigned byte': 'u8',
        'unsigned short': 'u16',
        'unsigned int': 'u32',
        'uint': 'u32',
        'unsigned long long': 'u64',
        'float': 'f32',
        'double': 'f64',
        'bool': 'ByteBool',
        'vec2': 'Vec2',
        'vec2i': 'Vec2i',
        'std::string': 'StdString',
        'void *': 'RawPtr',

        'undefined': 'u8',
        'undefined1': 'u8',
        'undefined2': 'u16',
        'undefined4': 'u32',
        'undefined8': 'u64',
    }

    vec_re = re.compile('^vector<(.*?)>$')
    map_re = re.compile('^map<(.*?),(.*?)>$')
    ptr_re = re.compile('^(.*?) \*$')

    def translate(tpe):
        # type: (str) -> str
        simple = type_map.get(tpe)
        if simple:
            return simple
        tpe = vec_re.sub(lambda m: 'StdVec<' + translate(m.group(1)) + '>', tpe)
        tpe = map_re.sub(lambda m: 'StdMap<' + translate(m.group(1)) + ', ' + translate(m.group(2)) + '>', tpe)
        tpe = ptr_re.sub(lambda m: 'Ptr<' + translate(m.group(1)) + '>', tpe)
        return tpe

    to_snake = re.compile('(?<!^)(?=[A-Z])')    

    result = '\n#[derive(FromBytes, IntoBytes, Debug)]\n'
    fields = []
    repack = False
    for component in the_type.getComponents():
        tpe = component.getDataType().getName()
        rtpe = translate(tpe)

        if rtpe.endswith('64'):
            repack = True            

        name = component.getFieldName() or '_' + component.getDefaultFieldName()
        name = to_snake.sub('_', name).lower()

        if isinstance(component.getDataType(), AlignmentDataType):
            prev_name, prev_tpe, prev_len = fields[-1]
            if prev_tpe == 'ByteBool':
                prev_tpe = 'PadBool<' + str(component.getLength()) + '>'
                fields[-1] = (prev_name, prev_tpe, prev_len)
                continue

        fields.append((name, tpe, rtpe, component.getLength()))

    if repack:
        result += '#[repr(C, packed(4))]\n'
    else:
        result += '#[repr(C)]\n'

    result += 'pub struct '
    result += the_type.getName()
    result += ' {\n'
    for name, tpe, rtpe, length in fields:
        if name.startswith('_'):
            result += '    '
        else:
            result += '    pub '
        result += name
        result += ': '
        if tpe.startswith('undefined'):
            result += rtpe
            result += ', // undefined\n'
        elif rtpe == 'Alignment':
            result += '[u8; '
            result += hex(length)
            result += '], // padding\n'
        else:
            result += rtpe
            result += ',\n'
    result += '}\nconst _: () = assert!(std::mem::size_of::<'
    result += the_type.getName()
    result += '>() == '
    result += hex(the_type.getLength())
    result += ');\n'

    println(result)


if __name__ == "__main__":
    main()
