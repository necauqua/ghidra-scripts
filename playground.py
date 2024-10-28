# Run the playground script
# @author necauqua
# @category _My Scripts
# @keybinding
# @menupath
# @toolbar world.png
# @runtime Jython

try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass


def main():
    println('hello world')

if __name__ == '__main__':
    main()
