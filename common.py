
try:
    from ghidra.ghidra_builtins import *  # noqa: F403
except:  # noqa: E722
    pass

from hack import Hack
from ghidra.util import Msg
from java.lang import Iterable


class PopupErrorAndStop(RuntimeError):
    pass


def popupErr(this, msg, err=None):
    # type: (PythonScript, str) -> None
    name = this.getScriptName()
    Msg.showError(this, None, name, '%s error\n\n%s' % (name, msg), err)


def popupWarn(this, msg):
    # type: (PythonScript, str) -> None
    name = this.getScriptName()
    Msg.showWarn(this, None, name, '%s error\n\n%s' % (name, msg))


def check(thing, msg):
    # type: (T, str) -> T
    if thing is None:
        raise PopupErrorAndStop(msg)
    return thing


def monkey_business():
    def list_unwrap(self, msg):
        try:
            return next(iter(self))
        except StopIteration:
            raise PopupErrorAndStop(msg)

    Iterable.unwrap = list_unwrap
    list.unwrap = list_unwrap

    @staticmethod
    def none_unwrap(msg):
        raise PopupErrorAndStop(msg)

    type(None).unwrap = none_unwrap


def run(this):
    def run(main):
        Hack.run()
        monkey_business()
        try:
            main()
        except PopupErrorAndStop as e:
            popupErr(this, e.args[0])
    return run

