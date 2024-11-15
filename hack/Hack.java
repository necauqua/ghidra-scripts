package hack;

// we need the hack cuz I havent figured out how to pass
// PyType to java methods without it getting converted to Class
public final class Hack {
    public static void run() throws Throwable {
        // well getting the types could've been done without reflection
        // if we add jython to classpath but naaah
        var noneTpe = Class.forName("org.python.core.PyNone").getField("TYPE").get(null);
        var listTpe = Class.forName("org.python.core.PyList").getField("TYPE").get(null);

        var builtin = Class.forName("org.python.core.PyType").getDeclaredField("builtin");
        builtin.setAccessible(true);

        builtin.setBoolean(noneTpe, false);
        builtin.setBoolean(listTpe, false);
    }
}

