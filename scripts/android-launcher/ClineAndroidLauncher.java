// Internal fixed-entry bridge. The Windows Java launcher decodes argv through the
// active ANSI code page; ASCII Base64 transports UTF-8 without changing OS locale.
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

public final class ClineAndroidLauncher {
    private static final Map<String, String> ENTRIES = Map.of(
        "apktool", "brut.apktool.Main",
        "smali", "com.android.tools.smali.smali.Main",
        "baksmali", "com.android.tools.smali.baksmali.Main",
        "jadx", "jadx.cli.JadxCLI",
        "bundletool", "com.android.tools.build.bundletool.BundleToolMain",
        "apksigner", "com.android.apksigner.ApkSignerTool",
        "keytool", "sun.security.tools.keytool.Main"
    );
    public static void main(String[] args) throws Throwable {
        if (args.length == 0 || !ENTRIES.containsKey(args[0]))
            throw new IllegalArgumentException("Fixed Android entry required");
        String[] decoded = new String[args.length - 1];
        for (int i = 1; i < args.length; i++) {
            if (!args[i].startsWith("u:")) throw new IllegalArgumentException("Encoded argument required");
            decoded[i - 1] = new String(Base64.getDecoder().decode(args[i].substring(2)), StandardCharsets.UTF_8);
        }
        try {
            Class.forName(ENTRIES.get(args[0])).getMethod("main", String[].class)
                .invoke(null, (Object) decoded);
        } catch (InvocationTargetException error) {
            throw error.getCause();
        }
    }
}
