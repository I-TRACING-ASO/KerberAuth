package kerberauth.util;

import kerberauth.config.Config;
import kerberauth.KerberAuthExtension;
import kerberauth.config.Config.LogLevel;

public class LogUtil {

    public static void alert(LogLevel level, String message) {
        if (level.compareTo(Config.getInstance().getLogLevel()) <= 0) {
            KerberAuthExtension.api.logging().logToError(message);
        }
    }

    public static void log(LogLevel level, String message) {
        if (level.compareTo(Config.getInstance().getLogLevel()) <= 0) {
            KerberAuthExtension.api.logging().logToOutput(message);
        }
    }

    public static void logWithTimestamp(LogLevel level, String message) {
        if (level.compareTo(Config.getInstance().getLogLevel()) <= 0) {
            String timestampedMessage = String.format("[%tF %tT] %s", System.currentTimeMillis(), System.currentTimeMillis(), message);
            KerberAuthExtension.api.logging().logToOutput(timestampedMessage);
        }
    }

    public static void logException(LogLevel level, Exception e) {
        if (level.compareTo(Config.getInstance().getLogLevel()) <= 0) {
            KerberAuthExtension.api.logging().logToError(e);
        }
    }

    public static void alertAndLog(LogLevel level, String message) {
        alert(level, message);
        log(level, message);
    }

}
