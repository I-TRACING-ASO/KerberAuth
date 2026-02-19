package kerberauth.util;

import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import kerberauth.config.Config;

public class RequestUtil {

    public static boolean is401Negotiate(HttpResponseReceived responseReceived) {
        if (!(responseReceived.statusCode() == 401)) {
            return false;
        }

        boolean supportsNegotiate = false;
        boolean supportsNTLM = false;

        for (HttpHeader header: responseReceived.headers()) {
            if (header.name().equalsIgnoreCase("WWW-Authenticate")) {
                if (header.value().startsWith("Negotiate")) {
                    supportsNegotiate = true;
                }
                if (header.value().startsWith("NTLM")) {
                    supportsNTLM = true;
                }
            }
        }

        if (Config.getInstance().isIgnoreNTLMServers()) {
            if (supportsNegotiate && supportsNTLM) {
                LogUtil.alertAndLog(Config.LogLevel.NORMAL,String.format("Not authenticating to server %s as it supports NTLM", responseReceived.initiatingRequest().headerValue("Host")));
            }
            return supportsNegotiate && !supportsNTLM;
        } else {
            return supportsNegotiate;
        }
    }

    public static String extractHostname(HttpRequest request) {
        return request.httpService().host();
    }

    public static String getCustomHeaderValue(HttpRequest request) {
        String customHeader = Config.getInstance().getCustomHeader();
        if (customHeader == null || customHeader.isEmpty()) {
            return "";
        }
        for (HttpHeader header: request.headers()) {
            if (header.name().equalsIgnoreCase(customHeader)) {
                return header.value().trim().toLowerCase();
            }
        }
        return "";
    }
    
}
