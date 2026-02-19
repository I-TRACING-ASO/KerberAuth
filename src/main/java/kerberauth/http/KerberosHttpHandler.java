package kerberauth.http;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import kerberauth.authenticator.KerberosAuthenticator;
import kerberauth.config.Config;
import kerberauth.util.DomainUtil;
import kerberauth.util.LogUtil;
import kerberauth.util.RequestUtil;

public class KerberosHttpHandler implements HttpHandler {

    private final Config config;
    private final MontoyaApi api;
    private final KerberosAuthenticator authenticator;
    private final Set<String> hostname401Set = ConcurrentHashMap.newKeySet();

    public KerberosHttpHandler(MontoyaApi api) {
        this.config = Config.getInstance();
        this.api = api;
        this.authenticator = KerberosAuthenticator.getInstance();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Skip if Kerberos auth is disabled or host is out of scope
        if (!config.isKerberosEnabled() || !DomainUtil.isInScope(requestToBeSent.httpService().host(), config)) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // PROACTIVE: always perform auth
        if (config.getAuthenticationStrategy() == Config.AuthenticationStrategy.PROACTIVE) {
            return performKerberosAuth(requestToBeSent);
        }
        
        // PROACTIVE_401: check if in list of 401 Negotiate hosts and perform auth
        if (config.getAuthenticationStrategy() == Config.AuthenticationStrategy.PROACTIVE_401 && hostname401Set.contains(requestToBeSent.httpService().host())) {
            return performKerberosAuth(requestToBeSent);
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!config.isKerberosEnabled() || !RequestUtil.is401Negotiate(responseReceived)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        String host = responseReceived.initiatingRequest().httpService().host();

        // Always remember hosts that returned 401 Negotiate (useful for PROACTIVE_401)
        hostname401Set.add(host);

        // REACTIVE: authenticate and re-send immediately
        if (config.getAuthenticationStrategy() == Config.AuthenticationStrategy.REACTIVE) {
            HttpRequest originalRequest = responseReceived.initiatingRequest();
            HttpRequest authenticatedRequest = authenticator.authenticateRequest(originalRequest);

            if (authenticatedRequest != originalRequest) {
                LogUtil.log(Config.LogLevel.VERBOSE,
                    String.format("REACTIVE: re-sending authenticated request to %s", host));
                api.http().sendRequest(authenticatedRequest);
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }
    
    private RequestToBeSentAction performKerberosAuth(HttpRequestToBeSent requestToBeSent) {
        if (requestToBeSent.hasHeader("Authorization")) {
            LogUtil.log(Config.LogLevel.VERBOSE,
                String.format("Request to %s already has Authorization header, skipping Kerberos auth.",
                    requestToBeSent.httpService().host()));
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        HttpRequest authenticated = authenticator.authenticateRequest(requestToBeSent);
        return RequestToBeSentAction.continueWith(authenticated);
    }

}
