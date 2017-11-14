package com.yandex.burp.extensions.auth;

import burp.*;
import com.yandex.burp.extensions.config.MollyAuthConfig;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by ezaitov on 03.02.2017.
 */
public class BasicAuthAdapter implements IMollyAuthAdapter {
    private final int MAX_AUTH_TRIES = 2;
    private final MollyAuthConfig authConfig;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private List<ICookie> sessionCookies;
    private int authFailures;

    public BasicAuthAdapter(IBurpExtenderCallbacks callbacks, MollyAuthConfig authConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.authConfig = authConfig;
        this.authFailures = 0;
        this.sessionCookies = new ArrayList<>();
    }

    public boolean isAuthExpected() {
        return false;
    }

    public boolean doAuth(IHttpRequestResponse messageInfo) {
        if (messageInfo == null) return true;
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo.getRequest());
        List<String> reqHeaders = requestInfo.getHeaders();
        List<String> newHeaders = new ArrayList<String>();
        for (String h : reqHeaders) {
            if (!h.toUpperCase().startsWith("AUTHORIZATION:"))
                newHeaders.add(h);
        }
        newHeaders.add("Authorization: " + authConfig.getAuthPassword());

        byte[] body;
        byte[] modifiedReq;
        if (helpers.bytesToString(messageInfo.getRequest()).length() > requestInfo.getBodyOffset()) {
            body = helpers.stringToBytes(helpers.bytesToString(messageInfo.getRequest()).substring(requestInfo.getBodyOffset()));
            modifiedReq = helpers.buildHttpMessage(newHeaders, body);
        } else {
            modifiedReq = helpers.buildHttpMessage(newHeaders, "".getBytes());
        }

        messageInfo.setRequest(modifiedReq);
        return true;
    }

    public void doLogout(IHttpRequestResponse messageInfo) {
        return;
    }

    public boolean isLogoutRequest(IHttpRequestResponse messageInfo) { return false; }

    public boolean isAuthenticated(IHttpRequestResponse messageInfo) { return true; }
}
