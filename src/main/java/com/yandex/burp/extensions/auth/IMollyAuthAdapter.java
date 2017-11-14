package com.yandex.burp.extensions.auth;

import burp.IHttpRequestResponse;

/**
 * Created by ezaitov on 06.02.2017.
 */
public interface IMollyAuthAdapter {
    public boolean isAuthExpected();
    public boolean doAuth(IHttpRequestResponse messageInfo);
    public void doLogout(IHttpRequestResponse messageInfo);
    public boolean isAuthenticated(IHttpRequestResponse messageInfo);
    public boolean isLogoutRequest(IHttpRequestResponse messageInfo);
}
