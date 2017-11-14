package com.yandex.burp.extensions.modifiers;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.yandex.burp.extensions.config.BurpMollyScannerConfig;

import java.util.ArrayList;
import java.util.List;


/**
 * Created by ezaitov on 03.02.2017.
 */
public class UserAgentModifier implements IMollyModifier {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private BurpMollyScannerConfig extConfig;

    public UserAgentModifier(IBurpExtenderCallbacks callbacks, BurpMollyScannerConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.extConfig = extConfig;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            return;
        }

        if (extConfig.getUserAgent() == null) {
            return;
        }

        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo.getRequest());
        List<String> reqHeaders = requestInfo.getHeaders();
        List<String> newHeaders = new ArrayList<String>();
        for (String h : reqHeaders) {
            if (!h.toUpperCase().startsWith("USER-AGENT:"))
                newHeaders.add(h);
        }
        newHeaders.add("User-Agent: " + extConfig.getUserAgent());

        byte[] body;
        byte[] modifiedReq;
        if (helpers.bytesToString(messageInfo.getRequest()).length() > requestInfo.getBodyOffset()) {
            body = helpers.stringToBytes(helpers.bytesToString(messageInfo.getRequest()).substring(requestInfo.getBodyOffset()));
            modifiedReq = helpers.buildHttpMessage(newHeaders, body);
        } else {
            modifiedReq = helpers.buildHttpMessage(newHeaders, "".getBytes());
        }
        messageInfo.setRequest(modifiedReq);
    }
}