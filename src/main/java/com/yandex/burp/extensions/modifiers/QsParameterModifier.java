package com.yandex.burp.extensions.modifiers;

import burp.*;
import com.yandex.burp.extensions.config.BurpMollyScannerConfig;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

/**
 * Created by ezaitov on 07.02.2017.
 */
public class QsParameterModifier implements IMollyModifier {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private BurpMollyScannerConfig extConfig;

    public QsParameterModifier(IBurpExtenderCallbacks callbacks, BurpMollyScannerConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.extConfig = extConfig;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            return;
        }

        if (extConfig.getQsParameters() == null) {
            return;
        }

        byte [] modifiedReq = messageInfo.getRequest();
        String[] pairs = extConfig.getQsParameters().split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            /* no "=" found */
            if (idx == -1) {
                try {
                    /* do not add param if it already exists */
                    if (helpers.getRequestParameter(modifiedReq, URLDecoder.decode(pair, "UTF-8")) != null) {
                        return;
                    }

                    modifiedReq = helpers.addParameter(modifiedReq,
                            helpers.buildParameter(URLDecoder.decode(pair, "UTF-8"), "",
                                    IParameter.PARAM_URL));
                } catch (UnsupportedEncodingException e) {
                    /* TODO: may be handle it one day */
                    return;
                }
            } else {
                try {
                    /* do not add param if it already exists */
                    if (helpers.getRequestParameter(modifiedReq, URLDecoder.decode(pair.substring(0, idx), "UTF-8")) != null) {
                        return;
                    }

                    modifiedReq = helpers.addParameter(modifiedReq,
                            helpers.buildParameter(URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                                    URLDecoder.decode(pair.substring(idx + 1), "UTF-8"),
                                    IParameter.PARAM_URL));
                } catch (UnsupportedEncodingException e) {
                    /* TODO: may be handle it one day */
                    return;
                }
            }
        }

//        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
//        stdout.println(helpers.bytesToString(modifiedReq));
        messageInfo.setRequest(modifiedReq);
    }
}
