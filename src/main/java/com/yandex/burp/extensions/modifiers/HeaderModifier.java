package com.yandex.burp.extensions.modifiers;

import burp.IHttpRequestResponse;

/**
 * Created by ezaitov on 08.02.2017.
 */
public class HeaderModifier implements IMollyModifier {

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            return;
        }
        /* implement your modification here */
    }
}