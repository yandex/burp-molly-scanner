package com.yandex.burp.extensions;

import burp.*;
import com.yandex.burp.extensions.auth.IMollyAuthAdapter;
import com.yandex.burp.extensions.config.BurpMollyScannerConfig;

import java.io.PrintWriter;

/**
 * Created by ezaitov on 02.03.2017.
 */
public class MollyProxyListener implements IProxyListener {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final BurpMollyScannerConfig extConfig;
    private final EntryPointDeduplicator deduper;
    private final IMollyAuthAdapter authenticator;

    public MollyProxyListener(IBurpExtenderCallbacks callbacks, BurpMollyScannerConfig extConfig,
                              IMollyAuthAdapter authenticator, EntryPointDeduplicator deduper) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.extConfig = extConfig;
        this.deduper = deduper;
        this.authenticator = authenticator;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);

        if (!messageIsRequest) {
            return;
        }

        IHttpRequestResponse messageInfo = message.getMessageInfo();
        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());

        for (String host : extConfig.getProxyDomainBlacklist()) {
            if (requestInfo.getUrl() == null || requestInfo.getUrl().getHost() == null) {
                message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
//                stdout.println("Proxy dropped: " + requestInfo.getUrl().toString());
                return;
            }
            if (host.equals(requestInfo.getUrl().getHost())) {
                message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
//                stdout.println("Proxy dropped: " + requestInfo.getUrl().toString());
                return;
            }
        }
//        stdout.println("Proxied: " + requestInfo.getUrl().toString());

    }
}
