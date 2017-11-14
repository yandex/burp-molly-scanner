package com.yandex.burp.extensions;

import burp.*;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

import com.yandex.burp.extensions.auth.IMollyAuthAdapter;
import com.yandex.burp.extensions.config.BurpMollyScannerConfig;
import com.yandex.burp.extensions.modifiers.QsParameterModifier;
import com.yandex.burp.extensions.modifiers.UserAgentModifier;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;

public class MollyRequestResponseHandler implements IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private BurpMollyScannerConfig extConfig;

    private final EntryPointDeduplicator deduper;
    private final List<IScanQueueItem> scanners;
    private final List<IHttpRequestResponse> postponedEntryPoints;
    private IMollyAuthAdapter authenticator;

    public MollyRequestResponseHandler(IBurpExtenderCallbacks callbacks, BurpMollyScannerConfig extConfig,
                                       IMollyAuthAdapter authenticator, List<IScanQueueItem> scanners,
                                       EntryPointDeduplicator deduper,
                                       List<IHttpRequestResponse> postponedEntryPoints) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.extConfig = extConfig;
        this.scanners = scanners;
        this.deduper = deduper;
        this.authenticator = authenticator;
        this.postponedEntryPoints = postponedEntryPoints;
    }

    private boolean isStaticFile(String fileName) {
        List<String> skipFiles = Arrays.asList("/favicon.ico", "/robots.txt");

        for (String fn : skipFiles) {
            if (fileName.equals(fn)) {
                return true;
            }
        }

        for (String ext : extConfig.getStaticFileExt()) {
            if (fileName.endsWith("." + ext)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
        if (!callbacks.isInScope(requestInfo.getUrl())) {
            return;
        }

        if (messageIsRequest) {
            /* Modify User-Agent if required */
            if (extConfig.getUserAgent() != null) {
                UserAgentModifier ua = new UserAgentModifier(callbacks, extConfig);
                ua.processHttpMessage(toolFlag, true, messageInfo);
            }

            /* Add custom GET parameters if required */
            if (extConfig.getQsParameters() != null) {
                QsParameterModifier qsm = new QsParameterModifier(callbacks, extConfig);
                qsm.processHttpMessage(toolFlag, true, messageInfo);
            }

            /* No custom authentication configured */
            if (authenticator == null) {
                return;
            }

            if (authenticator.isAuthExpected()) {
                if (authenticator.isLogoutRequest(messageInfo)) {
                    messageInfo.setRequest("".getBytes());
                }

                if (authenticator.isAuthenticated(messageInfo)) {
                    return;
                }

                if (!authenticator.doAuth(messageInfo)) {
                    try {
                        OutputStream stderr = callbacks.getStderr();
                        stderr.write(messageInfo.getRequest());
                        stderr.write("\n".getBytes());
                        stderr.write(helpers.stringToBytes("Authentication required"));
                        stderr.write("\n".getBytes());
                    } catch (IOException ex) {
                        /**/
                    }
                        /* ignore auth failures for now
                        callbacks.exitSuite(false);
                        */
                }
            }
            return;
        }

        /* No passive or active scans for static files */
        if (isStaticFile(requestInfo.getUrl().getPath())) {
            return;
        }

        /* From now we process request-response only */
//        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
//        stdout.println(helpers.bytesToString(messageInfo.getRequest()));
//        stdout.println(helpers.bytesToString(messageInfo.getResponse()));

        callbacks.doPassiveScan(
                extConfig.getInitialURL().getHost(),
                extConfig.getInitialURL().getPort() == -1 ?
                        extConfig.getInitialURL().getDefaultPort() :
                        extConfig.getInitialURL().getPort(),
                extConfig.getInitialURL().getProtocol().equals("https"),
                messageInfo.getRequest(),
                messageInfo.getResponse());

        /* We process only spider or proxy request-responses */
        if (toolFlag != IBurpExtenderCallbacks.TOOL_SPIDER &&
                toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
            return;
        }

        if (extConfig.getMaxUrls() > 0 && scanners.size() > extConfig.getMaxUrls()) {
            return;
        }

        IResponseInfo respInfo = helpers.analyzeResponse(messageInfo.getResponse());

        /* Do not init active scans for entry points answering 404 */
        List<Integer> skipScanCodes = Arrays.asList(404, 502, 504);
        short statusCode = respInfo.getStatusCode();
        if (skipScanCodes.contains(new Integer(statusCode)) && !requestInfo.getUrl().getPath().equals("/")) {
//            stdout.println("Skipping " + statusCode + " URL: " + requestInfo.getUrl().toString());
            return;
        }

        /* Full-dub detection */
        if (deduper.isFullDuplicate(messageInfo)) return;

        /* Half-dub detection */
        if (deduper.isHalfDuplicate(messageInfo)) return;

        if (requestInfo.getUrl().getQuery() != null &&
                requestInfo.getUrl().getQuery().length() == 0 &&
                scanners.size() > 1 && !requestInfo.getUrl().getPath().equals("/")) {
            /* we scan URLs with parameters first */
            synchronized (postponedEntryPoints) {
//                stdout.println("Postponing to Active Scanner: " + requestInfo.getUrl().toString());
                postponedEntryPoints.add(messageInfo);
            }
            return;
        }

        /* Do not scan URLs with same parameters twice (?) */
        // XXX: disabled!!!
        // if (deduper.isDuplicateURL(messageInfo)) return;
//        stdout.println("Sending to Active Scanner: " + requestInfo.getUrl().toString());

        IScanQueueItem scan = callbacks.doActiveScan(
            extConfig.getInitialURL().getHost(),
            extConfig.getInitialURL().getPort() == -1 ? extConfig.getInitialURL().getDefaultPort() : extConfig.getInitialURL().getPort(),
            extConfig.getInitialURL().getProtocol().equals("https"),
            messageInfo.getRequest());
        synchronized (scanners) {
            scanners.add(scan);
        }

//        stdout.println("Scanners: " + Integer.toString(scanners.size()));
    }
}