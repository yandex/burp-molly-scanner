package burp;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSyntaxException;
import com.jayway.awaitility.Awaitility;
import com.jayway.awaitility.core.ConditionTimeoutException;
import com.yandex.burp.extensions.EntryPointDeduplicator;
import com.yandex.burp.extensions.MollyProxyListener;
import com.yandex.burp.extensions.MollyRequestResponseHandler;
import com.yandex.burp.extensions.auth.BasicAuthAdapter;
import com.yandex.burp.extensions.auth.IMollyAuthAdapter;
import com.yandex.burp.extensions.config.BurpMollyScannerConfig;
import com.yandex.burp.extensions.config.MollyAuthConfig;
import com.yandex.burp.extensions.config.MollyConfig;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;


public class BurpExtender implements IBurpExtender,
        IScannerListener,
        IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ArrayList<IScanIssue> issues;
    private ConcurrentHashMap<String, Integer> issueStat;
    public List<IScanQueueItem> scanners;
    public EntryPointDeduplicator deduper;
    private List<IHttpRequestResponse> postponedEntryPoints;
    private int scanTime;
    private int totalScanners;
    private boolean timeout;
    private PrintWriter stdout;
    private BurpMollyScannerConfig extConfig;
    private static final int timeStep = 15;
    private IMollyAuthAdapter authenticator;

    public BurpMollyScannerConfig getExtConfig() {
        return extConfig;
    }

    public IMollyAuthAdapter getAuthenticator() {
        return authenticator;
    }

    public void postponeEntryPoint(IHttpRequestResponse messageInfo) {
        synchronized (postponedEntryPoints) {
            postponedEntryPoints.add(messageInfo);
        }
    }

    public void trackScanner(IScanQueueItem scan) {
        synchronized (scanners) {
            scanners.add(scan);
        }
    }

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.timeout = false;
        this.totalScanners = 0;
        this.scanTime = 0;

        // obtain our output stream
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        // set our extension name
        callbacks.setExtensionName("MollyBurp");

        stdout.println("Extension was loaded");

        Map<String, String> env = System.getenv();
        String configPath = env.get("MOLLY_CONFIG");

        for (String arg : callbacks.getCommandLineArguments()) {
            String[] kv = arg.split("=", 2);
            if (kv.length != 2) {
                continue;
            }
            if (kv[0].equals("--molly-config")) {
                configPath = kv[1];
            }
        }

        if (configPath == null || configPath.length() == 0) {
            stdout.println("Error loading extension config");
            callbacks.exitSuite(false);
            return;
        }

        MollyConfig mollyConfig;
        try {
            String configJSON = new String(Files.readAllBytes(Paths.get(configPath)), StandardCharsets.UTF_8);
            mollyConfig = new Gson().fromJson(configJSON, MollyConfig.class);
        } catch (IOException e) {
            stdout.println("Error loading extension config");
            callbacks.exitSuite(false);
            return;
        } catch (JsonSyntaxException e) {
            stdout.println("Error loading extension config");
            callbacks.exitSuite(false);
            return;
        } catch (JsonParseException e) {
            stdout.println("Error loading extension config");
            callbacks.exitSuite(false);
            return;
        }

        this.extConfig = mollyConfig.getBurpActiveScanner();
        if (extConfig == null) {
            stdout.println("Error loading extension config");
            callbacks.exitSuite(false);
            return;
        }

        this.issues = new ArrayList<>();
        this.issueStat = new ConcurrentHashMap<>();
        this.scanners = Collections.synchronizedList(new ArrayList<IScanQueueItem>());
        this.postponedEntryPoints = new ArrayList<>();
        this.deduper = new EntryPointDeduplicator(callbacks);

        if (extConfig.getReportPath() == null) {
            stdout.println("No report path configured");
            callbacks.exitSuite(false);
            return;
        }

        if (extConfig.getEntryPoint() == null) {
            stdout.println("No initial_url configured");
            callbacks.exitSuite(false);
            return;
        }

        MollyAuthConfig authConfig = extConfig.getAuthConfig();
        /* TODO: use reflections? */
        switch (authConfig.getAuthProvider().toUpperCase()) {
            case "BASIC":
                authenticator = new BasicAuthAdapter(callbacks, authConfig);
                if (authenticator.isAuthExpected()) {
                    if (!authenticator.doAuth(null)) {
                        stdout.println("Auth config error. Invalid username/password?");
                        callbacks.exitSuite(false);
                        return;
                    }
                }
                break;
            default:
                break;
        }

        try {
            extConfig.setInitialURL(new URL(extConfig.getEntryPoint()));
        } catch (MalformedURLException e) {
            stdout.println("Invalid initial URL " + extConfig.getEntryPoint());
            callbacks.exitSuite(false);
            return;
        }

        // register custom class as an HTTP listener
        this.callbacks.registerHttpListener(new MollyRequestResponseHandler(callbacks,
                extConfig, authenticator, scanners, deduper, postponedEntryPoints));
        // register custom class as an Proxy listener
        this.callbacks.registerProxyListener(new MollyProxyListener(callbacks, extConfig,
                authenticator, deduper));

        // register ourselves as a Scanner listener
        callbacks.registerScannerListener(this);

        // register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(this);

        if (!callbacks.isInScope(extConfig.getInitialURL())) {
            callbacks.includeInScope(extConfig.getInitialURL());
        }

        callbacks.sendToSpider(extConfig.getInitialURL());

        int maxTime = extConfig.getScanTimeout() * 60;

        /* Main work happens meanwhile */
        waitForScanners(maxTime);

        /* XXX: scanners count! move max scanners count to config! */
        if (!timeout && ((maxTime-scanTime) > timeStep*2) && totalScanners < 10) {
            for (IHttpRequestResponse messageInfo : postponedEntryPoints) {
                if (scanners.size() > 20) {
                    break;
                }
                /* Full-dub detection */
                if (deduper.isFullDuplicate(messageInfo)) continue;

                /* Half-dub detection */
                if (deduper.isHalfDuplicate(messageInfo)) continue;

                /* Do not scan URLs with same parameters twice (?) */
                if (deduper.isDuplicateURL(messageInfo)) continue;

                IScanQueueItem scan = callbacks.doActiveScan(
                        extConfig.getInitialURL().getHost(),
                        extConfig.getInitialURL().getPort() == -1 ? extConfig.getInitialURL().getDefaultPort() : extConfig.getInitialURL().getPort(),
                        extConfig.getInitialURL().getProtocol().equals("https"),
                        messageInfo.getRequest());
                synchronized (scanners) {
                    scanners.add(scan);
                }
            }
        }

        /* wait for postponed entry points to be scanned */
        /* XXX: we can do better  */
        waitForScanners((maxTime-scanTime));

        if (authenticator != null) {
            authenticator.doLogout(null);
        }

        if (issues != null) {
            callbacks.generateScanReport("XML", issues.toArray(new IScanIssue[issues.size()]),
                    new File(extConfig.getReportPath()));
        }

        callbacks.exitSuite(false);
    }

    //
    // implement IScannerListener
    //
    @Override
    public void newScanIssue(IScanIssue issue) {
        if (issue == null) return;

        List<Integer> ignoreIssueIds = extConfig.getIgnoredIssueIds();
        if (ignoreIssueIds != null && ignoreIssueIds.contains(issue.getIssueType())) return;
        IHttpService issueService = issue.getHttpService();

        /* XXX: test if it really works */
        if (!issueService.getHost().contains(extConfig.getInitialURL().getHost())) {
            return;
        }

        /* Do not store more than X issues of same type - prevent huuuge reports */
        int existingIssues = issueStat.getOrDefault(issue.getIssueName(), 0);
        if (extConfig.getMaxIssuesByType() > 0 && existingIssues >= extConfig.getMaxIssuesByType()) {
            return;
        }

        switch (issue.getIssueType()) {
            // 5244160 = Cross Domain Script include, handle whitelisting here
            case 0x00500500:
                List<String> wl = extConfig.getCrossdomainJsWhitelist();
                if (wl == null) break;
                for (String d : wl) {
                    stdout.println("whitelisted: " + d);
                    /* XXX! this is ugly */
                    /* TODO: grep URIs then parse and match domains only */
                    if (issue.getIssueDetail().contains("https://" + d)) {
                        return;
                    }
                }
                break;
            /* handle CORS whitelist here */
            case 0x00200600:
                boolean isInteresting = false;
                IHttpRequestResponse[] trans = issue.getHttpMessages();
                if (trans == null) return;
                for (IHttpRequestResponse t : trans) {
                    stdout.println(t.getHttpService().getHost());
                    stdout.println(issue.getHttpService().getHost());
                    if (!extConfig.getPublicCorsWhitelist().contains(t.getHttpService().getHost())) {
                        isInteresting = true;
                        break;
                    }
                }
                if (!isInteresting) return;
                break;
            // 2098176 = crossdomain.xml, handle whitelisting here
            case 0x200400:
                if (extConfig.getCrossdomainXmlWhitelist().contains(issue.getHttpService().getHost())) {
                    return;
                }
                break;
            default:
                break;
        }

        issueStat.put(issue.getIssueName(), existingIssues+1);
        issues.add(issue);
    }

    //
    // implement IExtensionStateListener
    //
    @Override
    public void extensionUnloaded() {
        stdout.println("Extension was unloaded");
    }

    private void waitForScanners(int maxTime) {
        /* XXX!!!!!!!!!!!!!!!!!! */
        if (maxTime == 0) {
            maxTime = 3600*2;
        }
        if (maxTime < timeStep) {
            maxTime = timeStep * 2;
        }
        try {
            Awaitility.with().timeout(maxTime, TimeUnit.SECONDS)
                    .and().with().pollDelay(timeStep, TimeUnit.SECONDS)
                    .and().with().pollInterval(timeStep, TimeUnit.SECONDS)
                    .await()
                    .until(new Callable<Boolean>() {
                        @Override
                        public Boolean call() throws Exception {
                            scanTime += timeStep;
                            synchronized (scanners) {
                                Iterator<IScanQueueItem> i = scanners.iterator();
                                while (i.hasNext()) {
                                    IScanQueueItem scan = i.next();
                                    if (scan.getStatus().equals("finished")) {
                                        i.remove();
                                        totalScanners += 1;
                                    } else {
                                        stdout.println("Scanners: " + scanners.size());

                                        if (issues != null) {
                                            callbacks.generateScanReport("XML", issues.toArray(new IScanIssue[issues.size()]),
                                                    new File(extConfig.getReportPath()));
                                        }

                                        return false;
                                    }
                                }
                            }
                            return true;
                        }
                    });
        } catch (ConditionTimeoutException e) {
            /* exiting anyway */
            stdout.println("timeout!");
            timeout = true;
        }
    }
}