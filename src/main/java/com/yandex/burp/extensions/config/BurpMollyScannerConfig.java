package com.yandex.burp.extensions.config;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.net.URL;
import java.util.List;

/**
 * Created by ezaitov on 04.02.2017.
 */
public class BurpMollyScannerConfig {
    private URL initialURL;

    @SerializedName("scan_timeout")
    private int scanTimeout;

    @SerializedName("max_urls")
    private int maxUrls;

    @SerializedName("max_issue_samples")
    private int maxIssuesByType;

    @SerializedName("report_path")
    private String reportPath;

    @SerializedName("initial_url")
    private String entryPoint;

    @SerializedName("user_agent")
    private String userAgent;

    @SerializedName("qs_parameters")
    private String qsParameters;

    @SerializedName("auth")
    @Expose
    private MollyAuthConfig authConfig;

    @SerializedName("ignore_issues")
    @Expose
    private List<Integer> ignoredIssueIds;

    @SerializedName("crossdomain_js_whitelist")
    @Expose
    private List<String> crossdomainJsWhitelist;

    @SerializedName("crossdomain_xml_whitelist")
    @Expose
    private List<String> crossdomainXmlWhitelist;

    @SerializedName("public_cors_whitelist")
    @Expose
    private List<String> publicCorsWhitelist;

    @SerializedName("static_file_extensions")
    @Expose
    private List<String> staticFileExt;

    @SerializedName("proxy_domain_blacklist")
    @Expose
    private List<String> proxyDomainBlacklist;

    public URL getInitialURL() {
        return initialURL;
    }

    public void setInitialURL(URL initialURL) {
        this.initialURL = initialURL;
    }

    public void setEntryPoint(String entryPoint) {
        this.entryPoint = entryPoint;
    }

    public String getEntryPoint() {
        return entryPoint;
    }

    public int getScanTimeout() {
        return scanTimeout;
    }

    public void setScanTimeout(int scanTimeout) {
        this.scanTimeout = scanTimeout;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) { this.userAgent = userAgent;
    }

    public void setReportPath(String reportPath) {
        this.reportPath = reportPath;
    }

    public String getReportPath() {
        return reportPath;
    }

    public String getQsParameters() { return qsParameters; }

    public void setQsParameters(String qsParameter) {
        this.qsParameters = qsParameter;
    }

    public MollyAuthConfig getAuthConfig() {
        return authConfig;
    }

    public void setAuthConfig(MollyAuthConfig authConfig) {
        this.authConfig = authConfig;
    }

    public List<String> getCrossdomainJsWhitelist() {
        return crossdomainJsWhitelist;
    }

    public void setCrossdomainJsWhitelist(List<String> crossdomaiJsWhitelist) {
        this.crossdomainJsWhitelist = crossdomaiJsWhitelist;
    }

    public void setPublicCorsWhitelist(List<String> publicCorsWhitelist) {
        this.publicCorsWhitelist = publicCorsWhitelist;
    }

    public List<String> getStaticFileExt() {
        return staticFileExt;
    }

    public void setStaticFileExt(List<String> staticFileExt) {
        this.staticFileExt = staticFileExt;
    }

    public List<String> getPublicCorsWhitelist() {
        return publicCorsWhitelist;
    }

    public List<String> getCrossdomainXmlWhitelist() {
        return crossdomainXmlWhitelist;
    }

    public void setCrossdomainXmlWhitelist(List<String> crossdomainXmlWhitelist) {
        this.crossdomainXmlWhitelist = crossdomainXmlWhitelist;
    }

    public List<Integer> getIgnoredIssueIds() {
        return ignoredIssueIds;
    }

    public void setIgnoredIssueIds(List<Integer> ignoredIssueIds) {
        this.ignoredIssueIds = ignoredIssueIds;
    }

    public int getMaxUrls() {
        return maxUrls;
    }

    public int getMaxIssuesByType() {
        return maxIssuesByType;
    }

    public void setMaxIssuesByType(int maxIssuesByType) {
        this.maxIssuesByType = maxIssuesByType;
    }

    public void setMaxUrls(int maxUrl) {
        this.maxUrls = maxUrls;
    }

    public List<String> getProxyDomainBlacklist() { return proxyDomainBlacklist; }

    public void setProxyDomainBlacklist(List<String> proxyDomainBlacklist) {
        this.proxyDomainBlacklist = proxyDomainBlacklist;
    }
}
