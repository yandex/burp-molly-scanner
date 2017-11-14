package com.yandex.burp.extensions.config;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class MollyConfig {

    @SerializedName("burp-molly-pack")
    @Expose
    private BurpMollyPackConfig BurpMollyPackConfig;

    @SerializedName("burp-molly-scanner")
    @Expose
    private BurpMollyScannerConfig BurpActiveScannerConfig;

    public BurpMollyPackConfig getBurpMollyPackConfig() {
        return BurpMollyPackConfig;
    }

    public BurpMollyScannerConfig getBurpActiveScanner() {
        return BurpActiveScannerConfig;
    }

}