package com.yandex.burp.extensions;

import burp.*;
import com.google.common.base.Splitter;
import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import deduper.*;

import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.util.List;

/**
 * Created by ezaitov on 20.02.2017.
 */
public class EntryPointDeduplicator {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private BKTree<Long> dubTree;
    private BloomFilter<String> dubBloomFilter;

    public EntryPointDeduplicator(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.dubBloomFilter = BloomFilter.create(Funnels.stringFunnel(Charset.defaultCharset()), 1000);
        this.dubTree = new BKTree<>(new HammingDistance());
    }

    public boolean isFullDuplicate(IHttpRequestResponse messageInfo) {
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        IResponseInfo respInfo = helpers.analyzeResponse(messageInfo.getResponse());

        if (dubBloomFilter == null) return false;

        HashFunction m_hash = Hashing.murmur3_32();
        if (helpers.bytesToString(messageInfo.getResponse()).length() > respInfo.getBodyOffset()) {
            String body = helpers.bytesToString(messageInfo.getResponse()).substring(respInfo.getBodyOffset());

            /* full-dub detection */
            String dedupHashValue = m_hash.hashBytes(helpers.stringToBytes(body)).toString();
            if (dubBloomFilter.mightContain(dedupHashValue)) {
                return true;
            }
            dubBloomFilter.put(dedupHashValue);
        }

        return false;
    }

    public boolean isDuplicateURL(IHttpRequestResponse messageInfo) {
        if (dubBloomFilter == null) return false;

        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
        if (requestInfo == null) return true;

        HashFunction m_hash = Hashing.murmur3_32();
        /* don't know if Burp has a deduplication here, make it sure */
        String hashInput = requestInfo.getUrl().getPath() + "?";
        if (requestInfo.getUrl().getQuery() != null && requestInfo.getUrl().getQuery().length() > 0) {
            List<String> qsList = Splitter.on('&').trimResults().splitToList(requestInfo.getUrl().getQuery());
            if (qsList.size() > 0) {
                for (String param : qsList) {
                    for (String k : Splitter.on("=").splitToList(param)) {
                        hashInput += "&" + k;
                    }
                }
            }
        }

        String dedupHashValue = "URL:" + requestInfo.getMethod() + m_hash.hashBytes(helpers.stringToBytes(hashInput)).toString();
        if (dubBloomFilter.mightContain(dedupHashValue)) {
            return true;
        }
        dubBloomFilter.put(dedupHashValue);
        return false;
    }

    public boolean isHalfDuplicate(IHttpRequestResponse messageInfo) {
        /* half-dub detection */
        if (dubTree == null) return false;

        IResponseInfo respInfo = helpers.analyzeResponse(messageInfo.getResponse());
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());

        if (helpers.bytesToString(messageInfo.getResponse()).length() > respInfo.getBodyOffset()) {
            String body = helpers.bytesToString(messageInfo.getResponse()).substring(respInfo.getBodyOffset());

            Simhash simHash;
            if (respInfo.getHeaders().stream().filter(c -> c.toUpperCase()
                    .contains("HTML")).findFirst().isPresent()) {
                simHash = new Simhash(new HtmlSeg());
            } else {
                simHash = new Simhash(new BinaryWordSeg());
            }
            long docHash = simHash.simhash64(body);
            if (dubTree.isEmpty()) {
                dubTree.add(docHash);
            } else {
                if (dubTree.find(docHash) <= 3) {
                    return true;
                }
                dubTree.add(docHash);
            }
        } else {
            /* responses with no body will not be sent to active scan */
            /* XXX! this can be bad idea */
            return true;
        }
        return false;
    }
}
