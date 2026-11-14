package com.kotsafe.security.model;

import android.content.Context;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SharedLinkCheck {
    public enum Result { MATCH, UNKNOWN, UNAVAILABLE }
    private static final Pattern URL = Pattern.compile("(?i)\\bhttps?://[^\\s<>\"]+");

    private SharedLinkCheck() {}

    public static String extract(CharSequence text) throws IOException {
        if (text == null || text.length() > 16384) throw new IOException();
        Matcher matcher = URL.matcher(text);
        if (!matcher.find()) throw new IOException();
        String link = matcher.group();
        // Messaging apps commonly wrap a shared link in parentheses.
        if (matcher.start() > 0 && text.charAt(matcher.start()-1) == '(' && link.endsWith(")")) {
            link = link.substring(0, link.length()-1);
        }
        if (matcher.find()) throw new IOException();
        int fragment = link.indexOf('#');
        return IntelligenceManifestV2Verifier.normalize("url", fragment < 0 ? link : link.substring(0, fragment));
    }

    public static Result check(Context context, String url) throws IOException {
        if (!SignedFeedWorker.enabled(context)) return Result.UNAVAILABLE;
        String account = SignedFeedWorker.account();
        String generation = SignedFeedWorker.state(context).getString("generation", "");
        IntelligenceSnapshotStore store = SignedFeedWorker.store(context, account);
        long now = System.currentTimeMillis() / 1000;
        if (!store.restore(now) || store.lastVersion() != SignedFeedWorker.state(context).getLong("version", 0))
            return Result.UNAVAILABLE;
        Result result = match(url, store.active(now));
        if (!SignedFeedWorker.enabled(context) || !account.equals(SignedFeedWorker.account()) ||
                !generation.equals(SignedFeedWorker.state(context).getString("generation", "")) ||
                store.lastVersion() != SignedFeedWorker.state(context).getLong("version", 0))
            return Result.UNAVAILABLE;
        return result;
    }

    static Result match(String url, List<IntelligenceManifestV2Verifier.Indicator> indicators) throws IOException {
        String host = URI.create(url).getHost();
        if (host.startsWith("[")) host = host.substring(1, host.length()-1);
        String ip = null;
        if (host.indexOf(':') >= 0 || host.matches("[0-9.]+"))
            ip = IntelligenceManifestV2Verifier.normalize("ip",host);
        boolean hasCoverage = false;
        for (IntelligenceManifestV2Verifier.Indicator row : indicators) {
            if (row.type.equals("url")) {
                hasCoverage = true;
                if (url.equals(row.value)) return Result.MATCH;
            } else if (ip == null && row.type.equals("domain")) {
                hasCoverage = true;
                if (host.equals(row.value)) return Result.MATCH;
            } else if (ip != null && row.type.equals("ip")) {
                hasCoverage = true;
                if (ip.equals(row.value)) return Result.MATCH;
            }
        }
        return hasCoverage ? Result.UNKNOWN : Result.UNAVAILABLE;
    }
}
