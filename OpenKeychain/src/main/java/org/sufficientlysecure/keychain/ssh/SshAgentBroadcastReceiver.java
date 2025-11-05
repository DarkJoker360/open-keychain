/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.ssh;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import timber.log.Timber;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class SshAgentBroadcastReceiver extends BroadcastReceiver {

    public static final String EXTRA_SSH_PROTO_VER = "org.sufficientlysecure.keychain.extra.SSH_PROTO_VER";
    public static final String EXTRA_PROXY_PORT = "org.sufficientlysecure.keychain.extra.PROXY_PORT";
    public static final String EXTRA_CERT_DER_HEX = "org.sufficientlysecure.keychain.extra.CERT_DER_HEX";
    public static final String EXTRA_CERT_DER = "org.sufficientlysecure.keychain.extra.CERT_DER";
    public static final String EXTRA_CERT_FINGERPRINT = "org.sufficientlysecure.keychain.extra.CERT_FINGERPRINT";
    public static final String EXTRA_AUTH_TOKEN = "org.sufficientlysecure.keychain.extra.AUTH_TOKEN";

    private static final long RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
    private static final int MAX_REQUESTS_PER_WINDOW = 10;
    private static final ConcurrentHashMap<String, AtomicLong> requestCounts = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Long> windowStarts = new ConcurrentHashMap<>();

    @Override
    public void onReceive(Context context, Intent intent) {
        Timber.d("SSH Agent broadcast received");

        handleAgentRequest(context, intent);
    }

    private void handleAgentRequest(Context context, Intent request) {
        Timber.d("SSH Agent request received");

        if (!checkRateLimit()) {
            Timber.w("Rate limit exceeded");
            Utils.showError(context, "Too many requests. Please wait.");
            return;
        }

        int clientProto = request.getIntExtra(EXTRA_SSH_PROTO_VER, -999);
        int proxyPort = request.getIntExtra(EXTRA_PROXY_PORT, -999);
        String certDerHex = request.getStringExtra(EXTRA_CERT_DER_HEX);
        String certFingerprint = request.getStringExtra(EXTRA_CERT_FINGERPRINT);
        String authToken = request.getStringExtra(EXTRA_AUTH_TOKEN);

        // Decode certificate DER from hex
        byte[] certDer = null;
        if (certDerHex != null && !certDerHex.isEmpty()) {
            try {
                certDer = Utils.hexStringToByteArray(certDerHex);
                Timber.d("Decoded certificate DER: %d bytes", certDer.length);
            } catch (Exception e) {
                Timber.e(e, "Failed to decode certificate DER from hex");
            }
        } else {
            Timber.e("Certificate is null or empty!");
        }

        // Check protocol version compatibility
        final int PROTO_VER = 1;
        if (clientProto != PROTO_VER) {
            String errorMsg = "Incompatible SSH protocol version. Client: " + clientProto + ", Server: " + PROTO_VER;
            Timber.e(errorMsg);
            Utils.showError(context, errorMsg);
            return;
        }

        Timber.d("Protocol version compatible");

        // Validate port number (must be in valid range)
        if (proxyPort < 1024 || proxyPort > 65535) {
            Timber.w("Invalid proxy port: %d (must be 1024-65535)", proxyPort);
            Utils.showError(context, "Invalid proxy port");
            return;
        }

        // Validate TLS credentials
        if (certDer == null || certDer.length == 0) {
            Timber.e("Missing certificate DER");
            Utils.showError(context, "Missing certificate");
            return;
        }

        if (certFingerprint == null || certFingerprint.isEmpty()) {
            Timber.e("Missing certificate fingerprint");
            Utils.showError(context, "Missing certificate fingerprint");
            return;
        }

        if (authToken == null || authToken.isEmpty()) {
            Timber.e("Missing authentication token");
            Utils.showError(context, "Missing authentication token");
            return;
        }

        Timber.d("Starting SSH agent for port: %d with TLS", proxyPort);

        Intent serviceIntent = new Intent(context, SshAgentService.class);
        serviceIntent.setAction(AgentService.ACTION_RUN_AGENT);
        serviceIntent.putExtra(AgentService.EXTRA_PROXY_PORT, proxyPort);
        serviceIntent.putExtra(EXTRA_CERT_DER, certDer);
        serviceIntent.putExtra(EXTRA_CERT_FINGERPRINT, certFingerprint);
        serviceIntent.putExtra(EXTRA_AUTH_TOKEN, authToken);

        context.startService(serviceIntent);
    }

    /**
     * Check if rate limit has been exceeded
     * Uses a simple global rate limit to prevent DoS attacks
     */
    private boolean checkRateLimit() {
        long now = System.currentTimeMillis();
        // TODO: make more robust
        windowStarts.putIfAbsent("unknown_caller", now);
        requestCounts.putIfAbsent("unknown_caller", new AtomicLong(0));

        long windowStart = windowStarts.get("unknown_caller");
        AtomicLong count = requestCounts.get("unknown_caller");

        // Reset window if expired
        if (now - windowStart > RATE_LIMIT_WINDOW_MS) {
            windowStarts.put("unknown_caller", now);
            assert count != null;
            count.set(0);
        }

        // Check if limit exceeded
        assert count != null;
        long currentCount = count.incrementAndGet();
        return currentCount <= MAX_REQUESTS_PER_WINDOW;
    }
}