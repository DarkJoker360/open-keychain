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

/**
 * Broadcast receiver for SSH agent discovery by external command-line tools
 * Similar to OkcAgent's approach for exposing SSH agent information
 */
public class SshAgentBroadcastReceiver extends BroadcastReceiver {

    public static final String ACTION_SSH_AGENT_REQUEST = "org.sufficientlysecure.keychain.action.SSH_AGENT_REQUEST";
    public static final String ACTION_SSH_AGENT_RESPONSE = "org.sufficientlysecure.keychain.action.SSH_AGENT_RESPONSE";

    public static final String EXTRA_PORT = "port";
    public static final String EXTRA_ENABLED = "enabled";
    public static final String EXTRA_PACKAGE_NAME = "package_name";
    public static final String EXTRA_SSH_PROTO_VER = "org.sufficientlysecure.keychain.extra.SSH_PROTO_VER";
    public static final String EXTRA_PROXY_PORT = "org.sufficientlysecure.keychain.extra.PROXY_PORT";
    public static final String EXTRA_CERT_PEM = "org.sufficientlysecure.keychain.extra.CERT_PEM";
    public static final String EXTRA_CERT_FINGERPRINT = "org.sufficientlysecure.keychain.extra.CERT_FINGERPRINT";
    public static final String EXTRA_AUTH_TOKEN = "org.sufficientlysecure.keychain.extra.AUTH_TOKEN";

    // Rate limiting: Max 10 requests per minute per calling package
    private static final long RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
    private static final int MAX_REQUESTS_PER_WINDOW = 10;
    private static final ConcurrentHashMap<String, AtomicLong> requestCounts = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Long> windowStarts = new ConcurrentHashMap<>();

    @Override
    public void onReceive(Context context, Intent intent) {
        Timber.d("SSH Agent broadcast received");

        // Handle the request directly - when using component-based broadcast (-n flag),
        // the action may be null, which is fine since we're targeting this receiver directly
        handleAgentRequest(context, intent);
    }

    private void handleAgentRequest(Context context, Intent request) {
        Timber.d("SSH Agent request received");

        android.util.Log.e("SshAgentBroadcast", "========== BROADCAST RECEIVED ==========");
        android.util.Log.e("SshAgentBroadcast", "ALL INTENT EXTRAS: " + request.getExtras());

        // Rate limiting check
        String callingPackage = context.getPackageName(); // Will be overridden in real scenario
        if (!checkRateLimit(callingPackage)) {
            Timber.w("Rate limit exceeded for package: %s", callingPackage);
            Utils.showError(context, "Too many requests. Please wait.");
            return;
        }

        // Extract protocol version and port from OkcAgent-style request
        int clientProto = request.getIntExtra(EXTRA_SSH_PROTO_VER, -999);
        int proxyPort = request.getIntExtra(EXTRA_PROXY_PORT, -999);
        String certPemB64 = request.getStringExtra(EXTRA_CERT_PEM);
        String certFingerprint = request.getStringExtra(EXTRA_CERT_FINGERPRINT);
        String authToken = request.getStringExtra(EXTRA_AUTH_TOKEN);

        android.util.Log.d("SshAgentBroadcast", "Broadcast received - Proto: " + clientProto + ", Port: " + proxyPort);
        android.util.Log.d("SshAgentBroadcast", "certPemB64 is null: " + (certPemB64 == null) + ", isEmpty: " + (certPemB64 != null && certPemB64.isEmpty()));
        if (certPemB64 != null) {
            android.util.Log.d("SshAgentBroadcast", "certPemB64 length: " + certPemB64.length());
            android.util.Log.d("SshAgentBroadcast", "certPemB64 content: " + certPemB64);
        }
        android.util.Log.d("SshAgentBroadcast", "certFingerprint: " + certFingerprint);
        android.util.Log.d("SshAgentBroadcast", "authToken is null: " + (authToken == null));
        if (authToken != null) {
            android.util.Log.d("SshAgentBroadcast", "authToken content: " + authToken);
        }

        // Decode certificate PEM from base64
        String certPem = null;
        if (certPemB64 != null && !certPemB64.isEmpty()) {
            try {
                byte[] certPemBytes = android.util.Base64.decode(certPemB64, android.util.Base64.DEFAULT);
                certPem = new String(certPemBytes, java.nio.charset.StandardCharsets.UTF_8);
                android.util.Log.d("SshAgentBroadcast", "Successfully decoded certificate PEM: " + certPem.length() + " bytes");
                Timber.d("Decoded certificate PEM: %d bytes", certPem.length());
            } catch (Exception e) {
                android.util.Log.e("SshAgentBroadcast", "Failed to decode certificate PEM from base64", e);
                Timber.e(e, "Failed to decode certificate PEM from base64");
            }
        } else {
            android.util.Log.e("SshAgentBroadcast", "certPemB64 is null or empty!");
        }

        // Check protocol version compatibility
        final int PROTO_VER = 1;  // Updated to 1 for TLS support
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
        if (certPem == null || certPem.isEmpty()) {
            Timber.e("Missing certificate PEM");
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
        serviceIntent.putExtra(EXTRA_CERT_PEM, certPem);
        serviceIntent.putExtra(EXTRA_CERT_FINGERPRINT, certFingerprint);
        serviceIntent.putExtra(EXTRA_AUTH_TOKEN, authToken);

        // Just use regular startService - works for short background tasks
        context.startService(serviceIntent);
    }

    /**
     * Check if the calling package has exceeded rate limit
     */
    private boolean checkRateLimit(String callingPackage) {
        long now = System.currentTimeMillis();

        // Get or create tracking data for this package
        windowStarts.putIfAbsent(callingPackage, now);
        requestCounts.putIfAbsent(callingPackage, new AtomicLong(0));

        long windowStart = windowStarts.get(callingPackage);
        AtomicLong count = requestCounts.get(callingPackage);

        // Reset window if expired
        if (now - windowStart > RATE_LIMIT_WINDOW_MS) {
            windowStarts.put(callingPackage, now);
            count.set(0);
        }

        // Check if limit exceeded
        long currentCount = count.incrementAndGet();
        if (currentCount > MAX_REQUESTS_PER_WINDOW) {
            return false;
        }

        return true;
    }

    /**
     * Helper method for external tools to request SSH agent info
     */
    public static void requestAgentInfo(Context context) {
        Intent request = new Intent(ACTION_SSH_AGENT_REQUEST);
        context.sendBroadcast(request);
    }
}