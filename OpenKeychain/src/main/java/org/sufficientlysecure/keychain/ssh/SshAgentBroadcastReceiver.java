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
import android.util.Log;
import timber.log.Timber;

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

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d("SSH_BROADCAST", "=== BROADCAST RECEIVED ===");
        Log.d("SSH_BROADCAST", "Action: " + (intent.getAction() != null ? intent.getAction() : "null"));
        Log.d("SSH_BROADCAST", "Package: " + context.getPackageName());

        // Handle the request directly - when using component-based broadcast (-n flag),
        // the action may be null, which is fine since we're targeting this receiver directly
        Log.d("SSH_BROADCAST", "Handling SSH agent request");
        handleAgentRequest(context, intent);
    }

    private void handleAgentRequest(Context context, Intent request) {
        Log.d("SSH_BROADCAST", "=== HANDLING SSH AGENT REQUEST ===");
        Timber.d("SSH Agent request received");

        // Extract protocol version and port from OkcAgent-style request
        int clientProto = request.getIntExtra(EXTRA_SSH_PROTO_VER, -999);
        int proxyPort = request.getIntExtra(EXTRA_PROXY_PORT, -999);

        Log.d("SSH_BROADCAST", "Client protocol version: " + clientProto);
        Log.d("SSH_BROADCAST", "Proxy port: " + proxyPort);
        Log.d("SSH_BROADCAST", "Intent extras: " + request.getExtras());

        // Check protocol version compatibility
        final int PROTO_VER = 0;
        if (clientProto != PROTO_VER) {
            String errorMsg = "Incompatible SSH protocol version. Client: " + clientProto + ", Server: " + PROTO_VER;
            Log.e("SSH_BROADCAST", errorMsg);
            Utils.showError(context, errorMsg);
            return;
        }

        Log.d("SSH_BROADCAST", "Protocol version compatible");

        // Start SSH agent service to connect to the proxy port
        if (proxyPort > 0) {
            Log.d("SSH_BROADCAST", "Creating SSH agent service intent");
            Intent serviceIntent = new Intent(context, SshAgentService.class);
            serviceIntent.setAction(AgentService.ACTION_RUN_AGENT);
            serviceIntent.putExtra(AgentService.EXTRA_PROXY_PORT, proxyPort);

            Log.d("SSH_BROADCAST", "Service intent created with action: " + AgentService.ACTION_RUN_AGENT);
            Log.d("SSH_BROADCAST", "Service intent proxy port: " + proxyPort);

            try {
                Log.d("SSH_BROADCAST", "Starting SSH agent service...");

                // On Android 12+ (API 31+), there are strict limitations on starting foreground services
                // from background. The service can only be started if:
                // 1. App is in foreground
                // 2. App has a visible notification
                // 3. Service is already running
                // Since we're receiving a broadcast, we're likely in background
                if (android.os.Build.VERSION.SDK_INT >= 31) {
                    // Android 12+ - Try to start the service, but be prepared for failure
                    try {
                        context.startForegroundService(serviceIntent);
                        Log.d("SSH_BROADCAST", "SSH agent service started (foreground) for port: " + proxyPort);
                    } catch (Exception fgException) {
                        // This is expected on Android 12+ when app is in background
                        Log.w("SSH_BROADCAST", "Cannot start foreground service from background (Android 12+), trying regular start");
                        try {
                            // Try regular start - this might work if service is already running
                            context.startService(serviceIntent);
                            Log.d("SSH_BROADCAST", "SSH agent service started (regular) for port: " + proxyPort);
                        } catch (Exception regException) {
                            Log.e("SSH_BROADCAST", "Both foreground and regular start failed: " + regException.getMessage());
                            // Last resort: Show notification to user
                            Utils.showError(context, "Please open OpenKeychain first, then retry SSH");
                            return;
                        }
                    }
                } else if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    // Android 8.0-11 - Can use startForegroundService normally
                    context.startForegroundService(serviceIntent);
                    Log.d("SSH_BROADCAST", "SSH agent service started successfully for proxy port: " + proxyPort);
                } else {
                    // Android 7.1 and below
                    context.startService(serviceIntent);
                    Log.d("SSH_BROADCAST", "SSH agent service started successfully for proxy port: " + proxyPort);
                }

                Timber.d("Started SSH agent service for proxy port: %d", proxyPort);
            } catch (Exception e) {
                Log.e("SSH_BROADCAST", "Failed to start SSH agent service: " + e.getMessage(), e);
                Timber.e(e, "Failed to start SSH agent service");
                Utils.showError(context, "Failed to start SSH agent: " + e.getMessage());
            }
        } else {
            Log.w("SSH_BROADCAST", "Invalid proxy port provided: " + proxyPort);
            Timber.w("No valid proxy port provided in SSH agent request");
        }

        Log.d("SSH_BROADCAST", "=== SSH AGENT REQUEST HANDLING COMPLETE ===");
    }

    /**
     * Helper method for external tools to request SSH agent info
     */
    public static void requestAgentInfo(Context context) {
        Intent request = new Intent(ACTION_SSH_AGENT_REQUEST);
        context.sendBroadcast(request);
    }
}