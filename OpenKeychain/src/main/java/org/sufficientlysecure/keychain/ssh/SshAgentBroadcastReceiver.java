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

        // SIMPLE: Just start the service as a regular background service
        if (proxyPort > 0) {
            Log.d("SSH_BROADCAST", "Starting SSH agent for port: " + proxyPort);

            Intent serviceIntent = new Intent(context, SshAgentService.class);
            serviceIntent.setAction(AgentService.ACTION_RUN_AGENT);
            serviceIntent.putExtra(AgentService.EXTRA_PROXY_PORT, proxyPort);

            // Just use regular startService - works for short background tasks
            context.startService(serviceIntent);
            Log.d("SSH_BROADCAST", "SSH agent service started for port: " + proxyPort);
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