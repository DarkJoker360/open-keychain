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
        if (ACTION_SSH_AGENT_REQUEST.equals(intent.getAction())) {
            handleAgentRequest(context, intent);
        }
    }

    private void handleAgentRequest(Context context, Intent request) {
        Timber.d("SSH Agent request received");

        AuthenticationKeyStorage authKeyStorage = new AuthenticationKeyStorage(context);
        boolean isEnabled = authKeyStorage.isSshAgentEnabled();
        int port = authKeyStorage.getSshAgentPort();

        // Create response intent
        Intent response = new Intent(ACTION_SSH_AGENT_RESPONSE);
        response.putExtra(EXTRA_ENABLED, isEnabled);
        response.putExtra(EXTRA_PACKAGE_NAME, context.getPackageName());

        if (isEnabled && port > 0) {
            response.putExtra(EXTRA_PORT, port);
            Timber.d("SSH Agent response: enabled=%s, port=%d", isEnabled, port);
        } else {
            Timber.d("SSH Agent response: enabled=%s, no port available", isEnabled);
        }

        // Send broadcast response
        context.sendBroadcast(response);
    }

    /**
     * Helper method for external tools to request SSH agent info
     */
    public static void requestAgentInfo(Context context) {
        Intent request = new Intent(ACTION_SSH_AGENT_REQUEST);
        context.sendBroadcast(request);
    }
}