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

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import org.openintents.ssh.authentication.ISshAuthenticationService;
import org.openintents.ssh.authentication.SshAuthenticationApi;
import org.openintents.ssh.authentication.SshAuthenticationConnection;

import java.io.Closeable;

/**
 * SSH API wrapper for connecting to OpenKeychain's SSH authentication service
 */
public class SshApi implements Closeable {
    private final Context context;
    private final ConnectCallback connectCallback;
    private SshAuthenticationConnection conn;
    private SshAuthenticationApi api;

    public interface ConnectCallback {
        void onResult(SshApi sshApi, boolean success);
    }

    public SshApi(Context context, ConnectCallback connectCallback) {
        this.context = context;
        this.connectCallback = connectCallback;
    }

    public void connect() {
        Log.d("SSH_API", "=== SSH API CONNECT START ===");
        String pkg = context.getPackageName();
        Log.d("SSH_API", "Package name: " + pkg);
        conn = new SshAuthenticationConnection(context, pkg);

        Log.d("SSH_API", "Attempting SSH authentication connection...");
        boolean connRes = conn.connect(new SshAuthenticationConnection.OnBound() {
            @Override
            public void onBound(ISshAuthenticationService service) {
                Log.d("SSH_API", "SSH authentication service bound successfully");
                api = new SshAuthenticationApi(context, service);
                Log.d("SSH_API", "SSH authentication API created");
                connectCallback.onResult(SshApi.this, true);
            }

            @Override
            public void onError() {
                Log.e("SSH_API", "SSH authentication service binding failed");
                connectCallback.onResult(SshApi.this, false);
            }
        });

        Log.d("SSH_API", "Initial connection result: " + connRes);
        if (!connRes) {
            Log.e("SSH_API", "Failed to initiate SSH authentication connection");
            connectCallback.onResult(this, false);
        }
        Log.d("SSH_API", "=== SSH API CONNECT END ===");
    }

    public Intent executeApi(Intent intent) {
        Log.d("SSH_API", "Executing API call: " + (intent != null ? intent.getAction() : "null intent"));
        if (api == null) {
            Log.e("SSH_API", "API is null, cannot execute");
            return null;
        }
        Intent result = api.executeApi(intent);
        Log.d("SSH_API", "API call completed, result: " + (result != null ? "success" : "null"));
        return result;
    }

    @Override
    public void close() {
        Log.d("SSH_API", "Closing SSH API connection");
        if (conn != null && conn.isConnected()) {
            Log.d("SSH_API", "Disconnecting SSH authentication connection");
            conn.disconnect();
            Log.d("SSH_API", "SSH authentication connection disconnected");
        } else {
            Log.d("SSH_API", "No active connection to close");
        }
    }
}