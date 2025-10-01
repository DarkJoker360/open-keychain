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

import android.content.Intent;
import android.util.Base64;

import org.openintents.ssh.authentication.SshAuthenticationApiError;
import org.openintents.ssh.authentication.request.SigningRequest;
import org.openintents.ssh.authentication.request.SshPublicKeyRequest;
import org.openintents.ssh.authentication.response.SigningResponse;
import org.openintents.ssh.authentication.response.SshPublicKeyResponse;
import org.sufficientlysecure.keychain.R;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;

import android.util.Log;
import timber.log.Timber;

/**
 * SSH Agent Service - ported from OkcAgent architecture
 */
public class SshAgentService extends AgentService {

    private static final String LOG_TAG = "SshAgentService";
    @Override
    public String getErrorMessage(Intent intent) {
        SshAuthenticationApiError error = intent.getParcelableExtra("org.openintents.ssh.authentication.EXTRA_ERROR");
        return error != null ? error.getMessage() : null;
    }

    @Override
    public void runAgent(int port, Intent intent) {
        Log.d("SSH_SERVICE", "=== STARTING SSH AGENT ===");
        Log.d("SSH_SERVICE", "Proxy port: " + port);
        Log.d("SSH_SERVICE", "Intent action: " + (intent != null ? intent.getAction() : "null"));

        Socket socket = null;
        try {
            Log.d("SSH_SERVICE", "Attempting to connect to proxy server at 127.0.0.1:" + port);
            socket = new Socket("127.0.0.1", port);
            Log.d("SSH_SERVICE", "Socket connected successfully to " + socket.getRemoteSocketAddress());

            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();
            Log.d("SSH_SERVICE", "Input/Output streams obtained");

            // Load SSH keys from storage
            Log.d("SSH_SERVICE", "Loading SSH keys from storage");
            AuthenticationKeyStorage authKeyStorage = new AuthenticationKeyStorage(this);
            List<AuthenticationKeyInfo> keys = authKeyStorage.loadSelectedKeys();
            Log.d("SSH_SERVICE", "Loaded " + keys.size() + " SSH keys");

            // Connect to SSH API
            Semaphore lock = new Semaphore(0);
            final boolean[] connRes = {false};

            Log.d("SSH_SERVICE", "Creating SSH API connection");
            try (SshApi api = new SshApi(this, (sshApi, res) -> {
                Log.d("SSH_SERVICE", "SSH API connection result: " + res);
                if (!res) {
                    Log.e("SSH_SERVICE", "SSH API connection failed");
                    Utils.showError(SshAgentService.this, R.string.error_connection_failed);
                }
                connRes[0] = res;
                lock.release();
            })) {
                Log.d("SSH_SERVICE", "Connecting to SSH API...");
                api.connect();
                Log.d("SSH_SERVICE", "Waiting for SSH API connection...");
                lock.acquire();
                Log.d("SSH_SERVICE", "SSH API connection completed with result: " + connRes[0]);

                if (!connRes[0]) {
                    Log.e("SSH_SERVICE", "SSH API connection failed, aborting");
                    return;
                }

                Log.d("SSH_SERVICE", "SSH API connected successfully");
                ApiExecutor executeApi = api::executeApi;

                // Load all public keys BEFORE entering message loop (OkcAgent style)
                List<SshPublicKeyInfo> publicKeys = new ArrayList<>();
                Log.d("SSH_SERVICE", "Loading public keys for " + keys.size() + " authentication keys");
                for (int keyIndex = 0; keyIndex < keys.size(); keyIndex++) {
                    AuthenticationKeyInfo key = keys.get(keyIndex);
                    Log.d("SSH_SERVICE", "Processing key " + keyIndex + ": " + key.getName() + " (ID: " + key.getKeyId() + ")");
                    if (key.isGpgKey()) {
                        Intent requestIntent = new SshPublicKeyRequest(String.valueOf(key.getKeyId())).toIntent();
                        Intent resIntent = callApi(executeApi, requestIntent, port, null);

                        if (resIntent != null) {
                            SshPublicKeyResponse response = new SshPublicKeyResponse(resIntent);
                            String pubKeyStr = response.getSshPublicKey();

                            if (pubKeyStr != null && !pubKeyStr.isEmpty()) {
                                String[] parts = pubKeyStr.split(" ");
                                if (parts.length >= 2) {
                                    byte[] keyData = Base64.decode(parts[1], Base64.DEFAULT);
                                    String description = key.getName();
                                    SshPublicKeyInfo info = new SshPublicKeyInfo(
                                        keyData,
                                        description.getBytes(StandardCharsets.UTF_8)
                                    );
                                    publicKeys.add(info);
                                    Log.d("SSH_SERVICE", "Added SSH public key " + keyIndex + " (" + keyData.length + " bytes)");
                                }
                            }
                        }
                    }
                }
                Log.d("SSH_SERVICE", "Finished loading " + publicKeys.size() + " public keys");

                // Handle SSH agent protocol messages
                Log.d("SSH_SERVICE", "Starting SSH agent protocol message loop");
                int messageCount = 0;
                while (true) {
                    Log.d("SSH_SERVICE", "Waiting for SSH agent message " + (++messageCount) + "...");
                    SshAgentMessage req = SshAgentMessage.readFromStream(input);
                    if (req == null) {
                        Log.d("SSH_SERVICE", "Received null message, ending message loop");
                        break;
                    }

                    Log.d("SSH_SERVICE", "Received SSH agent message " + messageCount + ", type: " + req.getType() + " (0x" + Integer.toHexString(req.getType()) + ")");
                    if (req.getContents() != null) {
                        Log.d("SSH_SERVICE", "Message has " + req.getContents().length + " bytes of content");
                    } else {
                        Log.d("SSH_SERVICE", "Message has no content");
                    }
                    SshAgentMessage resMsg = null;
                    switch (req.getType()) {
                        case SshAgentMessage.SSH_AGENTC_REQUEST_IDENTITIES:
                            Log.d("SSH_SERVICE", "Processing SSH_AGENTC_REQUEST_IDENTITIES");
                            Log.d("SSH_SERVICE", "Returning " + publicKeys.size() + " identities");
                            resMsg = new SshAgentMessage(
                                SshAgentMessage.SSH_AGENT_IDENTITIES_ANSWER,
                                new SshIdentitiesResponse(publicKeys).toBytes()
                            );
                            Log.d("SSH_SERVICE", "SSH_AGENT_IDENTITIES_ANSWER message created");
                            break;

                        case SshAgentMessage.SSH_AGENTC_SIGN_REQUEST:
                            Log.d("SSH_SERVICE", "Processing SSH_AGENTC_SIGN_REQUEST");
                            SshSignRequest signReq = new SshSignRequest(req.getContents());
                            Log.d("SSH_SERVICE", "Sign request - key blob length: " + signReq.getKeyBlob().length + ", data length: " + signReq.getData().length + ", flags: " + signReq.getFlags());

                            // Find matching key
                            int keyIndex = -1;
                            for (int i = 0; i < publicKeys.size(); i++) {
                                if (publicKeys.get(i).publicKeyEquals(signReq.getKeyBlob())) {
                                    keyIndex = i;
                                    Log.d("SSH_SERVICE", "Found matching key at index " + i);
                                    break;
                                }
                            }

                            if (keyIndex >= 0 && keyIndex < keys.size()) {
                                String keyId = String.valueOf(keys.get(keyIndex).getKeyId());
                                Log.d("SSH_SERVICE", "Requesting signature for key ID: " + keyId);

                                // Convert SSH agent flags to hash algorithm
                                // SSH_AGENT_RSA_SHA2_256 = 0x02, SSH_AGENT_RSA_SHA2_512 = 0x04
                                int hashAlgorithm;
                                if ((signReq.getFlags() & 0x04) != 0) {
                                    hashAlgorithm = org.openintents.ssh.authentication.SshAuthenticationApi.SHA512;
                                    Log.d("SSH_SERVICE", "Using SHA512 hash algorithm from flags");
                                } else if ((signReq.getFlags() & 0x02) != 0) {
                                    hashAlgorithm = org.openintents.ssh.authentication.SshAuthenticationApi.SHA256;
                                    Log.d("SSH_SERVICE", "Using SHA256 hash algorithm from flags");
                                } else {
                                    // Default to SHA1 for RSA, or SHA256 for ECDSA/EdDSA
                                    hashAlgorithm = org.openintents.ssh.authentication.SshAuthenticationApi.SHA1;
                                    Log.d("SSH_SERVICE", "Using default SHA1 hash algorithm");
                                }

                                Intent signIntent = callApi(
                                    executeApi,
                                    new SigningRequest(signReq.getData(), keyId, hashAlgorithm).toIntent(),
                                    port,
                                    null
                                );

                                if (signIntent != null) {
                                    byte[] signature = new SigningResponse(signIntent).getSignature();
                                    Log.d("SSH_SERVICE", "Got signature response (" + signature.length + " bytes)");
                                    resMsg = new SshAgentMessage(
                                        SshAgentMessage.SSH_AGENT_SIGN_RESPONSE,
                                        new SshSignResponse(signature).toBytes()
                                    );
                                    Log.d("SSH_SERVICE", "SSH_AGENT_SIGN_RESPONSE message created");
                                } else {
                                    Log.e("SSH_SERVICE", "Failed to get signature from SSH API");
                                }
                            } else {
                                Log.e("SSH_SERVICE", "No matching key found for sign request (keyIndex: " + keyIndex + ", total keys: " + keys.size() + ")");
                            }
                            break;

                        default:
                            Log.w("SSH_SERVICE", "Unsupported SSH agent message type: " + req.getType() + " (0x" + Integer.toHexString(req.getType()) + ")");
                            Log.w("SSH_SERVICE", "This is likely an SSH extension request (type 27) or other unsupported feature");
                            // Will send SSH_AGENT_FAILURE below
                            break;
                    }

                    if (resMsg == null) {
                        Log.w("SSH_SERVICE", "No response message created, sending SSH_AGENT_FAILURE");
                        resMsg = new SshAgentMessage(SshAgentMessage.SSH_AGENT_FAILURE, null);
                    }

                    Log.d("SSH_SERVICE", "Sending response message type: " + resMsg.getType());
                    resMsg.writeToStream(output);
                    Log.d("SSH_SERVICE", "Response message sent successfully");
                }
            }
        } catch (Exception e) {
            Log.e("SSH_SERVICE", "SSH Agent error: " + e.getMessage(), e);
            Timber.e(e, "SSH Agent error");
            try {
                if (socket != null) {
                    socket.setSoLinger(true, 0);
                    Log.d("SSH_SERVICE", "Socket linger option set");
                }
            } catch (Exception e2) {
                Log.e("SSH_SERVICE", "Failed to set linger option: " + e2.getMessage(), e2);
                Timber.w(e2, "Failed to set linger option on exception");
                Utils.showError(this, e.toString());
            }
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                    Log.d("SSH_SERVICE", "Socket closed");
                }
            } catch (Exception e) {
                Log.e("SSH_SERVICE", "Failed to close socket: " + e.getMessage(), e);
                Timber.w(e, "Failed to close socket on exit");
            }
            Log.d("SSH_SERVICE", "Checking thread exit for port " + port);
            checkThreadExit(port);
            Log.d("SSH_SERVICE", "=== SSH AGENT FINISHED ===");
        }
    }

    @Override
    public void onCreate() {
        Log.d("SSH_SERVICE", "=== SSH AGENT SERVICE CREATING ===");
        super.onCreate();
        // CRITICAL: OkcAgent calls startForeground immediately in onCreate
        // This MUST happen here, not in onStartCommand, to comply with Android 8+ requirements
        startForeground(
            R.string.notification_ssh_title,
            R.string.notification_ssh_content,
            R.integer.notification_id_ssh
        );
        Log.d("SSH_SERVICE", "=== SSH AGENT SERVICE CREATED ===");
    }

}