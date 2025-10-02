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
        Timber.d("Starting SSH agent");

        Socket socket = null;
        try {
            Timber.d("Connecting to proxy server");
            socket = new Socket("127.0.0.1", port);
            socket.setSoTimeout(30000); // 30 second timeout

            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();

            // Load SSH keys from storage
            AuthenticationKeyStorage authKeyStorage = new AuthenticationKeyStorage(this);
            List<AuthenticationKeyInfo> keys = authKeyStorage.loadSelectedKeys();
            Timber.d("Loaded %d SSH keys", keys.size());

            // Connect to SSH API
            Semaphore lock = new Semaphore(0);
            final boolean[] connRes = {false};

            try (SshApi api = new SshApi(this, (sshApi, res) -> {
                if (!res) {
                    Timber.e("SSH API connection failed");
                    Utils.showError(SshAgentService.this, R.string.error_connection_failed);
                }
                connRes[0] = res;
                lock.release();
            })) {
                api.connect();
                lock.acquire();

                if (!connRes[0]) {
                    Timber.e("SSH API connection failed");
                    return;
                }

                Timber.d("SSH API connected");
                ApiExecutor executeApi = api::executeApi;

                // Load all public keys BEFORE entering message loop (OkcAgent style)
                List<SshPublicKeyInfo> publicKeys = new ArrayList<>();
                for (int keyIndex = 0; keyIndex < keys.size(); keyIndex++) {
                    AuthenticationKeyInfo key = keys.get(keyIndex);
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
                                }
                            }
                        }
                    }
                }
                Timber.d("Loaded %d public keys", publicKeys.size());

                // Handle SSH agent protocol messages
                while (true) {
                    SshAgentMessage req = SshAgentMessage.readFromStream(input);
                    if (req == null) {
                        break;
                    }

                    Timber.d("Received SSH message type: %d", req.getType());
                    SshAgentMessage resMsg = null;
                    switch (req.getType()) {
                        case SshAgentMessage.SSH_AGENTC_REQUEST_IDENTITIES:
                            Timber.d("Request identities");
                            resMsg = new SshAgentMessage(
                                SshAgentMessage.SSH_AGENT_IDENTITIES_ANSWER,
                                new SshIdentitiesResponse(publicKeys).toBytes()
                            );
                            break;

                        case SshAgentMessage.SSH_AGENTC_SIGN_REQUEST:
                            Timber.d("Sign request");
                            SshSignRequest signReq = new SshSignRequest(req.getContents());

                            // Find matching key
                            int keyIndex = -1;
                            for (int i = 0; i < publicKeys.size(); i++) {
                                if (publicKeys.get(i).publicKeyEquals(signReq.getKeyBlob())) {
                                    keyIndex = i;
                                    break;
                                }
                            }

                            if (keyIndex >= 0 && keyIndex < keys.size()) {
                                String keyId = String.valueOf(keys.get(keyIndex).getKeyId());

                                // Convert SSH agent flags to hash algorithm
                                // SSH_AGENT_RSA_SHA2_256 = 0x02, SSH_AGENT_RSA_SHA2_512 = 0x04
                                int hashAlgorithm;
                                if ((signReq.getFlags() & 0x04) != 0) {
                                    hashAlgorithm = org.openintents.ssh.authentication.SshAuthenticationApi.SHA512;
                                } else if ((signReq.getFlags() & 0x02) != 0) {
                                    hashAlgorithm = org.openintents.ssh.authentication.SshAuthenticationApi.SHA256;
                                } else {
                                    hashAlgorithm = org.openintents.ssh.authentication.SshAuthenticationApi.SHA1;
                                }

                                Intent signIntent = callApi(
                                    executeApi,
                                    new SigningRequest(signReq.getData(), keyId, hashAlgorithm).toIntent(),
                                    port,
                                    null
                                );

                                if (signIntent != null) {
                                    byte[] signature = new SigningResponse(signIntent).getSignature();
                                    Timber.d("Signature generated");
                                    resMsg = new SshAgentMessage(
                                        SshAgentMessage.SSH_AGENT_SIGN_RESPONSE,
                                        new SshSignResponse(signature).toBytes()
                                    );
                                } else {
                                    Timber.e("Failed to get signature");
                                }
                            } else {
                                Timber.e("No matching key found");
                            }
                            break;

                        case SshAgentMessage.SSH_AGENTC_EXTENSION:
                            // Extensions are optional features - we don't support any
                            resMsg = new SshAgentMessage(SshAgentMessage.SSH_AGENT_EXTENSION_FAILURE, null);
                            break;

                        default:
                            Timber.w("Unsupported SSH message type: %d", req.getType());
                            break;
                    }

                    if (resMsg == null) {
                        resMsg = new SshAgentMessage(SshAgentMessage.SSH_AGENT_FAILURE, null);
                    }

                    resMsg.writeToStream(output);
                }
            }
        } catch (Exception e) {
            Timber.e(e, "SSH Agent error");
            try {
                if (socket != null) {
                    socket.setSoLinger(true, 0);
                }
            } catch (Exception e2) {
                Timber.w(e2, "Failed to set linger option");
                Utils.showError(this, e.toString());
            }
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (Exception e) {
                Timber.w(e, "Failed to close socket");
            }
            checkThreadExit(port);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Timber.d("SSH Agent service created");
    }

}