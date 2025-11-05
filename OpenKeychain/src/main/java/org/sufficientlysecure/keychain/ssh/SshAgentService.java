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
import org.openintents.ssh.authentication.response.SigningResponse;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.pgp.CanonicalizedPublicKey;
import org.sufficientlysecure.keychain.pgp.SshPublicKey;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import timber.log.Timber;

public class SshAgentService extends AgentService {

    // Connection configuration
    private static final int MAX_CONNECTION_RETRIES = 5;
    private static final long CONNECTION_RETRY_INITIAL_DELAY_MS = 100;
    private static final int SOCKET_TIMEOUT_MS = 30000; // 30 seconds

    @Override
    public String getErrorMessage(Intent intent) {
        SshAuthenticationApiError error = intent.getParcelableExtra("org.openintents.ssh.authentication.EXTRA_ERROR");
        return error != null ? error.getMessage() : null;
    }

    /**
     * Create a TLS socket with certificate pinning
     */
    private SSLSocket createTlsSocket(byte[] certDer, String expectedFingerprint, int port) throws Exception {
        Timber.d("Creating TLS socket with certificate pinning");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certDer));

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        certDer = cert.getEncoded();
        byte[] hash = digest.digest(certDer);
        StringBuilder fingerprintBuilder = new StringBuilder("sha256:");
        for (byte b : hash) {
            fingerprintBuilder.append(String.format("%02x", b));
        }
        String actualFingerprint = fingerprintBuilder.toString();
        Timber.d("Expected fingerprint: %s", expectedFingerprint);
        Timber.d("Actual fingerprint: %s", actualFingerprint);

        if (!actualFingerprint.equals(expectedFingerprint)) {
            throw new SecurityException("Certificate fingerprint mismatch!");
        }

        Timber.d("Certificate fingerprint verified");

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("server", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket("127.0.0.1", port);
        socket.setSoTimeout(30000); // 30 seconds

        Timber.d("TLS socket created and connected");
        return socket;
    }

    @Override
    public void runAgent(int port, Intent intent) {
        Timber.d("Starting SSH agent for port %d", port);

        byte[] certDer = intent.getByteArrayExtra(SshAgentBroadcastReceiver.EXTRA_CERT_DER);
        String certFingerprint = intent.getStringExtra(SshAgentBroadcastReceiver.EXTRA_CERT_FINGERPRINT);
        String authTokenHex = intent.getStringExtra(SshAgentBroadcastReceiver.EXTRA_AUTH_TOKEN);

        if (certDer == null || certFingerprint == null || authTokenHex == null) {
            Timber.e("Missing TLS credentials in intent");
            Utils.showError(this, "Missing TLS credentials");
            checkThreadExit(port);
            return;
        }

        SSLSocket socket = null;
        try {
            // Retry connection with exponential backoff if agent needs time to start listening
            long retryDelay = CONNECTION_RETRY_INITIAL_DELAY_MS;

            for (int attempt = 1; attempt <= MAX_CONNECTION_RETRIES; attempt++) {
                try {
                    Timber.d("Creating TLS connection to proxy server");
                    socket = createTlsSocket(certDer, certFingerprint, port);
                    socket.setSoTimeout(SOCKET_TIMEOUT_MS);
                    socket.setTcpNoDelay(true);
                    socket.setKeepAlive(true);
                    break;
                } catch (ConnectException e) {
                    if (attempt < MAX_CONNECTION_RETRIES) {
                        Thread.sleep(retryDelay);
                        retryDelay *= 2; // Exponential backoff: 100, 200, 400, 800ms
                    } else {
                        Timber.e("Failed to connect after %d attempts", MAX_CONNECTION_RETRIES);
                        throw e; // Rethrow on final attempt
                    }
                }
            }

            if (socket == null) {
                throw new IOException("Failed to establish connection to proxy");
            }

            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();

            Timber.d("Sending authentication token");
            byte[] authToken = Utils.hexStringToByteArray(authTokenHex);
            output.write(authToken);
            output.flush();

            byte[] response = new byte[2];
            int bytesRead = input.read(response);
            if (bytesRead != 2 || response[0] != 'O' || response[1] != 'K') {
                Timber.e("Authentication failed");
                Utils.showError(this, "Authentication failed");
                checkThreadExit(port);
                return;
            }

            Timber.d("Authentication successful, starting SSH agent protocol");

            // Load SSH keys from storage
            AuthenticationKeyStorage authKeyStorage = new AuthenticationKeyStorage(this);
            List<AuthenticationKeyInfo> keys = authKeyStorage.loadSelectedKeys();
            Timber.d("Loaded %d SSH keys", keys.size());

            // Lazy-load public keys and API connection
            List<SshPublicKeyInfo> publicKeys = null;
            SshApi api = null;
            ApiExecutor executeApi = null;

            // Handle SSH agent protocol messages
            try {
                while (true) {
                    SshAgentMessage req = SshAgentMessage.readFromStream(input);
                    if (req == null) {
                        break;
                    }

                    Timber.d("Received SSH message type: %d", req.getType());
                    SshAgentMessage resMsg = null;
                    switch (req.getType()) {
                        case SshAgentMessage.SSH_AGENTC_REQUEST_IDENTITIES:
                            // Lazy-load public keys on first request
                            if (publicKeys == null) {
                                publicKeys = loadSshPublicKeys(keys);
                            }
                            resMsg = new SshAgentMessage(
                                SshAgentMessage.SSH_AGENT_IDENTITIES_ANSWER,
                                new SshIdentitiesResponse(publicKeys).toBytes()
                            );
                            break;

                        case SshAgentMessage.SSH_AGENTC_SIGN_REQUEST:
                            Timber.d("Sign request");
                            SshSignRequest signReq = new SshSignRequest(req.getContents());

                            // Ensure public keys are loaded (in case client sends SIGN_REQUEST before REQUEST_IDENTITIES)
                            if (publicKeys == null) {
                                Timber.w("SIGN_REQUEST received before REQUEST_IDENTITIES, loading keys now");
                                publicKeys = loadSshPublicKeys(keys);
                                Timber.d("Loaded %d public keys for signing", publicKeys.size());
                            }

                            // Lazy-load API connection on first signing request
                            if (api == null) {
                                Semaphore lock = new Semaphore(0);
                                final boolean[] connRes = {false};

                                api = new SshApi(this, (sshApi, res) -> {
                                    connRes[0] = res;
                                    lock.release();
                                });
                                api.connect();
                                lock.acquire();

                                if (!connRes[0]) {
                                    Timber.e("SSH API connection failed");
                                    resMsg = new SshAgentMessage(SshAgentMessage.SSH_AGENT_FAILURE, null);
                                    break;
                                }

                                executeApi = api::executeApi;
                                Timber.d("SSH API connected");
                            }

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

                                // SSH_AGENT_RSA_SHA2_256 = 0x02, SSH_AGENT_RSA_SHA2_512 = 0x04
                                int hashAlgorithm;
                                if ((signReq.getFlags() & 0x04) != 0) {
                                    hashAlgorithm = org.openintents.ssh.authentication.SshAuthenticationApi.SHA512;
                                } else if ((signReq.getFlags() & 0x02) != 0) {
                                    hashAlgorithm = org.openintents.ssh.authentication.SshAuthenticationApi.SHA256;
                                } else {
                                    hashAlgorithm = org.openintents.ssh.authentication.SshAuthenticationApi.SHA1;
                                }

                                assert executeApi != null;
                                Intent signIntent = callApi(
                                    executeApi,
                                    new SigningRequest(signReq.getData(), keyId, hashAlgorithm).toIntent(),
                                    port
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
            } finally {
                // Clean up API connection
                if (api != null) {
                    try {
                        api.close();
                    } catch (Exception e) {
                        Timber.w(e, "Failed to close SSH API");
                    }
                }
            }
        } catch (InterruptedException e) {
            Timber.w(e, "SSH Agent interrupted during retry");
            Thread.currentThread().interrupt();
        } catch (IOException e) {
            Timber.e(e, "SSH Agent I/O error on port %d", port);
            Utils.showError(this, "SSH I/O error: " + e.getMessage());
        } catch (Exception e) {
            Timber.e(e, "SSH Agent unexpected error on port %d: %s", port, e.getClass().getSimpleName());
            Utils.showError(this, "SSH error: " + e.getMessage());
            try {
                if (socket != null) {
                    socket.setSoLinger(true, 0);
                }
            } catch (Exception e2) {
                Timber.w(e2, "Failed to set linger option");
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

    private List<SshPublicKeyInfo> loadSshPublicKeys(List<AuthenticationKeyInfo> keys) {
        List<SshPublicKeyInfo> publicKeys = new ArrayList<>();
        KeyRepository keyRepository = KeyRepository.create(getApplicationContext());

        for (AuthenticationKeyInfo key : keys) {
            if (key.isGpgKey()) {
                try {
                    long masterKeyId = key.getKeyId();
                    long authKeyId = keyRepository.getEffectiveAuthenticationKeyId(masterKeyId);
                    CanonicalizedPublicKey publicKey = keyRepository.getCanonicalizedPublicKeyRing(masterKeyId).getPublicKey(authKeyId);

                    SshPublicKey sshPublicKey = new SshPublicKey(publicKey);
                    String pubKeyStr = sshPublicKey.getEncodedKey();

                    if (pubKeyStr != null && !pubKeyStr.isEmpty()) {
                        String[] parts = pubKeyStr.split(" ");
                        if (parts.length >= 2) {
                            // Use strict Base64 decoding (no wrapping, no padding tolerance)
                            byte[] keyData = Base64.decode(parts[1], Base64.NO_WRAP);
                            SshPublicKeyInfo info = new SshPublicKeyInfo(
                                    keyData,
                                    key.getName().getBytes(StandardCharsets.UTF_8)
                            );
                            publicKeys.add(info);
                        }
                    }
                } catch (KeyRepository.NotFoundException | PgpGeneralException | NoSuchAlgorithmException e) {
                    Timber.w(e, "Failed to load public key for key %d", key.getKeyId());
                }
            }
        }
        Timber.d("Loaded %d public keys", publicKeys.size());
        return publicKeys;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Timber.d("SSH Agent service created");
    }

}
