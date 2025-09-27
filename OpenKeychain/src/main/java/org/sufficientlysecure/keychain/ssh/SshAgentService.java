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

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import java.net.ServerSocket;
import java.net.Socket;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.RemoteException;
import androidx.annotation.Nullable;

import org.openintents.ssh.authentication.ISshAuthenticationService;
import org.openintents.ssh.authentication.SshAuthenticationApi;
import org.openintents.ssh.authentication.SshAuthenticationConnection;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import timber.log.Timber;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * SSH Agent Service that acts as a bridge to OpenKeychain's SSH Authentication API
 * Similar to OkcAgent but integrated directly into OpenKeychain
 */
public class SshAgentService extends Service {

    private static final int SSH_AGENT_FIXED_PORT = 22022;

    private ServerSocket serverSocket;
    private int currentPort = -1;
    private ExecutorService executorService;
    private HandlerThread handlerThread;
    private Handler handler;
    private boolean isRunning = false;

    // SSH Authentication API connection
    private SshAuthenticationConnection sshAuthConnection;
    private ISshAuthenticationService sshAuthService;
    private KeyRepository keyRepository;
    private AuthenticationKeyStorage authKeyStorage;

    @Override
    public void onCreate() {
        super.onCreate();

        handlerThread = new HandlerThread("SshAgentService");
        handlerThread.start();
        handler = new Handler(handlerThread.getLooper());

        executorService = Executors.newCachedThreadPool();
        keyRepository = KeyRepository.create(this);
        authKeyStorage = new AuthenticationKeyStorage(this);

        // Connect to OpenKeychain's SSH Authentication Service using SshAuthenticationConnection
        connectToSshAuthenticationService();

        Timber.d("SSH Agent Service created");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (!isRunning && authKeyStorage.isSshAgentEnabled()) {
            startSshAgent();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        stopSshAgent();

        if (executorService != null) {
            executorService.shutdown();
        }

        if (handlerThread != null) {
            handlerThread.quitSafely();
        }

        if (sshAuthConnection != null && sshAuthConnection.isConnected()) {
            sshAuthConnection.disconnect();
        }

        Timber.d("SSH Agent Service destroyed");
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void connectToSshAuthenticationService() {
        sshAuthConnection = new SshAuthenticationConnection(this, getPackageName());

        sshAuthConnection.connect(new SshAuthenticationConnection.OnBound() {
            @Override
            public void onBound(ISshAuthenticationService sshAgent) {
                sshAuthService = sshAgent;
                Timber.d("Connected to SSH Authentication Service");
            }

            @Override
            public void onError() {
                sshAuthService = null;
                Timber.w("Failed to connect to SSH Authentication Service");
            }
        });
    }

    private void startSshAgent() {
        handler.post(() -> {
            try {
                // Use fixed port for consistency with okc-agents
                serverSocket = new ServerSocket(SSH_AGENT_FIXED_PORT);
                currentPort = SSH_AGENT_FIXED_PORT;
                isRunning = true;

                Timber.d("SSH Agent listening on fixed port: %d", currentPort);

                // Accept connections in background thread
                executorService.submit(this::acceptConnections);

            } catch (IOException e) {
                Timber.e(e, "Failed to start SSH agent on port %d", SSH_AGENT_FIXED_PORT);
                stopSelf();
            }
        });
    }

    private void acceptConnections() {
        while (isRunning && serverSocket != null) {
            try {
                Socket clientSocket = serverSocket.accept();
                Timber.d("SSH Agent: New client connection from %s", clientSocket.getRemoteSocketAddress());

                // Handle each client in separate thread
                executorService.submit(() -> handleClient(clientSocket));

            } catch (IOException e) {
                if (isRunning) {
                    Timber.e(e, "Error accepting SSH agent connection");
                }
            }
        }
    }

    private void handleClient(Socket clientSocket) {
        try (InputStream inputStream = clientSocket.getInputStream();
             OutputStream outputStream = clientSocket.getOutputStream()) {

            Timber.d("SSH Agent: Handling client request");

            while (clientSocket.isConnected() && !clientSocket.isClosed()) {
                // Read SSH agent protocol message
                SshAgentMessage request = SshAgentMessage.readFromStream(inputStream);
                if (request == null) {
                    break;
                }

                // Process the message
                SshAgentMessage response = processMessage(request);
                if (response != null) {
                    response.writeToStream(outputStream);
                    outputStream.flush();
                }
            }

        } catch (IOException e) {
            Timber.d(e, "SSH Agent client disconnected");
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                Timber.w(e, "Error closing client socket");
            }
        }
    }

    private SshAgentMessage processMessage(SshAgentMessage request) {
        try {
            switch (request.getMessageType()) {
                case SshAgentMessage.SSH_AGENTC_REQUEST_IDENTITIES:
                    return handleRequestIdentities();

                case SshAgentMessage.SSH_AGENTC_SIGN_REQUEST:
                    return handleSignRequest(request);

                default:
                    Timber.w("SSH Agent: Unsupported message type: %d", request.getMessageType());
                    return createFailureResponse();
            }
        } catch (Exception e) {
            Timber.e(e, "SSH Agent: Error processing message");
            return createFailureResponse();
        }
    }

    private SshAgentMessage handleRequestIdentities() {
        try {
            // Get selected authentication keys
            List<AuthenticationKeyInfo> selectedKeys = authKeyStorage.loadSelectedKeys();

            SshAgentMessage.Builder builder = new SshAgentMessage.Builder();
            builder.writeInt(selectedKeys.size());

            for (AuthenticationKeyInfo keyInfo : selectedKeys) {
                if (keyInfo.isGpgKey()) {
                    // Get SSH public key from OpenKeychain
                    byte[] sshPublicKey = getSshPublicKey(keyInfo.getKeyId());
                    if (sshPublicKey != null) {
                        builder.writeBytes(sshPublicKey);
                        builder.writeString(keyInfo.getName());
                    }
                }
            }

            return builder.build(SshAgentMessage.SSH_AGENT_IDENTITIES_ANSWER);

        } catch (Exception e) {
            Timber.e(e, "Error handling request identities");
            return createFailureResponse();
        }
    }

    private SshAgentMessage handleSignRequest(SshAgentMessage request) {
        try {
            SshAgentMessage.Reader reader = new SshAgentMessage.Reader(request.getPayload());

            byte[] publicKeyBlob = reader.readBytes();
            byte[] dataToSign = reader.readBytes();
            int flags = reader.readInt();

            // Find the matching key
            AuthenticationKeyInfo matchingKey = findKeyByPublicKeyBlob(publicKeyBlob);
            if (matchingKey == null) {
                Timber.w("No matching key found for signature request");
                return createFailureResponse();
            }

            // Sign using OpenKeychain's SSH Authentication API
            byte[] signature = signWithOpenKeychainApi(matchingKey.getKeyId(), dataToSign, flags);
            if (signature == null) {
                return createFailureResponse();
            }

            SshAgentMessage.Builder builder = new SshAgentMessage.Builder();
            builder.writeBytes(signature);

            return builder.build(SshAgentMessage.SSH_AGENT_SIGN_RESPONSE);

        } catch (Exception e) {
            Timber.e(e, "Error handling sign request");
            return createFailureResponse();
        }
    }

    private byte[] getSshPublicKey(long keyId) {
        if (sshAuthService == null) {
            return null;
        }

        try {
            Intent intent = new Intent(SshAuthenticationApi.ACTION_GET_SSH_PUBLIC_KEY);
            intent.putExtra(SshAuthenticationApi.EXTRA_KEY_ID, String.valueOf(keyId));

            Intent result = sshAuthService.execute(intent);
            if (result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, 0) == SshAuthenticationApi.RESULT_CODE_SUCCESS) {
                return result.getByteArrayExtra(SshAuthenticationApi.EXTRA_SSH_PUBLIC_KEY);
            }
        } catch (RemoteException e) {
            Timber.e(e, "Error getting SSH public key");
        }

        return null;
    }

    private byte[] signWithOpenKeychainApi(long keyId, byte[] dataToSign, int flags) {
        if (sshAuthService == null) {
            return null;
        }

        try {
            Intent intent = new Intent(SshAuthenticationApi.ACTION_SIGN);
            intent.putExtra(SshAuthenticationApi.EXTRA_KEY_ID, String.valueOf(keyId));
            intent.putExtra(SshAuthenticationApi.EXTRA_CHALLENGE, dataToSign);
            // Convert SSH flags to hash algorithm
            int hashAlgorithm = getHashAlgorithmFromFlags(flags);
            intent.putExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, hashAlgorithm);

            Intent result = sshAuthService.execute(intent);
            if (result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, 0) == SshAuthenticationApi.RESULT_CODE_SUCCESS) {
                return result.getByteArrayExtra(SshAuthenticationApi.EXTRA_SIGNATURE);
            }
        } catch (RemoteException e) {
            Timber.e(e, "Error signing with OpenKeychain API");
        }

        return null;
    }


    private int getHashAlgorithmFromFlags(int flags) {
        if ((flags & 0x04) != 0) {
            return SshAuthenticationApi.SHA512; // RSA-SHA2-512
        } else if ((flags & 0x02) != 0) {
            return SshAuthenticationApi.SHA256; // RSA-SHA2-256
        } else {
            return SshAuthenticationApi.SHA256; // Default to SHA256
        }
    }

    private AuthenticationKeyInfo findKeyByPublicKeyBlob(byte[] publicKeyBlob) {
        List<AuthenticationKeyInfo> selectedKeys = authKeyStorage.loadSelectedKeys();

        for (AuthenticationKeyInfo keyInfo : selectedKeys) {
            if (keyInfo.isGpgKey()) {
                byte[] keyBlob = getSshPublicKey(keyInfo.getKeyId());
                if (keyBlob != null && java.util.Arrays.equals(publicKeyBlob, keyBlob)) {
                    return keyInfo;
                }
            }
        }

        return null;
    }

    private SshAgentMessage createFailureResponse() {
        return new SshAgentMessage(SshAgentMessage.SSH_AGENT_FAILURE, new byte[0]);
    }

    private void stopSshAgent() {
        isRunning = false;

        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                Timber.w(e, "Error closing SSH agent socket");
            }
            serverSocket = null;
        }

        currentPort = -1;
    }

    public int getCurrentPort() {
        return currentPort;
    }

    public static int getAgentPort(Context context) {
        AuthenticationKeyStorage storage = new AuthenticationKeyStorage(context);
        return storage.getSshAgentPort();
    }
}