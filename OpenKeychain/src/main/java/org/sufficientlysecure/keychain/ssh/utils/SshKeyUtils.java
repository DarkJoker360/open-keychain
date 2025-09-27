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

package org.sufficientlysecure.keychain.ssh.utils;

import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.ssh.SshAgentMessage;
import timber.log.Timber;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

public class SshKeyUtils {

    public static boolean canAuthenticate(UnifiedKeyInfo keyInfo) {
        // Check if the key has authentication capability
        // In OpenKeychain, this would typically be determined by:
        // 1. Checking if the key has authentication subkeys
        // 2. Verifying the key is not expired or revoked
        // 3. Ensuring we have the secret key material

        if (!keyInfo.has_any_secret()) {
            return false;
        }

        if (keyInfo.is_expired() || keyInfo.is_revoked()) {
            return false;
        }

        // TODO: Check for authentication-capable subkeys
        // This would require accessing the SubKey information
        // and checking the key flags for authentication capability

        return true; // Simplified for now
    }

    public static String createComment(UnifiedKeyInfo keyInfo) {
        // Create a meaningful comment for the SSH key
        StringBuilder comment = new StringBuilder();

        // Add primary user ID if available
        if (keyInfo.name() != null && !keyInfo.name().isEmpty()) {
            comment.append(keyInfo.name());
        } else if (keyInfo.email() != null && !keyInfo.email().isEmpty()) {
            comment.append(keyInfo.email());
        } else {
            comment.append("OpenKeychain");
        }

        // Add key ID
        comment.append(" (");
        comment.append(formatKeyId(keyInfo.master_key_id()));
        comment.append(")");

        return comment.toString();
    }

    public static String formatKeyId(long keyId) {
        return String.format(Locale.US, "%016X", keyId);
    }

    public static String formatFingerprint(byte[] fingerprint) {
        if (fingerprint == null || fingerprint.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < fingerprint.length; i++) {
            if (i > 0 && i % 2 == 0) {
                sb.append(":");
            }
            sb.append(String.format("%02X", fingerprint[i] & 0xFF));
        }
        return sb.toString();
    }

    public static byte[] createMockSignature(byte[] dataToSign, UnifiedKeyInfo keyInfo) {
        // Create a mock signature for testing purposes
        // In a real implementation, this would perform actual cryptographic signing

        try {
            // Create a deterministic "signature" based on the data and key
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(dataToSign);
            digest.update(String.valueOf(keyInfo.master_key_id()).getBytes());

            byte[] hash = digest.digest();

            // Format as SSH signature (simplified)
            SshAgentMessage.Builder builder = new SshAgentMessage.Builder();
            builder.writeString("ssh-rsa"); // Algorithm
            builder.writeBytes(hash); // Mock signature data

            return builder.build((byte) 0).getPayload();

        } catch (NoSuchAlgorithmException e) {
            Timber.e(e, "Error creating mock signature");
            return new byte[0];
        }
    }

    public static String getSshPublicKeyString(UnifiedKeyInfo keyInfo) {
        // Generate SSH public key string in OpenSSH format
        // Format: <key-type> <base64-encoded-key> <comment>

        try {
            SshKeyConverter converter = new SshKeyConverter();
            byte[] keyBlob = converter.createMockSshPublicKey(keyInfo);
            String base64Key = android.util.Base64.encodeToString(keyBlob, android.util.Base64.NO_WRAP);
            String comment = createComment(keyInfo);

            return String.format("ssh-rsa %s %s", base64Key, comment);

        } catch (Exception e) {
            Timber.e(e, "Error generating SSH public key string");
            return "";
        }
    }

    public static byte[] calculateSshFingerprint(byte[] publicKeyBlob) {
        // Calculate SSH fingerprint (MD5 hash of the public key blob)
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            return md5.digest(publicKeyBlob);
        } catch (NoSuchAlgorithmException e) {
            Timber.e(e, "MD5 not available for SSH fingerprint calculation");
            return new byte[0];
        }
    }

    public static String formatSshFingerprint(byte[] fingerprint) {
        if (fingerprint == null || fingerprint.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < fingerprint.length; i++) {
            if (i > 0) {
                sb.append(":");
            }
            sb.append(String.format("%02x", fingerprint[i] & 0xFF));
        }
        return sb.toString();
    }

    public static boolean isValidSshKeyType(String keyType) {
        return keyType != null && (
                keyType.equals("ssh-rsa") ||
                keyType.equals("ssh-dss") ||
                keyType.equals("ecdsa-sha2-nistp256") ||
                keyType.equals("ecdsa-sha2-nistp384") ||
                keyType.equals("ecdsa-sha2-nistp521") ||
                keyType.equals("ssh-ed25519")
        );
    }
}