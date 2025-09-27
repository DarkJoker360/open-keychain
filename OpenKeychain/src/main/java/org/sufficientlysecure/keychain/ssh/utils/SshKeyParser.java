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

import android.util.Base64;
import timber.log.Timber;

import org.sufficientlysecure.keychain.ssh.SshAgentMessage;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SshKeyParser {

    private static final Pattern SSH_PUBLIC_KEY_PATTERN = Pattern.compile(
            "^(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521))\\s+([A-Za-z0-9+/=]+)(?:\\s+(.*))?$"
    );

    private static final Pattern SSH_PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN (.+) PRIVATE KEY-----"
    );

    public static class ParsedSshKey {
        private final String type;
        private final int size;
        private final String fingerprint;

        public ParsedSshKey(String type, int size, String fingerprint) {
            this.type = type;
            this.size = size;
            this.fingerprint = fingerprint;
        }

        public String getType() {
            return type;
        }

        public int getSize() {
            return size;
        }

        public String getFingerprint() {
            return fingerprint;
        }
    }

    public ParsedSshKey parsePublicKey(String publicKeyString) throws Exception {
        String[] lines = publicKeyString.trim().split("\n");
        String keyLine = null;

        // Find the actual key line (skip comments and empty lines)
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {
                keyLine = line;
                break;
            }
        }

        if (keyLine == null) {
            throw new Exception("No valid SSH public key found");
        }

        Matcher matcher = SSH_PUBLIC_KEY_PATTERN.matcher(keyLine);
        if (!matcher.matches()) {
            throw new Exception("Invalid SSH public key format");
        }

        String keyType = matcher.group(1);
        String keyData = matcher.group(2);
        String comment = matcher.group(3);

        // Decode base64 key data
        byte[] keyBytes;
        try {
            keyBytes = Base64.decode(keyData, Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            throw new Exception("Invalid base64 encoding in SSH key");
        }

        // Calculate fingerprint
        String fingerprint = calculateFingerprint(keyBytes);

        // Determine key size
        int keySize = calculateKeySize(keyType, keyBytes);

        // Extract key type without ssh- prefix for display
        String displayType = keyType.startsWith("ssh-") ? keyType.substring(4) : keyType;
        if (displayType.startsWith("ecdsa-sha2-")) {
            displayType = "ecdsa";
        }

        return new ParsedSshKey(displayType, keySize, fingerprint);
    }

    public boolean isPrivateKeyEncrypted(String privateKeyString) {
        if (privateKeyString == null || privateKeyString.trim().isEmpty()) {
            return false;
        }

        // Check for encryption indicators in private key
        String lowerKey = privateKeyString.toLowerCase();
        return lowerKey.contains("encrypted") ||
               lowerKey.contains("proc-type: 4,encrypted") ||
               lowerKey.contains("dek-info:");
    }

    private String calculateFingerprint(byte[] keyBytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(keyBytes);

            // Convert to base64 without padding for SSH fingerprint format
            String base64 = Base64.encodeToString(digest, Base64.NO_PADDING | Base64.NO_WRAP);
            return "SHA256:" + base64;

        } catch (NoSuchAlgorithmException e) {
            Timber.e(e, "SHA-256 not available for fingerprint calculation");
            return "Unknown fingerprint";
        }
    }

    private int calculateKeySize(String keyType, byte[] keyBytes) {
        try {
            SshAgentMessage.Reader reader = new SshAgentMessage.Reader(keyBytes);

            // Skip the key type string
            String typeInKey = reader.readString();

            switch (keyType) {
                case "ssh-rsa":
                    // RSA: skip exponent, read modulus length
                    reader.readBytes(); // exponent
                    byte[] modulus = reader.readBytes();
                    return (modulus.length - 1) * 8; // Subtract 1 for potential leading zero, multiply by 8 for bits

                case "ssh-dss":
                    // DSA: read p parameter length
                    byte[] p = reader.readBytes();
                    return (p.length - 1) * 8;

                case "ecdsa-sha2-nistp256":
                    return 256;
                case "ecdsa-sha2-nistp384":
                    return 384;
                case "ecdsa-sha2-nistp521":
                    return 521;

                case "ssh-ed25519":
                    return 256; // Ed25519 is always 256-bit

                default:
                    return 0; // Unknown key type
            }

        } catch (Exception e) {
            Timber.w(e, "Could not determine key size for type: %s", keyType);
            return 0;
        }
    }

    public boolean isValidSshPublicKey(String publicKeyString) {
        try {
            parsePublicKey(publicKeyString);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isValidSshPrivateKey(String privateKeyString) {
        if (privateKeyString == null || privateKeyString.trim().isEmpty()) {
            return true; // Empty private key is valid (public key only)
        }

        Matcher matcher = SSH_PRIVATE_KEY_PATTERN.matcher(privateKeyString);
        return matcher.find();
    }

    public String extractKeyComment(String publicKeyString) {
        Matcher matcher = SSH_PUBLIC_KEY_PATTERN.matcher(publicKeyString.trim());
        if (matcher.matches()) {
            String comment = matcher.group(3);
            return comment != null ? comment.trim() : "";
        }
        return "";
    }

    public String formatSshPublicKey(String keyType, String keyData, String comment) {
        StringBuilder sb = new StringBuilder();
        sb.append(keyType).append(" ").append(keyData);
        if (comment != null && !comment.trim().isEmpty()) {
            sb.append(" ").append(comment.trim());
        }
        return sb.toString();
    }
}