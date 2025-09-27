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

import android.content.Context;

import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKeyRing;
import org.sufficientlysecure.keychain.ssh.SshAgentMessage;
import timber.log.Timber;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.PublicKey;
import java.security.spec.ECPoint;

public class SshKeyConverter {

    private final Context context;

    public SshKeyConverter(Context context) {
        this.context = context;
    }

    // For backwards compatibility
    public SshKeyConverter() {
        this.context = null;
    }

    // SSH key type identifiers
    private static final String SSH_RSA = "ssh-rsa";
    private static final String SSH_DSS = "ssh-dss";
    private static final String SSH_ECDSA_P256 = "ecdsa-sha2-nistp256";
    private static final String SSH_ECDSA_P384 = "ecdsa-sha2-nistp384";
    private static final String SSH_ECDSA_P521 = "ecdsa-sha2-nistp521";
    private static final String SSH_ED25519 = "ssh-ed25519";

    public byte[] convertToSshPublicKey(UnifiedKeyInfo keyInfo) throws Exception {
        // Get the authentication subkey from OpenKeychain
        KeyRepository keyRepository = KeyRepository.create(context);

        try {
            // Get the authentication subkey ID
            long authSubKeyId = keyRepository.getEffectiveAuthenticationKeyId(keyInfo.master_key_id());

            // Get the secret key ring to access the public key
            CanonicalizedSecretKeyRing secretKeyRing = keyRepository.getCanonicalizedSecretKeyRing(keyInfo.master_key_id());
            CanonicalizedSecretKey authKey = secretKeyRing.getSecretKey(authSubKeyId);

            // Extract the public key from the authentication subkey
            // We need to work with the PGPPublicKey directly since getPublicKey() isn't accessible
            return convertPgpPublicKeyToSshFormat(authKey, authSubKeyId);

        } catch (Exception e) {
            Timber.e(e, "Error converting GPG key to SSH format");
            throw new Exception("Failed to convert GPG key to SSH format: " + e.getMessage());
        }
    }

    /**
     * Convert a PGP public key to SSH wire format
     */
    private byte[] convertPgpPublicKeyToSshFormat(CanonicalizedSecretKey authKey, long authSubKeyId) throws Exception {
        try {
            // TODO: This is a simplified implementation. A complete implementation would:
            // 1. Extract the PGPPublicKey from the CanonicalizedSecretKey
            // 2. Parse the key algorithm and parameters
            // 3. Convert to proper SSH wire format based on the algorithm

            // For now, create a mock SSH public key
            return createMockSshPublicKeyFromPgp(authKey);

        } catch (Exception e) {
            throw new Exception("Failed to convert PGP key to SSH format: " + e.getMessage());
        }
    }

    /**
     * Convert a Java PublicKey to SSH wire format
     */
    private byte[] convertPublicKeyToSshFormat(PublicKey publicKey) throws Exception {
        if (publicKey == null) {
            throw new Exception("PublicKey is null");
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
            writeString(buffer, SSH_RSA);
            writeBigInteger(buffer, rsaKey.getPublicExponent());
            writeBigInteger(buffer, rsaKey.getModulus());

        } else if (publicKey instanceof DSAPublicKey) {
            DSAPublicKey dsaKey = (DSAPublicKey) publicKey;
            writeString(buffer, SSH_DSS);
            writeBigInteger(buffer, dsaKey.getParams().getP());
            writeBigInteger(buffer, dsaKey.getParams().getQ());
            writeBigInteger(buffer, dsaKey.getParams().getG());
            writeBigInteger(buffer, dsaKey.getY());

        } else if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) publicKey;
            String keyType = getEcKeyType(ecKey);
            writeString(buffer, keyType);
            writeString(buffer, getCurveName(ecKey));
            writeEcPoint(buffer, ecKey);

        } else {
            throw new Exception("Unsupported public key type: " + publicKey.getClass().getSimpleName());
        }

        return buffer.toByteArray();
    }

    private PublicKey extractPublicKey(UnifiedKeyInfo keyInfo) {
        // TODO: Implement proper key extraction from OpenKeychain
        // This would involve:
        // 1. Getting the authentication subkey from the key info
        // 2. Extracting the public key material
        // 3. Converting to Java PublicKey object

        Timber.d("Extracting public key for key ID: %d", keyInfo.master_key_id());

        // For now, return null - this needs to be implemented
        // by integrating with OpenKeychain's existing key handling
        return null;
    }


    private void writeString(ByteArrayOutputStream buffer, String value) throws IOException {
        byte[] bytes = value.getBytes("UTF-8");
        writeInt(buffer, bytes.length);
        buffer.write(bytes);
    }

    private void writeInt(ByteArrayOutputStream buffer, int value) throws IOException {
        buffer.write((value >>> 24) & 0xFF);
        buffer.write((value >>> 16) & 0xFF);
        buffer.write((value >>> 8) & 0xFF);
        buffer.write(value & 0xFF);
    }

    private void writeBigInteger(ByteArrayOutputStream buffer, BigInteger value) throws IOException {
        byte[] bytes = value.toByteArray();
        writeInt(buffer, bytes.length);
        buffer.write(bytes);
    }

    private String getEcKeyType(ECPublicKey ecKey) {
        // Determine EC key type based on curve
        String curveName = getCurveName(ecKey);
        switch (curveName) {
            case "nistp256":
                return SSH_ECDSA_P256;
            case "nistp384":
                return SSH_ECDSA_P384;
            case "nistp521":
                return SSH_ECDSA_P521;
            default:
                throw new IllegalArgumentException("Unsupported EC curve: " + curveName);
        }
    }

    private String getCurveName(ECPublicKey ecKey) {
        // Extract curve name from EC public key
        // This is simplified - real implementation would need proper curve detection
        int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();

        if (fieldSize == 256) {
            return "nistp256";
        } else if (fieldSize == 384) {
            return "nistp384";
        } else if (fieldSize == 521) {
            return "nistp521";
        } else {
            throw new IllegalArgumentException("Unsupported EC field size: " + fieldSize);
        }
    }

    private void writeEcPoint(ByteArrayOutputStream buffer, ECPublicKey ecKey) throws IOException {
        // Convert EC point to SSH format
        ECPoint point = ecKey.getW();

        // Get the field size to determine coordinate byte length
        int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
        int coordinateLength = (fieldSize + 7) / 8; // Convert bits to bytes, round up

        // Create uncompressed point format: 0x04 || X || Y
        ByteArrayOutputStream pointBuffer = new ByteArrayOutputStream();
        pointBuffer.write(0x04); // Uncompressed point format marker

        // Write X coordinate
        byte[] xBytes = point.getAffineX().toByteArray();
        if (xBytes.length > coordinateLength) {
            // Remove leading zero if present
            pointBuffer.write(xBytes, xBytes.length - coordinateLength, coordinateLength);
        } else {
            // Pad with leading zeros if necessary
            for (int i = xBytes.length; i < coordinateLength; i++) {
                pointBuffer.write(0);
            }
            pointBuffer.write(xBytes);
        }

        // Write Y coordinate
        byte[] yBytes = point.getAffineY().toByteArray();
        if (yBytes.length > coordinateLength) {
            // Remove leading zero if present
            pointBuffer.write(yBytes, yBytes.length - coordinateLength, coordinateLength);
        } else {
            // Pad with leading zeros if necessary
            for (int i = yBytes.length; i < coordinateLength; i++) {
                pointBuffer.write(0);
            }
            pointBuffer.write(yBytes);
        }

        byte[] pointBytes = pointBuffer.toByteArray();
        writeInt(buffer, pointBytes.length);
        buffer.write(pointBytes);
    }

    /**
     * Convert SSH key info to SSH public key blob format
     */
    public byte[] convertSshKeyToBlob(org.sufficientlysecure.keychain.ssh.SshKeyInfo sshKey) throws Exception {
        try {
            // Parse the SSH public key string to extract the key data
            String publicKeyString = sshKey.getPublicKey();
            String[] parts = publicKeyString.trim().split("\\s+");

            if (parts.length < 2) {
                throw new Exception("Invalid SSH public key format");
            }

            String keyType = parts[0];
            String keyData = parts[1];

            // Decode the base64 key data
            byte[] keyBytes = android.util.Base64.decode(keyData, android.util.Base64.DEFAULT);

            return keyBytes;

        } catch (Exception e) {
            Timber.e(e, "Error converting SSH key to blob");
            throw new Exception("Failed to convert SSH key to blob: " + e.getMessage());
        }
    }

    private byte[] createMockSshPublicKeyFromPgp(CanonicalizedSecretKey authKey) {
        // Create a mock SSH public key for testing
        try {
            SshAgentMessage.Builder builder = new SshAgentMessage.Builder();
            builder.writeString(SSH_RSA);
            // Mock RSA exponent (65537)
            builder.writeBytes(new byte[]{0x01, 0x00, 0x01});
            // Mock RSA modulus (simplified)
            byte[] mockModulus = new byte[256];
            mockModulus[0] = 0x01; // Ensure positive
            builder.writeBytes(mockModulus);

            return builder.build((byte) 0).getPayload();
        } catch (Exception e) {
            Timber.e(e, "Error creating mock SSH public key");
            return new byte[0];
        }
    }

    public byte[] createMockSshPublicKey(UnifiedKeyInfo keyInfo) {
        // Create a mock SSH public key for testing
        try {
            SshAgentMessage.Builder builder = new SshAgentMessage.Builder();
            builder.writeString(SSH_RSA);
            // Mock RSA exponent (65537)
            builder.writeBytes(new byte[]{0x01, 0x00, 0x01});
            // Mock RSA modulus (simplified)
            byte[] mockModulus = new byte[256];
            mockModulus[0] = 0x01; // Ensure positive
            builder.writeBytes(mockModulus);

            return builder.build((byte) 0).getPayload();
        } catch (Exception e) {
            Timber.e(e, "Error creating mock SSH public key");
            return new byte[0];
        }
    }
}