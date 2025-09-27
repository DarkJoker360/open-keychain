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

import android.os.Parcel;
import android.os.Parcelable;

public class AuthenticationKeyInfo implements Parcelable {

    public enum KeyType {
        GPG, SSH
    }

    private final String name;
    private final String details;
    private final String fingerprint;
    private final KeyType keyType;
    private final String typeBadge;
    private final long keyId;

    public AuthenticationKeyInfo(String name, String details, String fingerprint,
                               KeyType keyType, String typeBadge, long keyId) {
        this.name = name;
        this.details = details;
        this.fingerprint = fingerprint;
        this.keyType = keyType;
        this.typeBadge = typeBadge;
        this.keyId = keyId;
    }

    // Create from OpenKeychain GPG key
    public static AuthenticationKeyInfo fromGpgKey(String name, String email, long keyId, String keyDetails) {
        String displayName = name;
        if (email != null && !email.isEmpty()) {
            displayName = name + " <" + email + ">";
        }
        String details = keyDetails != null ? keyDetails : "GPG Key";
        String fingerprint = "0x" + Long.toHexString(keyId).toUpperCase();

        return new AuthenticationKeyInfo(displayName, details, fingerprint,
                                       KeyType.GPG, "GPG", keyId);
    }

    // Create from SSH key
    public static AuthenticationKeyInfo fromSshKey(SshKeyInfo sshKey) {
        String details = sshKey.getType().toUpperCase() + " " + sshKey.getSize() + "-bit";

        return new AuthenticationKeyInfo(sshKey.getName(), details,
                                       sshKey.getShortFingerprint(),
                                       KeyType.SSH, sshKey.getType().toUpperCase(),
                                       sshKey.getFingerprint().hashCode());
    }

    public String getName() {
        return name;
    }

    public String getDetails() {
        return details;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public String getTypeBadge() {
        return typeBadge;
    }

    public long getKeyId() {
        return keyId;
    }

    public boolean isGpgKey() {
        return keyType == KeyType.GPG;
    }

    public boolean isSshKey() {
        return keyType == KeyType.SSH;
    }

    // Parcelable implementation
    protected AuthenticationKeyInfo(Parcel in) {
        name = in.readString();
        details = in.readString();
        fingerprint = in.readString();
        keyType = KeyType.valueOf(in.readString());
        typeBadge = in.readString();
        keyId = in.readLong();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(name);
        dest.writeString(details);
        dest.writeString(fingerprint);
        dest.writeString(keyType.name());
        dest.writeString(typeBadge);
        dest.writeLong(keyId);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<AuthenticationKeyInfo> CREATOR = new Creator<AuthenticationKeyInfo>() {
        @Override
        public AuthenticationKeyInfo createFromParcel(Parcel in) {
            return new AuthenticationKeyInfo(in);
        }

        @Override
        public AuthenticationKeyInfo[] newArray(int size) {
            return new AuthenticationKeyInfo[size];
        }
    };
}