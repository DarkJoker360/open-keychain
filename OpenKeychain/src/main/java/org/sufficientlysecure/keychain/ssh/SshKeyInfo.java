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
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONException;
import org.json.JSONObject;

public class SshKeyInfo implements Parcelable {

    private static final String JSON_NAME = "name";
    private static final String JSON_TYPE = "type";
    private static final String JSON_SIZE = "size";
    private static final String JSON_FINGERPRINT = "fingerprint";
    private static final String JSON_PUBLIC_KEY = "publicKey";
    private static final String JSON_PRIVATE_KEY = "privateKey";
    private static final String JSON_IS_ENCRYPTED = "isEncrypted";

    private final String name;
    private final String type;
    private final int size;
    private final String fingerprint;
    private final String publicKey;
    private final String privateKey;
    private final boolean isEncrypted;

    public SshKeyInfo(@NonNull String name, @NonNull String type, int size,
                      @NonNull String fingerprint, @NonNull String publicKey,
                      @Nullable String privateKey, boolean isEncrypted) {
        this.name = name;
        this.type = type;
        this.size = size;
        this.fingerprint = fingerprint;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.isEncrypted = isEncrypted;
    }

    protected SshKeyInfo(Parcel in) {
        name = in.readString();
        type = in.readString();
        size = in.readInt();
        fingerprint = in.readString();
        publicKey = in.readString();
        privateKey = in.readString();
        isEncrypted = in.readByte() != 0;
    }

    public static final Creator<SshKeyInfo> CREATOR = new Creator<SshKeyInfo>() {
        @Override
        public SshKeyInfo createFromParcel(Parcel in) {
            return new SshKeyInfo(in);
        }

        @Override
        public SshKeyInfo[] newArray(int size) {
            return new SshKeyInfo[size];
        }
    };

    @NonNull
    public String getName() {
        return name;
    }

    @NonNull
    public String getType() {
        return type;
    }

    public int getSize() {
        return size;
    }

    @NonNull
    public String getFingerprint() {
        return fingerprint;
    }

    @NonNull
    public String getPublicKey() {
        return publicKey;
    }

    @Nullable
    public String getPrivateKey() {
        return privateKey;
    }

    public boolean isEncrypted() {
        return isEncrypted;
    }

    public String getDisplayType() {
        return type.toUpperCase() + " " + size + "-bit";
    }

    public String getShortFingerprint() {
        if (fingerprint.startsWith("SHA256:")) {
            String hash = fingerprint.substring(7);
            return "SHA256:" + hash.substring(0, Math.min(16, hash.length())) + "...";
        }
        return fingerprint.length() > 20 ? fingerprint.substring(0, 20) + "..." : fingerprint;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject json = new JSONObject();
        json.put(JSON_NAME, name);
        json.put(JSON_TYPE, type);
        json.put(JSON_SIZE, size);
        json.put(JSON_FINGERPRINT, fingerprint);
        json.put(JSON_PUBLIC_KEY, publicKey);
        if (privateKey != null) {
            json.put(JSON_PRIVATE_KEY, privateKey);
        }
        json.put(JSON_IS_ENCRYPTED, isEncrypted);
        return json;
    }

    public static SshKeyInfo fromJson(JSONObject json) throws JSONException {
        String name = json.getString(JSON_NAME);
        String type = json.getString(JSON_TYPE);
        int size = json.getInt(JSON_SIZE);
        String fingerprint = json.getString(JSON_FINGERPRINT);
        String publicKey = json.getString(JSON_PUBLIC_KEY);
        String privateKey = json.optString(JSON_PRIVATE_KEY, null);
        boolean isEncrypted = json.optBoolean(JSON_IS_ENCRYPTED, false);

        return new SshKeyInfo(name, type, size, fingerprint, publicKey, privateKey, isEncrypted);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(name);
        dest.writeString(type);
        dest.writeInt(size);
        dest.writeString(fingerprint);
        dest.writeString(publicKey);
        dest.writeString(privateKey);
        dest.writeByte((byte) (isEncrypted ? 1 : 0));
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        SshKeyInfo that = (SshKeyInfo) obj;
        return fingerprint.equals(that.fingerprint);
    }

    @Override
    public int hashCode() {
        return fingerprint.hashCode();
    }

    @Override
    public String toString() {
        return "SshKeyInfo{" +
                "name='" + name + '\'' +
                ", type='" + type + '\'' +
                ", size=" + size +
                ", fingerprint='" + fingerprint + '\'' +
                '}';
    }
}