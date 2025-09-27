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
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import timber.log.Timber;

import java.util.ArrayList;
import java.util.List;

/**
 * Storage for authentication keys selected for SSH agent use
 */
public class AuthenticationKeyStorage {

    private static final String PREF_NAME = "authentication_keys";
    private static final String KEY_SELECTED_KEYS = "selected_keys";
    private static final String KEY_SSH_AGENT_ENABLED = "ssh_agent_enabled";
    private static final String KEY_SSH_AGENT_PORT = "ssh_agent_port";

    private final SharedPreferences preferences;

    public AuthenticationKeyStorage(@NonNull Context context) {
        this.preferences = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
    }

    /**
     * Save the list of selected authentication keys
     */
    public void saveSelectedKeys(@NonNull List<AuthenticationKeyInfo> keys) {
        try {
            JSONArray jsonArray = new JSONArray();
            for (AuthenticationKeyInfo key : keys) {
                JSONObject keyJson = new JSONObject();
                keyJson.put("name", key.getName());
                keyJson.put("details", key.getDetails());
                keyJson.put("fingerprint", key.getFingerprint());
                keyJson.put("keyType", key.getKeyType().name());
                keyJson.put("typeBadge", key.getTypeBadge());
                keyJson.put("keyId", key.getKeyId());
                jsonArray.put(keyJson);
            }

            preferences.edit()
                .putString(KEY_SELECTED_KEYS, jsonArray.toString())
                .apply();

            Timber.d("Saved %d authentication keys", keys.size());
        } catch (JSONException e) {
            Timber.e(e, "Error saving authentication keys");
        }
    }

    /**
     * Load the list of selected authentication keys
     */
    @NonNull
    public List<AuthenticationKeyInfo> loadSelectedKeys() {
        List<AuthenticationKeyInfo> keys = new ArrayList<>();
        String jsonString = preferences.getString(KEY_SELECTED_KEYS, null);

        if (jsonString != null) {
            try {
                JSONArray jsonArray = new JSONArray(jsonString);
                for (int i = 0; i < jsonArray.length(); i++) {
                    JSONObject keyJson = jsonArray.getJSONObject(i);

                    String name = keyJson.getString("name");
                    String details = keyJson.getString("details");
                    String fingerprint = keyJson.getString("fingerprint");
                    AuthenticationKeyInfo.KeyType keyType = AuthenticationKeyInfo.KeyType.valueOf(keyJson.getString("keyType"));
                    String typeBadge = keyJson.getString("typeBadge");
                    long keyId = keyJson.getLong("keyId");

                    AuthenticationKeyInfo key = new AuthenticationKeyInfo(
                        name, details, fingerprint, keyType, typeBadge, keyId);
                    keys.add(key);
                }
                Timber.d("Loaded %d authentication keys", keys.size());
            } catch (JSONException e) {
                Timber.e(e, "Error loading authentication keys");
            }
        }

        return keys;
    }

    /**
     * Add a single authentication key
     */
    public void addKey(@NonNull AuthenticationKeyInfo key) {
        List<AuthenticationKeyInfo> keys = loadSelectedKeys();

        // Check if key already exists
        for (AuthenticationKeyInfo existingKey : keys) {
            if (existingKey.getKeyId() == key.getKeyId() &&
                existingKey.getKeyType() == key.getKeyType()) {
                Timber.w("Key already exists, not adding: %s", key.getName());
                return;
            }
        }

        keys.add(key);
        saveSelectedKeys(keys);
    }

    /**
     * Remove a single authentication key
     */
    public void removeKey(@NonNull AuthenticationKeyInfo key) {
        List<AuthenticationKeyInfo> keys = loadSelectedKeys();
        keys.removeIf(existingKey ->
            existingKey.getKeyId() == key.getKeyId() &&
            existingKey.getKeyType() == key.getKeyType());
        saveSelectedKeys(keys);
    }

    /**
     * Update the order of authentication keys
     */
    public void updateKeyOrder(@NonNull List<AuthenticationKeyInfo> keys) {
        saveSelectedKeys(keys);
    }

    /**
     * Clear all selected authentication keys
     */
    public void clearAllKeys() {
        preferences.edit()
            .remove(KEY_SELECTED_KEYS)
            .apply();
        Timber.d("Cleared all authentication keys");
    }

    /**
     * Check if SSH agent is enabled
     */
    public boolean isSshAgentEnabled() {
        return preferences.getBoolean(KEY_SSH_AGENT_ENABLED, false);
    }

    /**
     * Set SSH agent enabled state
     */
    public void setSshAgentEnabled(boolean enabled) {
        preferences.edit()
            .putBoolean(KEY_SSH_AGENT_ENABLED, enabled)
            .apply();
        Timber.d("SSH agent enabled: %s", enabled);
    }

    /**
     * Get authentication keys that are GPG keys
     */
    @NonNull
    public List<AuthenticationKeyInfo> getGpgKeys() {
        List<AuthenticationKeyInfo> allKeys = loadSelectedKeys();
        List<AuthenticationKeyInfo> gpgKeys = new ArrayList<>();

        for (AuthenticationKeyInfo key : allKeys) {
            if (key.isGpgKey()) {
                gpgKeys.add(key);
            }
        }

        return gpgKeys;
    }

    /**
     * Get authentication keys that are SSH keys
     */
    @NonNull
    public List<AuthenticationKeyInfo> getSshKeys() {
        List<AuthenticationKeyInfo> allKeys = loadSelectedKeys();
        List<AuthenticationKeyInfo> sshKeys = new ArrayList<>();

        for (AuthenticationKeyInfo key : allKeys) {
            if (key.isSshKey()) {
                sshKeys.add(key);
            }
        }

        return sshKeys;
    }

    /**
     * Set SSH agent port
     */
    public void setSshAgentPort(int port) {
        preferences.edit()
            .putInt(KEY_SSH_AGENT_PORT, port)
            .apply();
        Timber.d("SSH agent port set: %d", port);
    }

    /**
     * Get SSH agent port
     */
    public int getSshAgentPort() {
        return preferences.getInt(KEY_SSH_AGENT_PORT, -1);
    }

    /**
     * Clear SSH agent port
     */
    public void clearSshAgentPort() {
        preferences.edit()
            .remove(KEY_SSH_AGENT_PORT)
            .apply();
        Timber.d("SSH agent port cleared");
    }
}