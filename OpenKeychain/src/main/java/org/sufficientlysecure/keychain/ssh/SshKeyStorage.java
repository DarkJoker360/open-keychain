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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import timber.log.Timber;

import java.util.ArrayList;
import java.util.List;

public class SshKeyStorage {

    private static final String PREFS_NAME = "ssh_keys";
    private static final String KEY_SSH_KEYS = "ssh_keys_list";
    private static final String KEY_SELECTED_GPG_KEY = "selected_gpg_key";

    private final SharedPreferences preferences;

    public SshKeyStorage(Context context) {
        this.preferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public List<SshKeyInfo> loadSshKeys() {
        List<SshKeyInfo> sshKeys = new ArrayList<>();

        try {
            String jsonString = preferences.getString(KEY_SSH_KEYS, "[]");
            JSONArray jsonArray = new JSONArray(jsonString);

            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject jsonObject = jsonArray.getJSONObject(i);
                SshKeyInfo keyInfo = SshKeyInfo.fromJson(jsonObject);
                sshKeys.add(keyInfo);
            }

        } catch (JSONException e) {
            Timber.e(e, "Error loading SSH keys from storage");
        }

        return sshKeys;
    }

    public void saveSshKeys(List<SshKeyInfo> sshKeys) {
        try {
            JSONArray jsonArray = new JSONArray();

            for (SshKeyInfo keyInfo : sshKeys) {
                JSONObject jsonObject = keyInfo.toJson();
                jsonArray.put(jsonObject);
            }

            preferences.edit()
                    .putString(KEY_SSH_KEYS, jsonArray.toString())
                    .apply();

        } catch (JSONException e) {
            Timber.e(e, "Error saving SSH keys to storage");
        }
    }

    public void addSshKey(SshKeyInfo keyInfo) {
        List<SshKeyInfo> sshKeys = loadSshKeys();
        sshKeys.add(keyInfo);
        saveSshKeys(sshKeys);
    }

    public void removeSshKey(SshKeyInfo keyInfo) {
        List<SshKeyInfo> sshKeys = loadSshKeys();
        sshKeys.remove(keyInfo);
        saveSshKeys(sshKeys);
    }

    public void updateSshKeyOrder(List<SshKeyInfo> sshKeys) {
        saveSshKeys(sshKeys);
    }

    public long getSelectedGpgKeyId() {
        return preferences.getLong(KEY_SELECTED_GPG_KEY, -1);
    }

    public void setSelectedGpgKeyId(long keyId) {
        preferences.edit()
                .putLong(KEY_SELECTED_GPG_KEY, keyId)
                .apply();
    }

    public void clearSelectedGpgKey() {
        preferences.edit()
                .remove(KEY_SELECTED_GPG_KEY)
                .apply();
    }

    public boolean hasSshKeys() {
        return !loadSshKeys().isEmpty();
    }

    public boolean hasSelectedGpgKey() {
        return getSelectedGpgKeyId() != -1;
    }

    public void clearAllData() {
        preferences.edit().clear().apply();
    }
}