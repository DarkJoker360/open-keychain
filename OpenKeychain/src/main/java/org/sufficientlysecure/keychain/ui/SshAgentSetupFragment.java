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

package org.sufficientlysecure.keychain.ui;

import android.os.Bundle;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.Switch;
import android.widget.TextView;

import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.ssh.SshAgentService;
import org.sufficientlysecure.keychain.util.Preferences;

public class SshAgentSetupFragment extends Fragment {

    private Switch mSshAgentEnabled;
    private Button mGenerateKeys;
    private Button mConfigureKeys;
    private TextView mStatusText;

    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.ssh_agent_setup_fragment, container, false);

        mSshAgentEnabled = view.findViewById(R.id.ssh_agent_enabled);
        mGenerateKeys = view.findViewById(R.id.ssh_generate_keys);
        mConfigureKeys = view.findViewById(R.id.ssh_configure_keys);
        mStatusText = view.findViewById(R.id.ssh_status_text);

        mSshAgentEnabled.setOnCheckedChangeListener((buttonView, isChecked) -> {
            Preferences preferences = Preferences.getPreferences(getContext());
            preferences.setSshAgentEnabled(isChecked);
            updateSshAgentStatus(isChecked);

            if (isChecked) {
                startSshAgentService();
            } else {
                stopSshAgentService();
            }
        });

        mGenerateKeys.setOnClickListener(v -> {
            // TODO: Launch SSH key generation
        });

        mConfigureKeys.setOnClickListener(v -> {
            // TODO: Launch SSH key configuration
        });

        // Initialize with current preference status
        Preferences preferences = Preferences.getPreferences(getContext());
        boolean enabled = preferences.getSshAgentEnabled();
        mSshAgentEnabled.setChecked(enabled);
        updateSshAgentStatus(enabled);

        return view;
    }

    private void updateSshAgentStatus(boolean enabled) {
        if (enabled) {
            mStatusText.setText(R.string.ssh_agent_status_enabled);
            mGenerateKeys.setEnabled(true);
            mConfigureKeys.setEnabled(true);
        } else {
            mStatusText.setText(R.string.ssh_agent_status_disabled);
            mGenerateKeys.setEnabled(false);
            mConfigureKeys.setEnabled(false);
        }
    }

    private void startSshAgentService() {
        android.content.Intent intent = new android.content.Intent(getContext(), SshAgentService.class);
        getContext().startService(intent);
    }

    private void stopSshAgentService() {
        android.content.Intent intent = new android.content.Intent(getContext(), SshAgentService.class);
        getContext().stopService(intent);
    }
}