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

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.Switch;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.ssh.AuthenticationKeyAdapter;
import org.sufficientlysecure.keychain.ssh.AuthenticationKeyInfo;
import org.sufficientlysecure.keychain.ssh.AuthenticationKeyStorage;
import org.sufficientlysecure.keychain.ssh.SshAgentService;
import org.sufficientlysecure.keychain.ssh.SshKeyInfo;
import org.sufficientlysecure.keychain.ssh.SshKeyStorage;
import org.sufficientlysecure.keychain.ui.util.Notify;
import org.sufficientlysecure.keychain.ui.util.Notify.Style;
import org.sufficientlysecure.keychain.util.Preferences;
import timber.log.Timber;

import java.util.ArrayList;
import java.util.List;

public class AuthenticationFragment extends Fragment implements AuthenticationKeyAdapter.OnAuthenticationKeyActionListener {

    private static final int REQUEST_CODE_ADD_KEY = 1001;

    // UI Components
    private Button btnAddKey;
    private RecyclerView keysRecyclerView;
    private TextView noKeysMessage;
    private Switch sshAgentEnabled;
    private Button btnSettings;

    // Data components
    private SshKeyStorage sshKeyStorage;
    private AuthenticationKeyStorage authKeyStorage;
    private AuthenticationKeyAdapter authKeyAdapter;
    private ItemTouchHelper itemTouchHelper;
    private KeyRepository keyRepository;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        sshKeyStorage = new SshKeyStorage(requireContext());
        authKeyStorage = new AuthenticationKeyStorage(requireContext());
        keyRepository = KeyRepository.create(requireContext());
    }

    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.authentication_fragment, container, false);

        initializeViews(view);
        setupRecyclerView();
        setupClickListeners();
        loadData();

        return view;
    }

    private void initializeViews(View view) {
        btnAddKey = view.findViewById(R.id.btn_add_key);
        keysRecyclerView = view.findViewById(R.id.keys_recycler_view);
        noKeysMessage = view.findViewById(R.id.no_keys_message);
        sshAgentEnabled = view.findViewById(R.id.ssh_agent_enabled);
        btnSettings = view.findViewById(R.id.btn_settings);
    }

    private void setupRecyclerView() {
        authKeyAdapter = new AuthenticationKeyAdapter();
        authKeyAdapter.setOnAuthenticationKeyActionListener(this);

        keysRecyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        keysRecyclerView.setAdapter(authKeyAdapter);

        // Setup drag and drop
        ItemTouchHelper.Callback callback = new AuthKeyItemTouchHelperCallback();
        itemTouchHelper = new ItemTouchHelper(callback);
        itemTouchHelper.attachToRecyclerView(keysRecyclerView);
    }

    private void setupClickListeners() {
        btnAddKey.setOnClickListener(v -> addKey());
        btnSettings.setOnClickListener(v -> openSettings());

        sshAgentEnabled.setOnCheckedChangeListener((buttonView, isChecked) -> {
            authKeyStorage.setSshAgentEnabled(isChecked);

            if (isChecked) {
                startSshAgentService();
            } else {
                stopSshAgentService();
            }
        });
    }

    private void loadData() {
        // Load SSH agent status
        boolean isEnabled = authKeyStorage.isSshAgentEnabled();
        sshAgentEnabled.setChecked(isEnabled);

        // Start SSH agent service if enabled
        if (isEnabled) {
            startSshAgentService();
        }

        // Load authentication keys
        loadAuthenticationKeys();
    }

    private void loadAuthenticationKeys() {
        // Load all selected authentication keys from storage
        List<AuthenticationKeyInfo> authKeys = authKeyStorage.loadSelectedKeys();
        authKeyAdapter.setAuthenticationKeys(authKeys);

        if (authKeys.isEmpty()) {
            noKeysMessage.setVisibility(View.VISIBLE);
            keysRecyclerView.setVisibility(View.GONE);
        } else {
            noKeysMessage.setVisibility(View.GONE);
            keysRecyclerView.setVisibility(View.VISIBLE);
        }
    }

    private void addKey() {
        // Load all available keys from OpenKeychain
        try {
            List<UnifiedKeyInfo> availableKeys = keyRepository.getAllUnifiedKeyInfo();
            showKeySelectionDialog(availableKeys);
        } catch (Exception e) {
            Timber.e(e, "Error loading available keys");
            Notify.create(getActivity(), "Error loading keys: " + e.getMessage(), Style.ERROR).show();
        }
    }

    private void showKeySelectionDialog(List<UnifiedKeyInfo> keys) {
        if (keys == null || keys.isEmpty()) {
            Notify.create(getActivity(), "No keys available for authentication", Style.WARN).show();
            return;
        }

        // Filter out keys that are already selected
        List<AuthenticationKeyInfo> existingKeys = authKeyAdapter.getAuthenticationKeys();
        List<UnifiedKeyInfo> availableKeys = new ArrayList<>();

        for (UnifiedKeyInfo key : keys) {
            boolean alreadySelected = false;
            for (AuthenticationKeyInfo existingKey : existingKeys) {
                if (existingKey.isGpgKey() && existingKey.getKeyId() == key.master_key_id()) {
                    alreadySelected = true;
                    break;
                }
            }
            if (!alreadySelected) {
                availableKeys.add(key);
            }
        }

        if (availableKeys.isEmpty()) {
            Notify.create(getActivity(), "All available keys are already added", Style.OK).show();
            return;
        }

        // Create a simple dialog with key selection
        String[] keyNames = new String[availableKeys.size()];
        for (int i = 0; i < availableKeys.size(); i++) {
            UnifiedKeyInfo key = availableKeys.get(i);
            String name = key.name();
            String email = key.email();
            if (email != null && !email.isEmpty()) {
                keyNames[i] = name + " <" + email + ">";
            } else {
                keyNames[i] = name;
            }
        }

        new android.app.AlertDialog.Builder(requireContext())
            .setTitle("Select Authentication Key")
            .setItems(keyNames, (dialog, which) -> {
                UnifiedKeyInfo selectedKey = availableKeys.get(which);
                addSelectedKey(selectedKey);
            })
            .setNegativeButton("Cancel", null)
            .show();
    }

    private void addSelectedKey(UnifiedKeyInfo keyInfo) {
        // Create an AuthenticationKeyInfo from the selected GPG key
        String keyDetails = "GPG Key • " + Long.toHexString(keyInfo.master_key_id()).toUpperCase();
        AuthenticationKeyInfo authKey = AuthenticationKeyInfo.fromGpgKey(
            keyInfo.name(), keyInfo.email(), keyInfo.master_key_id(), keyDetails);

        // Store the selected key persistently
        authKeyStorage.addKey(authKey);

        // Refresh the display
        loadAuthenticationKeys();

        Timber.d("Added authentication key: " + authKey.getName());
    }

    private void openSettings() {
        Intent intent = new Intent(requireContext(), SshAgentSetupActivity.class);
        startActivity(intent);
    }


    private void startSshAgentService() {
        Intent intent = new Intent(requireContext(), SshAgentService.class);
        requireContext().startService(intent);
    }

    private void stopSshAgentService() {
        Intent intent = new Intent(requireContext(), SshAgentService.class);
        requireContext().stopService(intent);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (resultCode == Activity.RESULT_OK && requestCode == REQUEST_CODE_ADD_KEY) {
            // Handle key selection result from OpenKeychain
            if (data != null) {
                // TODO: Process selected key from OpenKeychain and add to authentication keys
                loadAuthenticationKeys();
            }
        }
    }

    // AuthenticationKeyAdapter.OnAuthenticationKeyActionListener implementation

    @Override
    public void onKeyRemoved(AuthenticationKeyInfo keyInfo, int position) {
        // Remove from persistent storage
        authKeyStorage.removeKey(keyInfo);

        // Refresh the display
        loadAuthenticationKeys();
    }

    @Override
    public void onKeyMoved(int fromPosition, int toPosition) {
        authKeyAdapter.moveAuthenticationKey(fromPosition, toPosition);

        // Update the order in persistent storage
        List<AuthenticationKeyInfo> updatedKeys = authKeyAdapter.getAuthenticationKeys();
        authKeyStorage.updateKeyOrder(updatedKeys);
    }

    @Override
    public void onStartDrag(AuthenticationKeyAdapter.AuthenticationKeyViewHolder viewHolder) {
        itemTouchHelper.startDrag(viewHolder);
    }

    // ItemTouchHelper callback for drag and drop
    private class AuthKeyItemTouchHelperCallback extends ItemTouchHelper.Callback {

        @Override
        public boolean isLongPressDragEnabled() {
            return false; // We handle drag start manually
        }

        @Override
        public boolean isItemViewSwipeEnabled() {
            return false;
        }

        @Override
        public int getMovementFlags(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            int dragFlags = ItemTouchHelper.UP | ItemTouchHelper.DOWN;
            return makeMovementFlags(dragFlags, 0);
        }

        @Override
        public boolean onMove(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder,
                              RecyclerView.ViewHolder target) {
            onKeyMoved(viewHolder.getAdapterPosition(), target.getAdapterPosition());
            return true;
        }

        @Override
        public void onSwiped(RecyclerView.ViewHolder viewHolder, int direction) {
            // Not used since swipe is disabled
        }
    }
}