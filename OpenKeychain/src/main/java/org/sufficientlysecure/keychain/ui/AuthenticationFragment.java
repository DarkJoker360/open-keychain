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

import android.app.AlertDialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
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
import org.sufficientlysecure.keychain.ui.util.Notify;
import org.sufficientlysecure.keychain.ui.util.Notify.Style;
import timber.log.Timber;

import java.util.ArrayList;
import java.util.List;

public class AuthenticationFragment extends Fragment implements AuthenticationKeyAdapter.OnAuthenticationKeyActionListener {

    private Button btnAddKey;
    private RecyclerView keysRecyclerView;
    private TextView noKeysMessage;

    private AuthenticationKeyStorage authKeyStorage;
    private AuthenticationKeyAdapter authKeyAdapter;
    private ItemTouchHelper itemTouchHelper;
    private KeyRepository keyRepository;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
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
    }

    private void setupRecyclerView() {
        authKeyAdapter = new AuthenticationKeyAdapter();
        authKeyAdapter.setOnAuthenticationKeyActionListener(this);

        keysRecyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        keysRecyclerView.setAdapter(authKeyAdapter);

        ItemTouchHelper.Callback callback = new AuthKeyItemTouchHelperCallback();
        itemTouchHelper = new ItemTouchHelper(callback);
        itemTouchHelper.attachToRecyclerView(keysRecyclerView);
    }

    private void setupClickListeners() {
        btnAddKey.setOnClickListener(v -> addKey());
    }

    private void loadData() {
        loadAuthenticationKeys();
    }

    private void loadAuthenticationKeys() {
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

        // Filter unique valid auth keys
        List<UnifiedKeyInfo> availableKeys = getUnifiedKeyInfos(keys);

        if (availableKeys.isEmpty()) {
            Notify.create(getActivity(), "No authentication-capable keys available. Keys must have authentication capability and not be revoked or expired.", Style.WARN).show();
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

        new AlertDialog.Builder(requireContext())
            .setTitle("Select Authentication Key")
            .setItems(keyNames, (dialog, which) -> {
                UnifiedKeyInfo selectedKey = availableKeys.get(which);
                addSelectedKey(selectedKey);
            })
            .setNegativeButton("Cancel", null)
            .show();
    }

    @NonNull
    private List<UnifiedKeyInfo> getUnifiedKeyInfos(List<UnifiedKeyInfo> keys) {
        List<AuthenticationKeyInfo> existingKeys = authKeyAdapter.getAuthenticationKeys();
        List<UnifiedKeyInfo> availableKeys = new ArrayList<>();

        for (UnifiedKeyInfo key : keys) {
            if (!key.has_auth_key()) {
                continue;
            }

            if (key.is_revoked() || key.is_expired()) {
                continue;
            }

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
        return availableKeys;
    }

    private void addSelectedKey(UnifiedKeyInfo keyInfo) {
        String keyDetails = "GPG Key • " + Long.toHexString(keyInfo.master_key_id()).toUpperCase();
        AuthenticationKeyInfo authKey = AuthenticationKeyInfo.fromGpgKey(
            keyInfo.name(), keyInfo.email(), keyInfo.master_key_id(), keyDetails);
        authKeyStorage.addKey(authKey);

        loadAuthenticationKeys();

        Timber.d("Added authentication key: %s", authKey.getName());
    }

    @Override
    public void onKeyRemoved(AuthenticationKeyInfo keyInfo, int position) {
        authKeyStorage.removeKey(keyInfo);

        loadAuthenticationKeys();
    }

    @Override
    public void onKeyMoved(int fromPosition, int toPosition) {
        authKeyAdapter.moveAuthenticationKey(fromPosition, toPosition);

        List<AuthenticationKeyInfo> updatedKeys = authKeyAdapter.getAuthenticationKeys();
        authKeyStorage.updateKeyOrder(updatedKeys);
    }

    @Override
    public void onStartDrag(AuthenticationKeyAdapter.AuthenticationKeyViewHolder viewHolder) {
        itemTouchHelper.startDrag(viewHolder);
    }

    private class AuthKeyItemTouchHelperCallback extends ItemTouchHelper.Callback {

        @Override
        public boolean isLongPressDragEnabled() {
            return false;
        }

        @Override
        public boolean isItemViewSwipeEnabled() {
            return false;
        }

        @Override
        public int getMovementFlags(@NonNull RecyclerView recyclerView, @NonNull RecyclerView.ViewHolder viewHolder) {
            int dragFlags = ItemTouchHelper.UP | ItemTouchHelper.DOWN;
            return makeMovementFlags(dragFlags, 0);
        }

        @Override
        public boolean onMove(@NonNull RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder,
                              RecyclerView.ViewHolder target) {
            onKeyMoved(viewHolder.getAdapterPosition(), target.getAdapterPosition());
            return true;
        }

        @Override
        public void onSwiped(@NonNull RecyclerView.ViewHolder viewHolder, int direction) { }
    }
}