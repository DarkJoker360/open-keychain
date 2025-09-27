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

import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import org.sufficientlysecure.keychain.R;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AuthenticationKeyAdapter extends RecyclerView.Adapter<AuthenticationKeyAdapter.AuthenticationKeyViewHolder> {

    public interface OnAuthenticationKeyActionListener {
        void onKeyRemoved(AuthenticationKeyInfo keyInfo, int position);
        void onKeyMoved(int fromPosition, int toPosition);
        void onStartDrag(AuthenticationKeyViewHolder viewHolder);
    }

    private List<AuthenticationKeyInfo> authenticationKeys;
    private OnAuthenticationKeyActionListener listener;

    public AuthenticationKeyAdapter() {
        this.authenticationKeys = new ArrayList<>();
    }

    public void setOnAuthenticationKeyActionListener(OnAuthenticationKeyActionListener listener) {
        this.listener = listener;
    }

    public void setAuthenticationKeys(List<AuthenticationKeyInfo> keys) {
        this.authenticationKeys = new ArrayList<>(keys);
        notifyDataSetChanged();
    }

    public void addAuthenticationKey(AuthenticationKeyInfo keyInfo) {
        authenticationKeys.add(keyInfo);
        notifyItemInserted(authenticationKeys.size() - 1);
    }

    public void removeAuthenticationKey(int position) {
        if (position >= 0 && position < authenticationKeys.size()) {
            authenticationKeys.remove(position);
            notifyItemRemoved(position);
        }
    }

    public void moveAuthenticationKey(int fromPosition, int toPosition) {
        if (fromPosition < toPosition) {
            for (int i = fromPosition; i < toPosition; i++) {
                Collections.swap(authenticationKeys, i, i + 1);
            }
        } else {
            for (int i = fromPosition; i > toPosition; i--) {
                Collections.swap(authenticationKeys, i, i - 1);
            }
        }
        notifyItemMoved(fromPosition, toPosition);
    }

    public List<AuthenticationKeyInfo> getAuthenticationKeys() {
        return new ArrayList<>(authenticationKeys);
    }

    @NonNull
    @Override
    public AuthenticationKeyViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.authentication_key_item, parent, false);
        return new AuthenticationKeyViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull AuthenticationKeyViewHolder holder, int position) {
        AuthenticationKeyInfo keyInfo = authenticationKeys.get(position);
        holder.bind(keyInfo);
    }

    @Override
    public int getItemCount() {
        return authenticationKeys.size();
    }

    public class AuthenticationKeyViewHolder extends RecyclerView.ViewHolder {
        private TextView keyName;
        private TextView keyDetails;
        private TextView keyFingerprint;
        private TextView keyTypeBadge;
        private ImageView dragHandle;
        private ImageButton removeButton;

        public AuthenticationKeyViewHolder(@NonNull View itemView) {
            super(itemView);

            keyName = itemView.findViewById(R.id.key_name);
            keyDetails = itemView.findViewById(R.id.key_details);
            keyFingerprint = itemView.findViewById(R.id.key_fingerprint);
            keyTypeBadge = itemView.findViewById(R.id.key_type_badge);
            dragHandle = itemView.findViewById(R.id.drag_handle);
            removeButton = itemView.findViewById(R.id.btn_remove_key);

            // Set up drag handle
            dragHandle.setOnTouchListener((v, event) -> {
                if (event.getAction() == MotionEvent.ACTION_DOWN) {
                    if (listener != null) {
                        listener.onStartDrag(this);
                    }
                }
                return false;
            });

            // Set up remove button
            removeButton.setOnClickListener(v -> {
                int position = getAdapterPosition();
                if (position != RecyclerView.NO_POSITION && listener != null) {
                    AuthenticationKeyInfo keyInfo = authenticationKeys.get(position);
                    listener.onKeyRemoved(keyInfo, position);
                }
            });
        }

        public void bind(AuthenticationKeyInfo keyInfo) {
            keyName.setText(keyInfo.getName());
            keyDetails.setText(keyInfo.getDetails());
            keyTypeBadge.setText(keyInfo.getTypeBadge());

            // Show fingerprint for SSH keys, hide for GPG keys (as per OkcAgent style)
            if (keyInfo.isSshKey()) {
                keyFingerprint.setText(keyInfo.getFingerprint());
                keyFingerprint.setVisibility(View.VISIBLE);
            } else {
                keyFingerprint.setVisibility(View.GONE);
            }
        }
    }
}