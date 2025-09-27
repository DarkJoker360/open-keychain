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

public class SshKeyAdapter extends RecyclerView.Adapter<SshKeyAdapter.SshKeyViewHolder> {

    public interface OnSshKeyActionListener {
        void onSshKeyRemoved(SshKeyInfo keyInfo, int position);
        void onSshKeyMoved(int fromPosition, int toPosition);
        void onStartDrag(SshKeyViewHolder viewHolder);
    }

    private List<SshKeyInfo> sshKeys;
    private OnSshKeyActionListener listener;

    public SshKeyAdapter() {
        this.sshKeys = new ArrayList<>();
    }

    public void setOnSshKeyActionListener(OnSshKeyActionListener listener) {
        this.listener = listener;
    }

    public void setSshKeys(List<SshKeyInfo> sshKeys) {
        this.sshKeys = new ArrayList<>(sshKeys);
        notifyDataSetChanged();
    }

    public void addSshKey(SshKeyInfo keyInfo) {
        sshKeys.add(keyInfo);
        notifyItemInserted(sshKeys.size() - 1);
    }

    public void removeSshKey(int position) {
        if (position >= 0 && position < sshKeys.size()) {
            sshKeys.remove(position);
            notifyItemRemoved(position);
        }
    }

    public void moveSshKey(int fromPosition, int toPosition) {
        if (fromPosition < toPosition) {
            for (int i = fromPosition; i < toPosition; i++) {
                Collections.swap(sshKeys, i, i + 1);
            }
        } else {
            for (int i = fromPosition; i > toPosition; i--) {
                Collections.swap(sshKeys, i, i - 1);
            }
        }
        notifyItemMoved(fromPosition, toPosition);
    }

    public List<SshKeyInfo> getSshKeys() {
        return new ArrayList<>(sshKeys);
    }

    @NonNull
    @Override
    public SshKeyViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.ssh_key_item, parent, false);
        return new SshKeyViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull SshKeyViewHolder holder, int position) {
        SshKeyInfo keyInfo = sshKeys.get(position);
        holder.bind(keyInfo);
    }

    @Override
    public int getItemCount() {
        return sshKeys.size();
    }

    public class SshKeyViewHolder extends RecyclerView.ViewHolder {
        private TextView nameText;
        private TextView typeText;
        private TextView fingerprintText;
        private ImageView dragHandle;
        private ImageButton removeButton;

        public SshKeyViewHolder(@NonNull View itemView) {
            super(itemView);

            nameText = itemView.findViewById(R.id.ssh_key_name);
            typeText = itemView.findViewById(R.id.ssh_key_type);
            fingerprintText = itemView.findViewById(R.id.ssh_key_fingerprint);
            dragHandle = itemView.findViewById(R.id.drag_handle);
            removeButton = itemView.findViewById(R.id.btn_remove_ssh_key);

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
                    SshKeyInfo keyInfo = sshKeys.get(position);
                    listener.onSshKeyRemoved(keyInfo, position);
                }
            });
        }

        public void bind(SshKeyInfo keyInfo) {
            nameText.setText(keyInfo.getName());
            typeText.setText(keyInfo.getDisplayType());
            fingerprintText.setText(keyInfo.getShortFingerprint());
        }
    }
}