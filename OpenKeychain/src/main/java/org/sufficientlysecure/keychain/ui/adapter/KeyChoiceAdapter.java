package org.sufficientlysecure.keychain.ui.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.ui.util.KeyInfoFormatter;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class KeyChoiceAdapter extends RecyclerView.Adapter<KeyChoiceAdapter.KeyChoiceViewHolder> {

    private List<UnifiedKeyInfo> keys = new ArrayList<>();
    private Set<Long> selectedKeyIds = new HashSet<>();
    private OnKeySelectedListener listener;
    private KeyInfoFormatter keyInfoFormatter;
    private KeyValidationFunction validationFunction;

    public interface OnKeySelectedListener {
        void onKeySelected(long keyId, boolean selected);
    }

    public interface OnKeyInfoSelectedListener {
        void onKeySelected(UnifiedKeyInfo keyInfo);
    }

    public interface KeyValidationFunction {
        Integer validate(UnifiedKeyInfo keyInfo);
    }

    public KeyChoiceAdapter(Context context) {
        this.keyInfoFormatter = new KeyInfoFormatter(context);
    }

    public void setOnKeySelectedListener(OnKeySelectedListener listener) {
        this.listener = listener;
    }

    public void setKeys(List<UnifiedKeyInfo> keys) {
        this.keys.clear();
        if (keys != null) {
            this.keys.addAll(keys);
        }
        notifyDataSetChanged();
    }

    public void setSelectedKeyIds(Set<Long> selectedKeyIds) {
        this.selectedKeyIds.clear();
        if (selectedKeyIds != null) {
            this.selectedKeyIds.addAll(selectedKeyIds);
        }
        notifyDataSetChanged();
    }

    public Set<Long> getSelectedKeyIds() {
        return new HashSet<>(selectedKeyIds);
    }

    // Compatibility methods for existing code
    public Set<Long> getSelectionIds() {
        return getSelectedKeyIds();
    }

    public void setSelectionByIds(Set<Long> keyIds) {
        setSelectedKeyIds(keyIds);
    }

    public void setUnifiedKeyInfoItems(List<UnifiedKeyInfo> keys) {
        setKeys(keys);
    }

    public UnifiedKeyInfo getActiveItem() {
        // For single selection, return the first selected item
        for (UnifiedKeyInfo key : keys) {
            if (selectedKeyIds.contains(key.master_key_id())) {
                return key;
            }
        }
        return null;
    }

    // Static factory methods for compatibility
    public static KeyChoiceAdapter createMultiChoiceAdapter(Context context, List<UnifiedKeyInfo> keys, KeyValidationFunction validationFunction) {
        KeyChoiceAdapter adapter = new KeyChoiceAdapter(context);
        adapter.setKeys(keys);
        // Store validation function for later use in binding
        adapter.validationFunction = validationFunction;
        return adapter;
    }

    public static KeyChoiceAdapter createSingleChoiceAdapter(Context context, List<UnifiedKeyInfo> keys, KeyValidationFunction validationFunction) {
        KeyChoiceAdapter adapter = new KeyChoiceAdapter(context);
        adapter.setKeys(keys);
        // Store validation function for later use in binding
        adapter.validationFunction = validationFunction;
        return adapter;
    }

    public static KeyChoiceAdapter createSingleClickableAdapter(Context context, List<UnifiedKeyInfo> keys, OnKeyInfoSelectedListener clickListener, KeyValidationFunction validationFunction) {
        KeyChoiceAdapter adapter = new KeyChoiceAdapter(context);
        adapter.setKeys(keys);
        if (clickListener != null) {
            adapter.setOnKeySelectedListener((keyId, selected) -> {
                // Find the UnifiedKeyInfo by keyId and call the listener
                for (UnifiedKeyInfo key : keys) {
                    if (key.master_key_id() == keyId) {
                        clickListener.onKeySelected(key);
                        break;
                    }
                }
            });
        }
        adapter.validationFunction = validationFunction;
        return adapter;
    }

    @NonNull
    @Override
    public KeyChoiceViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
        View view = inflater.inflate(R.layout.key_list_item, parent, false);
        return new KeyChoiceViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull KeyChoiceViewHolder holder, int position) {
        UnifiedKeyInfo keyInfo = keys.get(position);
        holder.validationFunction = this.validationFunction;
        holder.bind(keyInfo, selectedKeyIds.contains(keyInfo.master_key_id()));
    }

    @Override
    public int getItemCount() {
        return keys.size();
    }

    public class KeyChoiceViewHolder extends RecyclerView.ViewHolder {
        private TextView nameView;
        private TextView emailView;
        private TextView creationView;
        private ImageView statusIcon;
        private CheckBox checkBox;
        private KeyValidationFunction validationFunction;

        public KeyChoiceViewHolder(View itemView) {
            super(itemView);
            nameView = itemView.findViewById(R.id.key_list_item_name);
            emailView = itemView.findViewById(R.id.key_list_item_email);
            creationView = itemView.findViewById(R.id.key_list_item_creation);
            statusIcon = itemView.findViewById(R.id.key_list_item_status_icon);

            // Checkbox not available in standard layout - selection shown via activation state
            checkBox = null;

            itemView.setOnClickListener(v -> {
                int pos = getAdapterPosition();
                if (pos != RecyclerView.NO_POSITION) {
                    UnifiedKeyInfo keyInfo = keys.get(pos);
                    boolean wasSelected = selectedKeyIds.contains(keyInfo.master_key_id());

                    if (wasSelected) {
                        selectedKeyIds.remove(keyInfo.master_key_id());
                    } else {
                        selectedKeyIds.add(keyInfo.master_key_id());
                    }

                    notifyItemChanged(pos);

                    if (listener != null) {
                        listener.onKeySelected(keyInfo.master_key_id(), !wasSelected);
                    }
                }
            });
        }

        public void bind(UnifiedKeyInfo keyInfo, boolean isSelected) {
            keyInfoFormatter.setKeyInfo(keyInfo);
            keyInfoFormatter.formatUserId(nameView, emailView);
            keyInfoFormatter.formatCreationDate(creationView);
            keyInfoFormatter.formatStatusIcon(statusIcon);

            if (checkBox != null) {
                checkBox.setChecked(isSelected);
            }

            // Check if key has validation issues
            if (validationFunction != null) {
                Integer validationResult = validationFunction.validate(keyInfo);
                if (validationResult != null) {
                    // Key has validation issues - you could show warning icon or text here
                    // For now, just disable the item
                    itemView.setEnabled(false);
                    itemView.setAlpha(0.5f);
                } else {
                    itemView.setEnabled(true);
                    itemView.setAlpha(1.0f);
                }
            }

            // Highlight selected items
            itemView.setActivated(isSelected);
        }
    }
}