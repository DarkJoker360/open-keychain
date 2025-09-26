package org.sufficientlysecure.keychain.ui.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.ui.util.KeyInfoFormatter;

import java.util.ArrayList;
import java.util.List;

public class KeyListAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    private static final int VIEW_TYPE_HEADER = 0;
    private static final int VIEW_TYPE_KEY = 1;
    private static final int VIEW_TYPE_DUMMY = 2;

    private List<ListItem> items = new ArrayList<>();
    private KeyInfoFormatter keyInfoFormatter;
    private OnKeyClickListener clickListener;

    public interface OnKeyClickListener {
        void onKeyClick(UnifiedKeyInfo keyInfo);
    }

    public KeyListAdapter(Context context) {
        this.keyInfoFormatter = new KeyInfoFormatter(context);
    }

    public void setOnKeyClickListener(OnKeyClickListener listener) {
        this.clickListener = listener;
    }

    public void setKeys(List<UnifiedKeyInfo> keys) {
        items.clear();

        if (keys == null || keys.isEmpty()) {
            items.add(new DummyItem());
        } else {
            String currentSection = null;
            for (UnifiedKeyInfo keyInfo : keys) {
                if (keyInfo == null || keyInfo.user_id() == null) {
                    continue; // Skip null entries
                }

                String userId = keyInfo.user_id();
                String section = userId.length() > 0 ? userId.substring(0, 1).toUpperCase() : "#";
                if (!section.equals(currentSection)) {
                    currentSection = section;
                    items.add(new HeaderItem(section));
                }
                items.add(new KeyItem(keyInfo));
            }
        }
        notifyDataSetChanged();
    }

    @Override
    public int getItemViewType(int position) {
        return items.get(position).getType();
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(parent.getContext());

        switch (viewType) {
            case VIEW_TYPE_HEADER:
                View headerView = inflater.inflate(R.layout.key_list_header_public, parent, false);
                return new HeaderViewHolder(headerView);
            case VIEW_TYPE_KEY:
                View keyView = inflater.inflate(R.layout.key_list_item, parent, false);
                return new KeyViewHolder(keyView);
            case VIEW_TYPE_DUMMY:
                View dummyView = inflater.inflate(R.layout.key_list_dummy, parent, false);
                return new DummyViewHolder(dummyView);
            default:
                throw new IllegalArgumentException("Invalid view type: " + viewType);
        }
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        ListItem item = items.get(position);

        if (holder instanceof HeaderViewHolder) {
            HeaderItem headerItem = (HeaderItem) item;
            ((HeaderViewHolder) holder).bind(headerItem.title);
        } else if (holder instanceof KeyViewHolder) {
            KeyItem keyItem = (KeyItem) item;
            ((KeyViewHolder) holder).bind(keyItem.keyInfo, keyInfoFormatter);
        }
        // DummyViewHolder doesn't need binding
    }

    // ViewHolder classes
    static class HeaderViewHolder extends RecyclerView.ViewHolder {
        TextView textView;

        HeaderViewHolder(View itemView) {
            super(itemView);
            textView = itemView.findViewById(android.R.id.text1);
        }

        void bind(String title) {
            textView.setText(title);
        }
    }

    class KeyViewHolder extends RecyclerView.ViewHolder {
        TextView nameView;
        TextView emailView;
        TextView creationView;

        KeyViewHolder(View itemView) {
            super(itemView);
            nameView = itemView.findViewById(R.id.key_list_item_name);
            emailView = itemView.findViewById(R.id.key_list_item_email);
            creationView = itemView.findViewById(R.id.key_list_item_creation);

            itemView.setOnClickListener(v -> {
                int position = getAdapterPosition();
                if (position != RecyclerView.NO_POSITION && clickListener != null) {
                    ListItem item = items.get(position);
                    if (item instanceof KeyItem) {
                        clickListener.onKeyClick(((KeyItem) item).keyInfo);
                    }
                }
            });
        }

        void bind(UnifiedKeyInfo keyInfo, KeyInfoFormatter formatter) {
            if (keyInfo == null) {
                // Handle null keyInfo gracefully
                nameView.setText("");
                if (emailView != null) {
                    emailView.setVisibility(View.GONE);
                }
                creationView.setVisibility(View.GONE);
                return;
            }

            // Ensure formatter has key info before calling format methods
            formatter.setKeyInfo(keyInfo);

            // Use KeyInfoFormatter for proper name/email formatting
            formatter.formatUserId(nameView, emailView);
            formatter.formatCreationDate(creationView);
        }
    }

    static class DummyViewHolder extends RecyclerView.ViewHolder {
        DummyViewHolder(View itemView) {
            super(itemView);
        }
    }

    // Data classes
    abstract static class ListItem {
        abstract int getType();
    }

    static class HeaderItem extends ListItem {
        final String title;

        HeaderItem(String title) {
            this.title = title;
        }

        @Override
        int getType() {
            return VIEW_TYPE_HEADER;
        }
    }

    static class KeyItem extends ListItem {
        final UnifiedKeyInfo keyInfo;

        KeyItem(UnifiedKeyInfo keyInfo) {
            this.keyInfo = keyInfo;
        }

        @Override
        int getType() {
            return VIEW_TYPE_KEY;
        }
    }

    static class DummyItem extends ListItem {
        @Override
        int getType() {
            return VIEW_TYPE_DUMMY;
        }
    }
}