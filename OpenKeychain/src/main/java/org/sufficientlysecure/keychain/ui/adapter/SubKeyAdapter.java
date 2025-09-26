package org.sufficientlysecure.keychain.ui.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import org.sufficientlysecure.keychain.Keys;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.service.SaveKeyringParcel.SubkeyAdd;
import org.sufficientlysecure.keychain.ui.SubKeyItem.SubkeyViewHolder;
import org.sufficientlysecure.keychain.ui.ViewKeyAdvSubkeysFragment.SubkeyEditViewModel;

import java.util.ArrayList;
import java.util.List;

public class SubKeyAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    private static final int VIEW_TYPE_DETAIL = 0;
    private static final int VIEW_TYPE_ADDED = 1;

    private List<Object> items = new ArrayList<>();
    private SubkeyEditViewModel viewModel;
    private OnItemClickListener clickListener;

    public interface OnItemClickListener {
        boolean onItemClick(int position);
    }

    public SubKeyAdapter(SubkeyEditViewModel viewModel) {
        this.viewModel = viewModel;
    }

    public void setOnItemClickListener(OnItemClickListener listener) {
        this.clickListener = listener;
    }

    public void setSubKeys(List<Keys> subKeys) {
        items.clear();
        if (subKeys != null) {
            items.addAll(subKeys);
        }
        notifyDataSetChanged();
    }

    public void addSubkeyAdd(SubkeyAdd subkeyAdd) {
        items.add(subkeyAdd);
        notifyItemInserted(items.size() - 1);
    }

    public void removeItem(int position) {
        if (position >= 0 && position < items.size()) {
            items.remove(position);
            notifyItemRemoved(position);
        }
    }

    public List<Object> getAllItems() {
        return new ArrayList<>(items);
    }

    @Override
    public int getItemViewType(int position) {
        Object item = items.get(position);
        if (item instanceof Keys) {
            return VIEW_TYPE_DETAIL;
        } else if (item instanceof SubkeyAdd) {
            return VIEW_TYPE_ADDED;
        }
        throw new IllegalArgumentException("Unknown item type: " + item.getClass());
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
        View view = inflater.inflate(R.layout.view_key_adv_subkey_item, parent, false);
        return new SubkeyViewHolder(view, this);
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        Object item = items.get(position);
        SubkeyViewHolder subkeyHolder = (SubkeyViewHolder) holder;

        if (item instanceof Keys) {
            Keys subkeyInfo = (Keys) item;
            subkeyHolder.bind(subkeyInfo);
            subkeyHolder.bindSubkeyAction(subkeyInfo, viewModel.skpBuilder);
        } else if (item instanceof SubkeyAdd) {
            SubkeyAdd subkeyAdd = (SubkeyAdd) item;
            subkeyHolder.bindSubkeyAdd(subkeyAdd, viewModel);
            // Override the action to properly remove from adapter
            subkeyHolder.bindSubkeyAction(R.string.subkey_action_create, v -> {
                viewModel.skpBuilder.getMutableAddSubKeys().remove(subkeyAdd);
                removeItem(position);
            });
        }

        holder.itemView.setOnClickListener(v -> {
            if (clickListener != null) {
                clickListener.onItemClick(position);
            }
        });
    }

    @Override
    public int getItemCount() {
        return items.size();
    }
}