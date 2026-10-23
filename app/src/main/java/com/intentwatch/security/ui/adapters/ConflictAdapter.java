package com.intentwatch.security.ui.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.intentwatch.security.R;
import com.intentwatch.security.models.SchemeConflict;

import java.util.ArrayList;
import java.util.List;

public class ConflictAdapter extends RecyclerView.Adapter<ConflictAdapter.ViewHolder> {

    public interface OnItemClickListener {
        void onItemClick(SchemeConflict conflict);
    }

    private List<SchemeConflict> items = new ArrayList<>();
    private OnItemClickListener listener;

    public void setItems(List<SchemeConflict> items) {
        this.items = items != null ? items : new ArrayList<>();
        notifyDataSetChanged();
    }

    public void setOnItemClickListener(OnItemClickListener listener) {
        this.listener = listener;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_conflict, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        SchemeConflict item = items.get(position);
        holder.tvScheme.setText(item.getScheme() + "://");
        holder.tvSeverity.setText(item.getSeverity() + " (" + item.getRiskScore() + "/100)");

        if ("CRITICAL".equalsIgnoreCase(item.getSeverity())) {
            holder.tvSeverity.setBackgroundResource(R.drawable.bg_badge_critical);
            holder.tvSeverity.setTextColor(holder.itemView.getContext().getColor(R.color.severity_critical));
        } else if ("HIGH".equalsIgnoreCase(item.getSeverity())) {
            holder.tvSeverity.setBackgroundResource(R.drawable.bg_badge_high);
            holder.tvSeverity.setTextColor(holder.itemView.getContext().getColor(R.color.severity_high));
        } else {
            holder.tvSeverity.setBackgroundResource(R.drawable.bg_badge_moderate);
            holder.tvSeverity.setTextColor(holder.itemView.getContext().getColor(R.color.severity_moderate));
        }

        holder.tvHandlersCount.setText(item.getHandlerCount() + " Handlers Competing (Ambiguity Identified)");
        holder.tvApps.setText("Competing Applications: " + item.getAppsSummary());
        holder.tvDescription.setText(item.getDescription());
        holder.tvRemediation.setText("Remediation: " + item.getRemediation());

        holder.itemView.setOnClickListener(v -> {
            if (listener != null) listener.onItemClick(item);
        });
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvScheme, tvSeverity, tvHandlersCount, tvApps, tvDescription, tvRemediation;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            tvScheme = itemView.findViewById(R.id.tv_conflict_scheme);
            tvSeverity = itemView.findViewById(R.id.tv_conflict_severity);
            tvHandlersCount = itemView.findViewById(R.id.tv_conflict_handlers_count);
            tvApps = itemView.findViewById(R.id.tv_conflict_apps);
            tvDescription = itemView.findViewById(R.id.tv_conflict_description);
            tvRemediation = itemView.findViewById(R.id.tv_conflict_remediation);
        }
    }
}
