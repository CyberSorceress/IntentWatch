package com.intentwatch.security.ui.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.intentwatch.security.R;
import com.intentwatch.security.models.SecurityFinding;

import java.util.ArrayList;
import java.util.List;

public class FindingAdapter extends RecyclerView.Adapter<FindingAdapter.ViewHolder> {

    public interface OnFindingActionListener {
        void onFindingClick(SecurityFinding finding);
        void onToggleStatus(SecurityFinding finding);
    }

    private List<SecurityFinding> items = new ArrayList<>();
    private OnFindingActionListener listener;

    public void setItems(List<SecurityFinding> items) {
        this.items = items != null ? items : new ArrayList<>();
        notifyDataSetChanged();
    }

    public void setOnFindingActionListener(OnFindingActionListener listener) {
        this.listener = listener;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_finding, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        SecurityFinding item = items.get(position);
        holder.tvId.setText(item.getId());
        holder.tvTitle.setText(item.getTitle());
        holder.tvComponent.setText("Component: " + item.getAffectedComponent());
        holder.tvDescription.setText(item.getDescription());
        holder.tvEvidence.setText("Evidence: " + item.getEvidenceSource());

        holder.tvSeverity.setText(item.getSeverity());
        if ("CRITICAL".equalsIgnoreCase(item.getSeverity())) {
            holder.tvSeverity.setBackgroundResource(R.drawable.bg_badge_critical);
            holder.tvSeverity.setTextColor(holder.itemView.getContext().getColor(R.color.severity_critical));
        } else if ("HIGH".equalsIgnoreCase(item.getSeverity())) {
            holder.tvSeverity.setBackgroundResource(R.drawable.bg_badge_high);
            holder.tvSeverity.setTextColor(holder.itemView.getContext().getColor(R.color.severity_high));
        } else if ("MODERATE".equalsIgnoreCase(item.getSeverity())) {
            holder.tvSeverity.setBackgroundResource(R.drawable.bg_badge_moderate);
            holder.tvSeverity.setTextColor(holder.itemView.getContext().getColor(R.color.severity_moderate));
        } else {
            holder.tvSeverity.setBackgroundResource(R.drawable.bg_badge_low);
            holder.tvSeverity.setTextColor(holder.itemView.getContext().getColor(R.color.severity_low));
        }

        holder.tvStatus.setText(item.getVerificationStatus());
        if ("RESOLVED".equalsIgnoreCase(item.getVerificationStatus())) {
            holder.tvStatus.setBackgroundResource(R.drawable.bg_badge_low);
            holder.tvStatus.setTextColor(holder.itemView.getContext().getColor(R.color.severity_low));
            holder.tvActionToggle.setText("REOPEN");
        } else {
            holder.tvStatus.setBackgroundResource(R.drawable.bg_badge_high);
            holder.tvStatus.setTextColor(holder.itemView.getContext().getColor(R.color.severity_high));
            holder.tvActionToggle.setText("RESOLVE");
        }

        holder.itemView.setOnClickListener(v -> {
            if (listener != null) listener.onFindingClick(item);
        });

        holder.tvActionToggle.setOnClickListener(v -> {
            if (listener != null) listener.onToggleStatus(item);
        });
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvId, tvTitle, tvComponent, tvDescription, tvEvidence, tvSeverity, tvStatus, tvActionToggle;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            tvId = itemView.findViewById(R.id.tv_finding_id);
            tvTitle = itemView.findViewById(R.id.tv_finding_title);
            tvComponent = itemView.findViewById(R.id.tv_finding_component);
            tvDescription = itemView.findViewById(R.id.tv_finding_description);
            tvEvidence = itemView.findViewById(R.id.tv_finding_evidence);
            tvSeverity = itemView.findViewById(R.id.tv_finding_severity);
            tvStatus = itemView.findViewById(R.id.tv_finding_status);
            tvActionToggle = itemView.findViewById(R.id.tv_finding_action_toggle);
        }
    }
}
