package com.intentwatch.security.ui.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.intentwatch.security.R;
import com.intentwatch.security.models.DiscoveredDeepLink;

import java.util.ArrayList;
import java.util.List;

public class DeepLinkAdapter extends RecyclerView.Adapter<DeepLinkAdapter.ViewHolder> {

    public interface OnItemClickListener {
        void onItemClick(DiscoveredDeepLink item);
    }

    private List<DiscoveredDeepLink> items = new ArrayList<>();
    private OnItemClickListener listener;

    public void setItems(List<DiscoveredDeepLink> items) {
        this.items = items != null ? items : new ArrayList<>();
        notifyDataSetChanged();
    }

    public void setOnItemClickListener(OnItemClickListener listener) {
        this.listener = listener;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_deeplink, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        DiscoveredDeepLink item = items.get(position);
        holder.tvAppName.setText(item.getAppName());
        holder.tvPackageName.setText(item.getPackageName());
        holder.tvUriPattern.setText(item.getDisplayUriPattern());
        holder.tvActivityName.setText(item.getActivityName());

        holder.tvRiskBadge.setText("RISK: " + item.getRiskScore());
        if (item.getRiskScore() >= 75) {
            holder.tvRiskBadge.setBackgroundResource(R.drawable.bg_badge_critical);
            holder.tvRiskBadge.setTextColor(holder.itemView.getContext().getColor(R.color.severity_critical));
        } else if (item.getRiskScore() >= 50) {
            holder.tvRiskBadge.setBackgroundResource(R.drawable.bg_badge_high);
            holder.tvRiskBadge.setTextColor(holder.itemView.getContext().getColor(R.color.severity_high));
        } else if (item.getRiskScore() >= 25) {
            holder.tvRiskBadge.setBackgroundResource(R.drawable.bg_badge_moderate);
            holder.tvRiskBadge.setTextColor(holder.itemView.getContext().getColor(R.color.severity_moderate));
        } else {
            holder.tvRiskBadge.setBackgroundResource(R.drawable.bg_badge_low);
            holder.tvRiskBadge.setTextColor(holder.itemView.getContext().getColor(R.color.severity_low));
        }

        holder.tvExportedBadge.setVisibility(item.isExported() ? View.VISIBLE : View.GONE);
        holder.tvSourceBadge.setText(item.getDiscoverySource().replace("_", " "));

        holder.itemView.setOnClickListener(v -> {
            if (listener != null) listener.onItemClick(item);
        });
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvAppName, tvPackageName, tvUriPattern, tvActivityName;
        TextView tvRiskBadge, tvExportedBadge, tvSourceBadge;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            tvAppName = itemView.findViewById(R.id.tv_app_name);
            tvPackageName = itemView.findViewById(R.id.tv_package_name);
            tvUriPattern = itemView.findViewById(R.id.tv_uri_pattern);
            tvActivityName = itemView.findViewById(R.id.tv_activity_name);
            tvRiskBadge = itemView.findViewById(R.id.tv_risk_badge);
            tvExportedBadge = itemView.findViewById(R.id.tv_exported_badge);
            tvSourceBadge = itemView.findViewById(R.id.tv_source_badge);
        }
    }
}
