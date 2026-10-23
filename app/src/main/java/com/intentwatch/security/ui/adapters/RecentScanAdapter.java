package com.intentwatch.security.ui.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.intentwatch.security.R;
import com.intentwatch.security.models.ScanSession;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class RecentScanAdapter extends RecyclerView.Adapter<RecentScanAdapter.ViewHolder> {

    private List<ScanSession> items = new ArrayList<>();

    public void setItems(List<ScanSession> items) {
        this.items = items != null ? items : new ArrayList<>();
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_recent_scan, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        ScanSession item = items.get(position);
        holder.tvTarget.setText(item.getTargetName());

        String dateStr = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
                .format(new Date(item.getTimestamp()));
        holder.tvDate.setText(dateStr + " (" + item.getScanType().replace("_", " ") + ")");

        holder.tvSummary.setText(item.getTotalHandlers() + " Handlers | " +
                item.getCollisionCount() + " Collisions | " + item.getCriticalFindingsCount() + " Crit");
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvTarget, tvDate, tvSummary;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            tvTarget = itemView.findViewById(R.id.tv_scan_target);
            tvDate = itemView.findViewById(R.id.tv_scan_date);
            tvSummary = itemView.findViewById(R.id.tv_scan_handlers_summary);
        }
    }
}
