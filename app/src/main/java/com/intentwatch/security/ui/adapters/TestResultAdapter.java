package com.intentwatch.security.ui.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.intentwatch.security.R;
import com.intentwatch.security.models.TestResult;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class TestResultAdapter extends RecyclerView.Adapter<TestResultAdapter.ViewHolder> {

    private List<TestResult> items = new ArrayList<>();

    public void setItems(List<TestResult> items) {
        this.items = items != null ? items : new ArrayList<>();
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_test_result, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        TestResult item = items.get(position);
        holder.tvTestName.setText(item.getTestCaseName());
        holder.tvTestUri.setText(item.getInputUri());
        holder.tvTestOutcome.setText(item.getObservableOutcome());
        holder.tvTestBadge.setText(item.getResolutionType().replace("_", " "));

        String dateStr = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                .format(new Date(item.getExecutionTimestamp()));
        holder.tvTestTimestamp.setText("Execution Timestamp: " + dateStr);

        if ("RESOLVER_CHOOSER_DIALOG".equals(item.getResolutionType())) {
            holder.tvTestBadge.setBackgroundResource(R.drawable.bg_badge_high);
            holder.tvTestBadge.setTextColor(holder.itemView.getContext().getColor(R.color.severity_high));
        } else if ("BLOCKED_SANDBOX".equals(item.getResolutionType())) {
            holder.tvTestBadge.setBackgroundResource(R.drawable.bg_badge_critical);
            holder.tvTestBadge.setTextColor(holder.itemView.getContext().getColor(R.color.severity_critical));
        } else {
            holder.tvTestBadge.setBackgroundResource(R.drawable.bg_badge_low);
            holder.tvTestBadge.setTextColor(holder.itemView.getContext().getColor(R.color.severity_low));
        }
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvTestName, tvTestUri, tvTestOutcome, tvTestBadge, tvTestTimestamp;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            tvTestName = itemView.findViewById(R.id.tv_test_name);
            tvTestUri = itemView.findViewById(R.id.tv_test_uri);
            tvTestOutcome = itemView.findViewById(R.id.tv_test_outcome);
            tvTestBadge = itemView.findViewById(R.id.tv_test_status_badge);
            tvTestTimestamp = itemView.findViewById(R.id.tv_test_timestamp);
        }
    }
}
