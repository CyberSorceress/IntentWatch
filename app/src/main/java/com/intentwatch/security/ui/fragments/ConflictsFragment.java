package com.intentwatch.security.ui.fragments;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.intentwatch.security.R;
import com.intentwatch.security.database.DatabaseHelper;
import com.intentwatch.security.models.SchemeConflict;
import com.intentwatch.security.ui.adapters.ConflictAdapter;

import java.util.List;
import java.util.Map;

public class ConflictsFragment extends Fragment {

    private TextView tvCollisions, tvOverlapping, tvExportedUnprotected, tvEmpty;
    private RecyclerView recyclerConflicts;
    private ConflictAdapter adapter;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_scheme_conflict, container, false);

        tvCollisions = view.findViewById(R.id.tv_stat_collisions);
        tvOverlapping = view.findViewById(R.id.tv_stat_overlapping);
        tvExportedUnprotected = view.findViewById(R.id.tv_stat_exported_unprotected);
        tvEmpty = view.findViewById(R.id.tv_conflicts_empty);
        recyclerConflicts = view.findViewById(R.id.recycler_conflicts);

        recyclerConflicts.setLayoutManager(new LinearLayoutManager(getContext()));
        adapter = new ConflictAdapter();
        recyclerConflicts.setAdapter(adapter);

        adapter.setOnItemClickListener(this::showConflictDetailsDialog);

        loadConflicts();
        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        loadConflicts();
    }

    private void loadConflicts() {
        if (getContext() == null) return;
        DatabaseHelper db = DatabaseHelper.getInstance(getContext());
        List<SchemeConflict> conflicts = db.getAllSchemeConflicts();
        Map<String, Integer> stats = db.getStatistics();

        tvCollisions.setText(String.valueOf(conflicts.size()));
        tvOverlapping.setText(String.valueOf(conflicts.stream().filter(c -> "PATH_AMBIGUITY".equals(c.getConflictType()) || c.getRiskScore() >= 60).count()));
        tvExportedUnprotected.setText(String.valueOf(stats.getOrDefault("exported_count", 0)));

        adapter.setItems(conflicts);

        if (conflicts.isEmpty()) {
            tvEmpty.setVisibility(View.VISIBLE);
            recyclerConflicts.setVisibility(View.GONE);
        } else {
            tvEmpty.setVisibility(View.GONE);
            recyclerConflicts.setVisibility(View.VISIBLE);
        }
    }

    private void showConflictDetailsDialog(SchemeConflict item) {
        if (getContext() == null) return;
        new AlertDialog.Builder(getContext())
                .setTitle("Collision: " + item.getScheme() + "://")
                .setMessage("Conflict Type: " + item.getConflictType() + "\n" +
                        "Severity: " + item.getSeverity() + " (Score " + item.getRiskScore() + "/100)\n" +
                        "Confidence: " + item.getConfidence() + "\n\n" +
                        "Competing Applications (" + item.getHandlerCount() + "):\n" +
                        item.getAppsSummary() + "\n\n" +
                        "Description:\n" + item.getDescription() + "\n\n" +
                        "Recommended Remediation:\n" + item.getRemediation())
                .setPositiveButton("Close", null)
                .show();
    }
}
