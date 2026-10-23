package com.intentwatch.security.ui.fragments;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.intentwatch.security.R;
import com.intentwatch.security.database.DatabaseHelper;
import com.intentwatch.security.models.SecurityFinding;
import com.intentwatch.security.ui.adapters.FindingAdapter;

import java.util.List;

public class FindingsFragment extends Fragment {

    private TextView tvCriticalCount, tvHighCount, tvResolvedCount, tvEmpty;
    private RecyclerView recyclerFindings;
    private FindingAdapter adapter;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_findings, container, false);

        tvCriticalCount = view.findViewById(R.id.tv_badge_critical_count);
        tvHighCount = view.findViewById(R.id.tv_badge_high_count);
        tvResolvedCount = view.findViewById(R.id.tv_badge_resolved_count);
        tvEmpty = view.findViewById(R.id.tv_findings_empty);
        recyclerFindings = view.findViewById(R.id.recycler_findings);

        recyclerFindings.setLayoutManager(new LinearLayoutManager(getContext()));
        adapter = new FindingAdapter();
        recyclerFindings.setAdapter(adapter);

        adapter.setOnFindingActionListener(new FindingAdapter.OnFindingActionListener() {
            @Override
            public void onFindingClick(SecurityFinding finding) {
                showFindingDetail(finding);
            }

            @Override
            public void onToggleStatus(SecurityFinding finding) {
                toggleFindingStatus(finding);
            }
        });

        loadFindings();
        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        loadFindings();
    }

    private void loadFindings() {
        if (getContext() == null) return;
        DatabaseHelper db = DatabaseHelper.getInstance(getContext());
        List<SecurityFinding> findings = db.getAllSecurityFindings();

        long crit = findings.stream().filter(f -> "CRITICAL".equalsIgnoreCase(f.getSeverity())).count();
        long high = findings.stream().filter(f -> "HIGH".equalsIgnoreCase(f.getSeverity())).count();
        long res = findings.stream().filter(f -> "RESOLVED".equalsIgnoreCase(f.getVerificationStatus())).count();

        tvCriticalCount.setText(crit + " Critical");
        tvHighCount.setText(high + " High");
        tvResolvedCount.setText(res + " Resolved");

        adapter.setItems(findings);

        if (findings.isEmpty()) {
            tvEmpty.setVisibility(View.VISIBLE);
            recyclerFindings.setVisibility(View.GONE);
        } else {
            tvEmpty.setVisibility(View.GONE);
            recyclerFindings.setVisibility(View.VISIBLE);
        }
    }

    private void toggleFindingStatus(SecurityFinding finding) {
        if (getContext() == null) return;
        String newStatus = "RESOLVED".equalsIgnoreCase(finding.getVerificationStatus()) ? "CONFIRMED" : "RESOLVED";
        DatabaseHelper.getInstance(getContext()).updateFindingStatus(finding.getId(), newStatus);
        finding.setVerificationStatus(newStatus);
        loadFindings();
        Toast.makeText(getContext(), "Status updated to: " + newStatus, Toast.LENGTH_SHORT).show();
    }

    private void showFindingDetail(SecurityFinding f) {
        if (getContext() == null) return;
        new AlertDialog.Builder(getContext())
                .setTitle("[" + f.getId() + "] " + f.getTitle())
                .setMessage("Severity: " + f.getSeverity() + " (Score " + f.getRiskScore() + "/100)\n" +
                        "Confidence: " + f.getConfidence() + " | Status: " + f.getVerificationStatus() + "\n" +
                        "Affected Component: " + f.getAffectedComponent() + "\n" +
                        "Package: " + f.getPackageName() + "\n\n" +
                        "Description:\n" + f.getDescription() + "\n\n" +
                        "Reproduction Instructions:\n" + f.getReproductionInstructions() + "\n\n" +
                        "Remediation Guidance:\n" + f.getRemediationGuidance())
                .setPositiveButton("Close", null)
                .show();
    }
}
