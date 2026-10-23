package com.intentwatch.security.ui.fragments;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.intentwatch.security.R;
import com.intentwatch.security.database.DatabaseHelper;
import com.intentwatch.security.models.TestCase;
import com.intentwatch.security.models.TestResult;
import com.intentwatch.security.testing.DeepLinkFuzzer;
import com.intentwatch.security.testing.SafeTestExecutor;
import com.intentwatch.security.ui.adapters.TestResultAdapter;
import com.intentwatch.security.ui.dialogs.SafeExecutionDialog;
import com.intentwatch.security.ui.webview.SafeWebViewActivity;

import java.util.ArrayList;
import java.util.List;

public class TestLabFragment extends Fragment {

    private EditText etTestUri;
    private Spinner spinnerPresets;
    private TextView tvPresetDesc, tvOutcomeText, tvTargetsText, tvEmptyHistory;
    private CardView cardLatestOutcome;
    private MaterialButton btnSafeResolve, btnLaunchIntent, btnOpenWebview;
    private RecyclerView recyclerTestHistory;
    private TestResultAdapter historyAdapter;

    private List<TestCase> activeTestCases = new ArrayList<>();
    private TestCase selectedTestCase;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_testlab, container, false);

        etTestUri = view.findViewById(R.id.et_test_uri);
        spinnerPresets = view.findViewById(R.id.spinner_fuzz_presets);
        tvPresetDesc = view.findViewById(R.id.tv_preset_description);
        tvOutcomeText = view.findViewById(R.id.tv_latest_outcome_text);
        tvTargetsText = view.findViewById(R.id.tv_latest_targets_text);
        tvEmptyHistory = view.findViewById(R.id.tv_empty_history);
        cardLatestOutcome = view.findViewById(R.id.card_latest_outcome);
        btnSafeResolve = view.findViewById(R.id.btn_safe_resolve);
        btnLaunchIntent = view.findViewById(R.id.btn_launch_intent);
        btnOpenWebview = view.findViewById(R.id.btn_open_webview_sandbox);
        recyclerTestHistory = view.findViewById(R.id.recycler_test_history);

        recyclerTestHistory.setLayoutManager(new LinearLayoutManager(getContext()));
        historyAdapter = new TestResultAdapter();
        recyclerTestHistory.setAdapter(historyAdapter);

        setupPresets();

        btnSafeResolve.setOnClickListener(v -> performSafeSimulation());
        btnLaunchIntent.setOnClickListener(v -> showSafeLaunchDialog());
        btnOpenWebview.setOnClickListener(v -> openSandboxedWebview());

        loadHistory();
        return view;
    }

    private void setupPresets() {
        if (getContext() == null) return;
        String baseline = etTestUri.getText().toString().trim();
        activeTestCases = DeepLinkFuzzer.generateFuzzTestCases(baseline);

        List<String> names = new ArrayList<>();
        for (TestCase tc : activeTestCases) {
            names.add(tc.getName() + " (" + tc.getCategory() + ")");
        }

        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                getContext(),
                android.R.layout.simple_spinner_dropdown_item,
                names
        );
        spinnerPresets.setAdapter(adapter);

        spinnerPresets.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (position >= 0 && position < activeTestCases.size()) {
                    selectedTestCase = activeTestCases.get(position);
                    etTestUri.setText(selectedTestCase.getModifiedUri());
                    tvPresetDesc.setText(selectedTestCase.getDescription());
                }
            }
            @Override public void onNothingSelected(AdapterView<?> parent) {}
        });

        if (!activeTestCases.isEmpty()) {
            selectedTestCase = activeTestCases.get(0);
        }
    }

    private void performSafeSimulation() {
        if (getContext() == null || selectedTestCase == null) return;
        selectedTestCase.setModifiedUri(etTestUri.getText().toString().trim());

        TestResult res = SafeTestExecutor.queryResolutionSimulated(getContext(), selectedTestCase);
        displayOutcome(res);
        loadHistory();
    }

    private void showSafeLaunchDialog() {
        if (getContext() == null || selectedTestCase == null) return;
        selectedTestCase.setModifiedUri(etTestUri.getText().toString().trim());

        SafeExecutionDialog dialog = new SafeExecutionDialog(
                getContext(),
                selectedTestCase.getModifiedUri(),
                new SafeExecutionDialog.OnDialogActionListener() {
                    @Override
                    public void onSimulateQuery() {
                        performSafeSimulation();
                    }

                    @Override
                    public void onConfirmLaunch() {
                        TestResult res = SafeTestExecutor.executeLiveLaunch(getContext(), selectedTestCase, false);
                        displayOutcome(res);
                        loadHistory();
                    }
                }
        );
        dialog.show();
    }

    private void openSandboxedWebview() {
        if (getContext() == null) return;
        String uriStr = etTestUri.getText().toString().trim();
        Intent intent = new Intent(getContext(), SafeWebViewActivity.class);
        intent.putExtra("TARGET_URL", uriStr);
        startActivity(intent);
    }

    private void displayOutcome(TestResult res) {
        cardLatestOutcome.setVisibility(View.VISIBLE);
        tvOutcomeText.setText("Resolution: " + res.getResolutionType() + " | " + res.getObservableOutcome());
        if (res.getResolvedTargets() != null && !res.getResolvedTargets().isEmpty()) {
            tvTargetsText.setText("Matching Handlers (" + res.getTargetCount() + "):\n" +
                    String.join("\n", res.getResolvedTargets()));
        } else {
            tvTargetsText.setText(res.getExceptionDetails() != null && !res.getExceptionDetails().isEmpty() ?
                    res.getExceptionDetails() : "No active activities resolved on this device.");
        }
    }

    private void loadHistory() {
        if (getContext() == null) return;
        DatabaseHelper db = DatabaseHelper.getInstance(getContext());
        List<TestResult> results = db.getAllTestResults();
        historyAdapter.setItems(results);

        if (results.isEmpty()) {
            tvEmptyHistory.setVisibility(View.VISIBLE);
            recyclerTestHistory.setVisibility(View.GONE);
        } else {
            tvEmptyHistory.setVisibility(View.GONE);
            recyclerTestHistory.setVisibility(View.VISIBLE);
        }
    }
}
