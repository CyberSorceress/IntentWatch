package com.intentwatch.security.ui.fragments;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;

import com.google.android.material.button.MaterialButton;
import com.intentwatch.security.R;
import com.intentwatch.security.database.DatabaseHelper;

public class SettingsFragment extends Fragment {

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_settings, container, false);

        MaterialButton btnClear = view.findViewById(R.id.btn_clear_database);
        btnClear.setOnClickListener(v -> confirmClearData());

        return view;
    }

    private void confirmClearData() {
        if (getContext() == null) return;
        new AlertDialog.Builder(getContext())
                .setTitle("Reset Audit Database?")
                .setMessage("This will remove all cataloged deep-link handlers, conflict findings, and test results from the local device storage.")
                .setPositiveButton("Reset Data", (dialog, which) -> {
                    DatabaseHelper.getInstance(getContext()).clearAllData();
                    Toast.makeText(getContext(), "Audit database cleared successfully.", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }
}
