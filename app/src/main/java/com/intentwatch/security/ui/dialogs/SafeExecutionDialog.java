package com.intentwatch.security.ui.dialogs;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.view.Window;
import android.widget.TextView;

import androidx.annotation.NonNull;

import com.google.android.material.button.MaterialButton;
import com.intentwatch.security.R;

public class SafeExecutionDialog extends Dialog {

    public interface OnDialogActionListener {
        void onSimulateQuery();
        void onConfirmLaunch();
    }

    private final String uriString;
    private final OnDialogActionListener listener;

    public SafeExecutionDialog(@NonNull Context context, String uriString, OnDialogActionListener listener) {
        super(context);
        this.uriString = uriString;
        this.listener = listener;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.dialog_safe_execution);

        if (getWindow() != null) {
            getWindow().setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        }

        TextView tvUri = findViewById(R.id.tv_dialog_uri);
        MaterialButton btnCancel = findViewById(R.id.btn_dialog_cancel);
        MaterialButton btnSimulate = findViewById(R.id.btn_dialog_simulate);
        MaterialButton btnConfirm = findViewById(R.id.btn_dialog_confirm);

        tvUri.setText(uriString);

        btnCancel.setOnClickListener(v -> dismiss());

        btnSimulate.setOnClickListener(v -> {
            dismiss();
            if (listener != null) listener.onSimulateQuery();
        });

        btnConfirm.setOnClickListener(v -> {
            dismiss();
            if (listener != null) listener.onConfirmLaunch();
        });
    }
}
