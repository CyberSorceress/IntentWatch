package com.intentwatch.security.ui;

import android.os.Bundle;
import android.view.MenuItem;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.intentwatch.security.R;
import com.intentwatch.security.ui.fragments.ConflictsFragment;
import com.intentwatch.security.ui.fragments.DashboardFragment;
import com.intentwatch.security.ui.fragments.FindingsFragment;
import com.intentwatch.security.ui.fragments.ReportsFragment;
import com.intentwatch.security.ui.fragments.ScannerFragment;
import com.intentwatch.security.ui.fragments.SettingsFragment;
import com.intentwatch.security.ui.fragments.TestLabFragment;

public class MainActivity extends AppCompatActivity {

    private BottomNavigationView bottomNav;
    private Toolbar toolbar;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        toolbar = findViewById(R.id.main_toolbar);
        setSupportActionBar(toolbar);

        bottomNav = findViewById(R.id.bottom_navigation);

        bottomNav.setOnItemSelectedListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.nav_dashboard) {
                replaceFragment(new DashboardFragment(), "Dashboard");
                return true;
            } else if (itemId == R.id.nav_scanner) {
                replaceFragment(new ScannerFragment(), "Deep-Link Scanner");
                return true;
            } else if (itemId == R.id.nav_conflicts) {
                replaceFragment(new ConflictsFragment(), "Scheme Conflicts");
                return true;
            } else if (itemId == R.id.nav_testlab) {
                replaceFragment(new TestLabFragment(), "Test Lab & Fuzzer");
                return true;
            } else if (itemId == R.id.nav_reports) {
                replaceFragment(new ReportsFragment(), "Audit Reports");
                return true;
            }
            return false;
        });

        toolbar.setOnMenuItemClickListener(this::onToolbarMenuItemClick);

        if (savedInstanceState == null) {
            replaceFragment(new DashboardFragment(), "Dashboard");
        }
    }

    private boolean onToolbarMenuItemClick(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_findings) {
            replaceFragment(new FindingsFragment(), "Security Findings");
            return true;
        } else if (id == R.id.action_about) {
            replaceFragment(new SettingsFragment(), "About IntentWatch");
            return true;
        }
        return false;
    }

    public void replaceFragment(Fragment fragment, String title) {
        FragmentManager fm = getSupportFragmentManager();
        fm.beginTransaction()
                .replace(R.id.fragment_container, fragment)
                .commit();
        if (toolbar != null) {
            toolbar.setSubtitle(title);
        }
    }
}
