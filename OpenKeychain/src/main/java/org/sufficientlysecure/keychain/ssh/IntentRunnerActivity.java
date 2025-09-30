/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
 * Copyright (C) 2024 Simone Esposito
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.ssh;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;

import org.sufficientlysecure.keychain.R;

import timber.log.Timber;

/**
 * Activity to handle PendingIntent execution for SSH agent operations
 * Ported from OkcAgent architecture
 */
public class IntentRunnerActivity extends AppCompatActivity {

    public static final String ACTION_RUN_PENDING_INTENT = "org.sufficientlysecure.keychain.action.RUN_PENDING_INTENT";
    public static final String ACTION_FINISH = "org.sufficientlysecure.keychain.action.FINISH";
    public static final String EXTRA_API_INTENT = "org.sufficientlysecure.keychain.extra.API_INTENT";
    public static final String EXTRA_CALLBACK_INTENT = "org.sufficientlysecure.keychain.extra.CALLBACK_INTENT";
    public static final String EXTRA_RESULT_INTENT = "org.sufficientlysecure.keychain.extra.RESULT_INTENT";

    private static final String TAG = "IntentRunnerActivity";

    public static class RequestsViewModel extends ViewModel {
        public Intent reqIntent = null;
    }

    private RequestsViewModel vm;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.d(TAG, "onCreate called with action: " + (getIntent() != null ? getIntent().getAction() : "null"));

        setContentView(R.layout.activity_intent_runner);

        vm = new ViewModelProvider(this).get(RequestsViewModel.class);

        Intent intent = getIntent();
        if (intent == null) {
            Log.w(TAG, "Intent is null, finishing");
            finish();
            return;
        }

        String action = intent.getAction();
        if (ACTION_RUN_PENDING_INTENT.equals(action)) {
            Log.d(TAG, "ACTION_RUN_PENDING_INTENT received");
            vm.reqIntent = intent;

            PendingIntent apiIntent = intent.getParcelableExtra(EXTRA_API_INTENT);
            if (apiIntent == null) {
                Log.e(TAG, "EXTRA_API_INTENT is null, finishing");
                finish();
                return;
            }

            try {
                Log.d(TAG, "Starting PendingIntent");
                startIntentSenderForResult(apiIntent.getIntentSender(), 0, null, 0, 0, 0);
            } catch (IntentSender.SendIntentException e) {
                Log.e(TAG, "Failed to start PendingIntent: " + e.getMessage(), e);
                Timber.e(e, "Failed to start PendingIntent");
                finish();
            }
        } else if (ACTION_FINISH.equals(action)) {
            Log.d(TAG, "ACTION_FINISH received");
            finish();
        } else {
            Log.w(TAG, "Unknown action: " + action);
            finish();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        Log.d(TAG, "onActivityResult: requestCode=" + requestCode + ", resultCode=" + resultCode + ", data=" + (data != null ? "present" : "null"));

        Intent resultIntent = (resultCode == Activity.RESULT_OK) ? data : null;

        if (vm.reqIntent != null) {
            Intent callbackIntent = vm.reqIntent.getParcelableExtra(EXTRA_CALLBACK_INTENT);
            if (callbackIntent != null) {
                callbackIntent.putExtra(EXTRA_RESULT_INTENT, resultIntent);
                Log.d(TAG, "Starting callback service with result");
                startService(callbackIntent);
            } else {
                Log.w(TAG, "EXTRA_CALLBACK_INTENT is null");
            }
            vm.reqIntent = null;
        } else {
            Log.w(TAG, "vm.reqIntent is null");
        }

        finish();
    }

    @Override
    protected void onDestroy() {
        Log.d(TAG, "onDestroy called, isChangingConfigurations=" + isChangingConfigurations());

        if (!isChangingConfigurations() && vm.reqIntent != null) {
            Log.d(TAG, "Activity destroyed without result, sending null callback");
            Intent callbackIntent = vm.reqIntent.getParcelableExtra(EXTRA_CALLBACK_INTENT);
            if (callbackIntent != null) {
                callbackIntent.putExtra(EXTRA_RESULT_INTENT, (Intent) null);
                startService(callbackIntent);
            }
        }

        super.onDestroy();
    }
}