/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
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

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import org.sufficientlysecure.keychain.R;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import android.util.Log;
import timber.log.Timber;

/**
 * Base class for agent services (SSH, GPG) - ported from OkcAgent architecture
 */
public abstract class AgentService extends Service {

    public static final String ACTION_RUN_AGENT = "org.sufficientlysecure.keychain.action.RUN_AGENT";
    public static final String EXTRA_PROXY_PORT = "org.sufficientlysecure.keychain.extra.PROXY_PORT";

    private static final int RESULT_CODE_ERROR = 0;
    private static final int RESULT_CODE_SUCCESS = 1;
    private static final int RESULT_CODE_USER_INTERACTION_REQUIRED = 2;
    private static final String ACTION_RESULT_CALLBACK = "org.sufficientlysecure.keychain.action.RESULT_CALLBACK";
    private static final String ACTION_TERMINATE_SERVICE = "org.sufficientlysecure.keychain.action.TERMINATE_SERVICE";
    private static final String EXTRA_RESULT_CODE = "result_code";
    private static final String EXTRA_PENDING_INTENT = "intent";

    public static final Object lockObj = new Object();

    private static class NullableIntentHolder {
        public final Intent intent;

        public NullableIntentHolder(Intent intent) {
            this.intent = intent;
        }
    }

    private static class ThreadContext {
        public final Thread thread;
        public final ArrayBlockingQueue<NullableIntentHolder> queue;

        public ThreadContext(Thread thread, ArrayBlockingQueue<NullableIntentHolder> queue) {
            this.thread = thread;
            this.queue = queue;
        }
    }

    public static class StreamStatus {
        public Exception exception;

        public StreamStatus(Exception exception) {
            this.exception = exception;
        }
    }

    private final ConcurrentHashMap<Integer, ThreadContext> threadMap = new ConcurrentHashMap<>();
    private final AtomicBoolean exited = new AtomicBoolean(false);

    private void checkServiceExit() {
        if (threadMap.isEmpty()) {
            Log.d("AGENT_SERVICE", "checkServiceExit: No active threads, stopping service");
            stopSelf();
        } else {
            Log.d("AGENT_SERVICE", "checkServiceExit: " + threadMap.size() + " active threads remaining");
        }
    }

    protected void checkThreadExit(int port) {
        if (!Thread.currentThread().isInterrupted()) {
            new Handler(Looper.getMainLooper()).post(() -> {
                threadMap.remove(port);
                if (!exited.get()) {
                    checkServiceExit();
                }
            });
        }
    }

    protected abstract String getErrorMessage(Intent intent);

    protected abstract void runAgent(int port, Intent intent);

    protected Intent callApi(ApiExecutor executeApi, Intent req, int port, StreamStatus stat) {
        Log.d("AGENT_SERVICE", "Calling API for port " + port + ", action: " + (req != null ? req.getAction() : "null"));
        Intent reqIntent = req;
        while (true) {
            synchronized (lockObj) {
                Log.d("AGENT_SERVICE", "Executing API call...");
                Intent resIntent = executeApi.executeApi(reqIntent);
                if (resIntent == null) {
                    Log.e("AGENT_SERVICE", "API call returned null intent");
                    Utils.showError(this, getString(R.string.error_api_not_accessible));
                    return null;
                }

                if (stat != null && stat.exception != null) {
                    Log.e("AGENT_SERVICE", "Stream status exception: " + stat.exception.getMessage(), stat.exception);
                    throw new RuntimeException(stat.exception);
                }

                int resultCode = resIntent.getIntExtra(EXTRA_RESULT_CODE, RESULT_CODE_ERROR);
                Log.d("AGENT_SERVICE", "API call result code: " + resultCode);
                switch (resultCode) {
                    case RESULT_CODE_SUCCESS:
                        Log.d("AGENT_SERVICE", "API call successful");
                        return resIntent;
                    case RESULT_CODE_USER_INTERACTION_REQUIRED:
                        Log.d("AGENT_SERVICE", "User interaction required, launching IntentRunnerActivity");
                        Timber.d("User interaction required");

                        // Create intent to launch IntentRunnerActivity
                        Intent runnerIntent = new Intent(this, IntentRunnerActivity.class);
                        runnerIntent.setAction(IntentRunnerActivity.ACTION_RUN_PENDING_INTENT);
                        runnerIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        PendingIntent pendingIntent = resIntent.getParcelableExtra(EXTRA_PENDING_INTENT);
                        runnerIntent.putExtra(IntentRunnerActivity.EXTRA_API_INTENT, pendingIntent);

                        // Create callback intent for result
                        Intent callbackIntent = new Intent(this, this.getClass());
                        callbackIntent.setAction(ACTION_RESULT_CALLBACK);
                        callbackIntent.putExtra(EXTRA_PROXY_PORT, port);
                        runnerIntent.putExtra(IntentRunnerActivity.EXTRA_CALLBACK_INTENT, callbackIntent);

                        // On Android 10+, show notification instead of directly starting activity
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            Log.d("AGENT_SERVICE", "Android 10+, showing notification for user interaction");
                            PendingIntent pi = PendingIntent.getActivity(
                                this,
                                port,
                                runnerIntent,
                                PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE : 0)
                            );

                            android.app.Notification notification = new NotificationCompat.Builder(this, "ssh_auth_channel")
                                .setPriority(NotificationCompat.PRIORITY_HIGH)
                                .setSmallIcon(R.drawable.ic_launcher_foreground)
                                .setContentTitle(getString(R.string.notification_ssh_auth_title))
                                .setContentText(getString(R.string.notification_ssh_auth_content))
                                .setStyle(new NotificationCompat.BigTextStyle()
                                    .bigText(getString(R.string.notification_ssh_auth_content)))
                                .setAutoCancel(true)
                                .setOngoing(true)
                                .setContentIntent(pi)
                                .build();

                            NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
                            notificationManager.notify(port, notification);
                        } else {
                            Log.d("AGENT_SERVICE", "Starting IntentRunnerActivity directly");
                            startActivity(runnerIntent);
                        }

                        // Wait for the result from IntentRunnerActivity callback
                        Log.d("AGENT_SERVICE", "Waiting for user interaction result from queue...");
                        ThreadContext ctx = threadMap.get(port);
                        if (ctx == null) {
                            Log.e("AGENT_SERVICE", "No thread context found for port " + port);
                            return null;
                        }

                        try {
                            NullableIntentHolder holder = ctx.queue.take();
                            reqIntent = holder.intent;
                            if (reqIntent == null) {
                                Log.w("AGENT_SERVICE", "User interaction cancelled or failed");
                                return null;
                            }
                            Log.d("AGENT_SERVICE", "Got result from user interaction, retrying API call");
                            // Continue the while loop to retry with the new intent
                        } catch (InterruptedException e) {
                            Log.e("AGENT_SERVICE", "Interrupted while waiting for user interaction", e);
                            Thread.currentThread().interrupt();
                            return null;
                        }
                        break;

                    case RESULT_CODE_ERROR:
                        String errorMsg = getErrorMessage(resIntent);
                        Log.e("AGENT_SERVICE", "API call error: " + (errorMsg != null ? errorMsg : "Unknown error"));
                        Utils.showError(this, errorMsg != null ? errorMsg : getString(R.string.error_api_not_accessible));
                        return null;
                    default:
                        Log.e("AGENT_SERVICE", "Unknown result code: " + resultCode);
                        return null;
                }
            }
        }
    }

    private android.app.Notification createNotification() {
        Intent intent = new Intent(this, this.getClass());
        intent.setAction(ACTION_TERMINATE_SERVICE);

        PendingIntent pi = PendingIntent.getService(this, getResources().getInteger(R.integer.notification_id_ssh), intent,
            PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE : 0));

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "ssh_service_channel")
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(getString(R.string.notification_ssh_title))
            .setContentText(getString(R.string.notification_ssh_content))
            .addAction(0, "Terminate", pi);

        return builder.build();
    }

    protected void startForeground(int title, int text, int id) {
        startForeground(id, createNotification());
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel serviceChannel = new NotificationChannel(
                "ssh_service_channel",
                "SSH Service",
                NotificationManager.IMPORTANCE_MIN
            );
            NotificationChannel authChannel = new NotificationChannel(
                "ssh_auth_channel",
                "SSH Authentication",
                NotificationManager.IMPORTANCE_HIGH
            );

            NotificationManager mgr = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            mgr.createNotificationChannel(serviceChannel);
            mgr.createNotificationChannel(authChannel);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d("AGENT_SERVICE", "=== onStartCommand called ===");

        // On Android 12+ (API 31+), we can only call startForeground() if the service was
        // started with startForegroundService(). If it was started with regular startService()
        // (which happens when we can't start from background), skip the foreground promotion.
        boolean shouldGoForeground = true;
        if (Build.VERSION.SDK_INT >= 31) {
            // Check if we can go foreground - if not, run as regular background service
            try {
                int notificationId = getResources().getInteger(R.integer.notification_id_ssh);
                android.app.Notification notification = createNotification();
                Log.d("AGENT_SERVICE", "Attempting foreground with notification ID: " + notificationId);
                startForeground(notificationId, notification);
                Log.d("AGENT_SERVICE", "Service started in foreground successfully");
            } catch (Exception e) {
                // This is expected on Android 12+ when started with startService()
                Log.w("AGENT_SERVICE", "Cannot go foreground on Android 12+ (expected): " + e.getMessage());
                // Continue running as background service - Android allows short-lived background services
                shouldGoForeground = false;
            }
        } else {
            // Android 11 and below - always go foreground
            try {
                int notificationId = getResources().getInteger(R.integer.notification_id_ssh);
                android.app.Notification notification = createNotification();
                Log.d("AGENT_SERVICE", "Starting foreground with notification ID: " + notificationId);
                startForeground(notificationId, notification);
                Log.d("AGENT_SERVICE", "Service started in foreground successfully");
            } catch (Exception e) {
                Log.e("AGENT_SERVICE", "Failed to start foreground service: " + e.getMessage(), e);
                // On older Android, if we can't go foreground, we must stop
                stopSelf();
                return START_NOT_STICKY;
            }
        }

        if (intent == null) {
            Log.w("AGENT_SERVICE", "Intent is null");
            return START_NOT_STICKY;
        }

        int port = intent.getIntExtra(EXTRA_PROXY_PORT, -1);
        String action = intent.getAction();
        Log.d("AGENT_SERVICE", "Action: " + action + ", Port: " + port + ", StartId: " + startId);

        if (ACTION_RUN_AGENT.equals(action)) {
            Log.d("AGENT_SERVICE", "ACTION_RUN_AGENT received for port " + port);
            if (!threadMap.containsKey(port)) {
                Log.d("AGENT_SERVICE", "Creating new agent thread for port " + port);
                Thread agentThread = new Thread(() -> {
                    Log.d("AGENT_SERVICE", "Agent thread starting for port " + port);
                    runAgent(port, intent);
                    Log.d("AGENT_SERVICE", "Agent thread finished for port " + port);
                });
                ArrayBlockingQueue<NullableIntentHolder> queue = new ArrayBlockingQueue<>(1);
                threadMap.put(port, new ThreadContext(agentThread, queue));
                agentThread.start();
                Log.d("AGENT_SERVICE", "Agent thread started for port " + port);
            } else {
                Log.w("AGENT_SERVICE", "Thread already exists for port " + port);
                checkServiceExit();
            }
        } else if (ACTION_RESULT_CALLBACK.equals(action)) {
            Log.d("AGENT_SERVICE", "ACTION_RESULT_CALLBACK received for port " + port);
            ThreadContext ctx = threadMap.get(port);
            if (ctx != null) {
                try {
                    Intent resultIntent = intent.getParcelableExtra(IntentRunnerActivity.EXTRA_RESULT_INTENT);
                    ctx.queue.put(new NullableIntentHolder(resultIntent));
                    Log.d("AGENT_SERVICE", "Result callback queued for port " + port + ", result=" + (resultIntent != null ? "present" : "null"));
                } catch (InterruptedException e) {
                    Log.e("AGENT_SERVICE", "Interrupted while queuing result callback", e);
                    Thread.currentThread().interrupt();
                }
            } else {
                Log.w("AGENT_SERVICE", "No thread context found for port " + port);
                checkServiceExit();
            }
        } else if (ACTION_TERMINATE_SERVICE.equals(action)) {
            Log.d("AGENT_SERVICE", "ACTION_TERMINATE_SERVICE received");
            stopSelf();
        } else {
            Log.w("AGENT_SERVICE", "Unknown action: " + action);
        }

        Log.d("AGENT_SERVICE", "onStartCommand completed, returning START_NOT_STICKY");
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        exited.set(true);

        for (ThreadContext ctx : threadMap.values()) {
            ctx.thread.interrupt();
        }

        for (ThreadContext ctx : threadMap.values()) {
            try {
                ctx.thread.join(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        super.onDestroy();
    }

    public interface ApiExecutor {
        Intent executeApi(Intent intent);
    }
}