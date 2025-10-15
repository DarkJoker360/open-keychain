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

import android.app.Notification;
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

import timber.log.Timber;

public abstract class AgentService extends Service {

    private static final int RESULT_CODE_ERROR = 0;
    private static final int RESULT_CODE_SUCCESS = 1;
    private static final int RESULT_CODE_USER_INTERACTION_REQUIRED = 2;

    public static final String ACTION_RUN_AGENT = "org.sufficientlysecure.keychain.action.RUN_AGENT";
    public static final String EXTRA_PROXY_PORT = "org.sufficientlysecure.keychain.extra.PROXY_PORT";
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

    private final ConcurrentHashMap<Integer, ThreadContext> threadMap = new ConcurrentHashMap<>();
    private final AtomicBoolean exited = new AtomicBoolean(false);

    private void checkServiceExit() {
        if (threadMap.isEmpty()) {
            Timber.d("No active threads, stopping service");
            stopSelf();
        } else {
            Timber.d("%d active threads remaining", threadMap.size());
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

    protected Intent callApi(ApiExecutor executeApi, Intent req, int port) {
        Intent reqIntent = req;
        while (true) {
            synchronized (lockObj) {
                Intent resIntent = executeApi.executeApi(reqIntent);
                if (resIntent == null) {
                    Timber.e("API call returned null");
                    Utils.showError(this, getString(R.string.error_api_not_accessible));
                    return null;
                }

                int resultCode = resIntent.getIntExtra(EXTRA_RESULT_CODE, RESULT_CODE_ERROR);
                switch (resultCode) {
                    case RESULT_CODE_SUCCESS:
                        return resIntent;
                    case RESULT_CODE_USER_INTERACTION_REQUIRED:
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
                            Timber.d("Android 10+, showing notification for user interaction");
                            PendingIntent pi = PendingIntent.getActivity(
                                this,
                                port,
                                runnerIntent,
                                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
                            );

                            Notification notification = new NotificationCompat.Builder(this, "ssh_auth_channel")
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
                            Timber.d("Starting IntentRunnerActivity directly");
                            startActivity(runnerIntent);
                        }

                        // Wait for the result from IntentRunnerActivity callback
                        // Timeout after 5 minutes to prevent indefinite blocking
                        ThreadContext ctx = threadMap.get(port);
                        if (ctx == null) {
                            Timber.e("No thread context found");
                            return null;
                        }

                        try {
                            NullableIntentHolder holder = ctx.queue.poll(5, java.util.concurrent.TimeUnit.MINUTES);
                            if (holder == null) {
                                Timber.w("User interaction timed out after 5 minutes");
                                return null;
                            }
                            reqIntent = holder.intent;
                            if (reqIntent == null) {
                                Timber.w("User interaction cancelled");
                                return null;
                            }
                            // Continue the while loop to retry with the new intent
                        } catch (InterruptedException e) {
                            Timber.e(e, "Interrupted while waiting");
                            Thread.currentThread().interrupt();
                            return null;
                        }
                        break;

                    case RESULT_CODE_ERROR:
                        String errorMsg = getErrorMessage(resIntent);
                        Timber.e("API call error");
                        Utils.showError(this, errorMsg != null ? errorMsg : getString(R.string.error_api_not_accessible));
                        return null;
                    default:
                        Timber.e("Unknown result code");
                        return null;
                }
            }
        }
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
        if (intent == null) {
            return START_NOT_STICKY;
        }

        int port = intent.getIntExtra(EXTRA_PROXY_PORT, -1);
        String action = intent.getAction();

        if (ACTION_RUN_AGENT.equals(action)) {
            if (!threadMap.containsKey(port)) {
                Thread agentThread = new Thread(() -> runAgent(port, intent));
                ArrayBlockingQueue<NullableIntentHolder> queue = new ArrayBlockingQueue<>(1);
                threadMap.put(port, new ThreadContext(agentThread, queue));
                agentThread.start();
            } else {
                checkServiceExit();
            }
        } else if (ACTION_RESULT_CALLBACK.equals(action)) {
            Timber.d("ACTION_RESULT_CALLBACK received for port %d", port);
            ThreadContext ctx = threadMap.get(port);
            if (ctx != null) {
                try {
                    Intent resultIntent = intent.getParcelableExtra(IntentRunnerActivity.EXTRA_RESULT_INTENT);
                    ctx.queue.put(new NullableIntentHolder(resultIntent));
                    Timber.d("Result callback queued");
                } catch (InterruptedException e) {
                    Timber.e(e, "Interrupted while queuing");
                    Thread.currentThread().interrupt();
                }
            } else {
                Timber.w("No thread context found");
                checkServiceExit();
            }
        } else if (ACTION_TERMINATE_SERVICE.equals(action)) {
            Timber.d("Terminate service");
            stopSelf();
        } else {
            Timber.w("Unknown action");
        }

        Timber.d("onStartCommand completed, returning START_NOT_STICKY");
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