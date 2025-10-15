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

import android.app.Activity;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;

import androidx.core.app.NotificationCompat;

import org.sufficientlysecure.keychain.R;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import timber.log.Timber;

public class Utils {
    private static final AtomicInteger NOTIFICATION_ID_COUNTER = new AtomicInteger(100000);

    public static void showError(Context context, String msg) {
        if (context instanceof Activity) {
            Timber.e("SSH Agent Error: %s", msg);
        } else {
            NotificationManager mgr = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                mgr.createNotificationChannel(
                        new NotificationChannel(
                                "ssh_error_channel",
                                "SSH Errors",
                                NotificationManager.IMPORTANCE_HIGH
                        )
                );
            }

            NotificationCompat.Builder builder = new NotificationCompat.Builder(context, "ssh_error_channel")
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setSmallIcon(R.drawable.ic_launcher_foreground)
                    .setContentTitle("SSH Error")
                    .setContentText(msg)
                    .setStyle(new NotificationCompat.BigTextStyle().bigText(msg));

            mgr.notify(NOTIFICATION_ID_COUNTER.getAndIncrement(), builder.build());
        }
    }

    public static void writeString(OutputStream output, String str) throws IOException {
        byte[] strBuf = str.getBytes(StandardCharsets.UTF_8);
        int len = Math.min(strBuf.length, 65535); // UShort.MAX_VALUE

        ByteBuffer lenBuf = ByteBuffer.allocate(Short.BYTES);
        lenBuf.order(ByteOrder.BIG_ENDIAN);
        lenBuf.putShort((short) len);

        output.write(lenBuf.array());
        output.write(strBuf, 0, len);
        output.flush();
    }

    public static byte[] readExact(InputStream stream, int size) throws IOException {
        byte[] buf = new byte[size];
        int off = 0;
        while (off < size) {
            int cnt = stream.read(buf, off, size - off);
            if (cnt == -1) {
                if (off == 0) {
                    return null;
                } else {
                    throw new EOFException();
                }
            }
            off += cnt;
        }
        return buf;
    }
}