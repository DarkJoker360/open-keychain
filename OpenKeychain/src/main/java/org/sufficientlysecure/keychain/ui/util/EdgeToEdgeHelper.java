/*
 * Copyright (C) 2025 Schürmann & Breitmoser GbR
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

package org.sufficientlysecure.keychain.ui.util;

import android.content.res.Resources;
import android.os.Build;
import android.view.View;
import android.view.Window;

import androidx.appcompat.widget.Toolbar;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.RecyclerView;

public class EdgeToEdgeHelper {

    public static void enableEdgeToEdge(Window window) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            WindowCompat.setDecorFitsSystemWindows(window, false);
        }
    }

    public static void setupForToolbar(Toolbar toolbar) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM && toolbar != null) {
            ViewCompat.setOnApplyWindowInsetsListener(toolbar, (view, windowInsets) -> {
                Insets statusBarInsets = windowInsets.getInsets(WindowInsetsCompat.Type.statusBars());

                view.setPadding(
                    view.getPaddingLeft(),
                    statusBarInsets.top,
                    view.getPaddingRight(),
                    view.getPaddingBottom()
                );

                return windowInsets;
            });
        }
    }

    public static void setupForRecyclerView(RecyclerView recyclerView, Resources resources, int extraBottomPaddingResId) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM && recyclerView != null) {
            ViewCompat.setOnApplyWindowInsetsListener(recyclerView, (v, windowInsets) -> {
                Insets navBarInsets = windowInsets.getInsets(WindowInsetsCompat.Type.navigationBars());

                int extraBottomPadding = resources.getDimensionPixelSize(extraBottomPaddingResId);
                int bottomPadding = navBarInsets.bottom > 0 ?
                    extraBottomPadding + navBarInsets.bottom : extraBottomPadding;

                v.setPadding(
                    v.getPaddingLeft(),
                    v.getPaddingTop(),
                    v.getPaddingRight(),
                    bottomPadding
                );

                return windowInsets;
            });
        }
    }

    public static void setupForContainer(View container) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM && container != null) {
            ViewCompat.setOnApplyWindowInsetsListener(container, (view, windowInsets) -> {
                Insets navBarInsets = windowInsets.getInsets(WindowInsetsCompat.Type.navigationBars());

                view.setPadding(
                    view.getPaddingLeft(),
                    view.getPaddingTop(),
                    view.getPaddingRight(),
                    navBarInsets.bottom > 0 ? navBarInsets.bottom : view.getPaddingBottom()
                );

                return windowInsets;
            });
        }
    }

    public static void setupForScanner(View scannerView) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM && scannerView != null) {
            ViewCompat.setOnApplyWindowInsetsListener(scannerView, (view, windowInsets) -> {
                Insets systemBarsInsets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars());
                view.setPadding(
                    systemBarsInsets.left,
                    0,
                    systemBarsInsets.right,
                    systemBarsInsets.bottom
                );

                return windowInsets;
            });
        }
    }
}
