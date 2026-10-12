/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import androidx.annotation.NonNull;

import java.util.Collections;
import java.util.List;

/**
 * Immutable snapshot of the Connections screen state.
 * Contains the list of rows ready to render, pre-calculated metrics, and a generation number
 * to discard obsolete background tasks.
 */
public final class ConnectionScreenState {
    public final long generation;
    public final List<ConnectionRow> rows;
    public final ConnectionScreenMetrics metrics;
    public final FilterDescriptor.AppCategory category;
    public final long timestamp;
    public final boolean isLoading;

    public ConnectionScreenState(long generation,
                                 @NonNull List<ConnectionRow> rows,
                                 @NonNull ConnectionScreenMetrics metrics,
                                 long timestamp,
                                 boolean isLoading) {
        this(generation, rows, metrics, FilterDescriptor.AppCategory.USER, timestamp, isLoading);
    }

    public ConnectionScreenState(long generation,
                                 @NonNull List<ConnectionRow> rows,
                                 @NonNull ConnectionScreenMetrics metrics,
                                 @NonNull FilterDescriptor.AppCategory category,
                                 long timestamp,
                                 boolean isLoading) {
        this.generation = generation;
        this.rows = Collections.unmodifiableList(rows);
        this.metrics = metrics;
        this.category = category;
        this.timestamp = timestamp;
        this.isLoading = isLoading;
    }

    public static ConnectionScreenState empty(long generation, boolean isLoading) {
        return new ConnectionScreenState(generation, Collections.emptyList(), ConnectionScreenMetrics.empty(),
                FilterDescriptor.AppCategory.USER, System.currentTimeMillis(), isLoading);
    }
}
