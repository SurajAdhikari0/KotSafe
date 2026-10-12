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
 */

package com.kotsafe.security.model;

import java.io.Serializable;

/**
 * Lazy-loaded structural feature vector store for deep scan and ML similarity search.
 * See Implementation Plan v2 §2.3.
 */
public class FeatureVector implements Serializable {
    public String contentHash = "";
    public byte[] permissionBitmap;
    public String apiCallGraphHash = "";
    public float reflectionDensity;
    public float stringEntropy;
    public int nativeLibCount;
    public float assetToCodeRatio;
    public long extractedAt;

    public FeatureVector() {
        extractedAt = System.currentTimeMillis();
    }
}
