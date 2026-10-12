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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import androidx.annotation.NonNull;

import com.maxmind.db.MaxMindDbConstructor;
import com.maxmind.db.MaxMindDbParameter;

import java.io.Serializable;

public class Geomodel {
    public static class CountryResult {
        public final Country country;

        @MaxMindDbConstructor
        public CountryResult (
                @MaxMindDbParameter(name="country") Country country
        ) {
            this.country = country;
        }
    }

    public static class Country implements Serializable {
        public final String isoCode;

        // https://db-ip.com/db/format/ip-to-country/mmdb.html
        @MaxMindDbConstructor
        public Country(
                @MaxMindDbParameter(name="iso_code") String isoCode) {
            this.isoCode = isoCode;
        }
    }

    public static class ASN implements Serializable {
        public final long number;
        public final String asname;

        public ASN() {
            number = 0;
            asname = "";
        }

        // https://dev.maxmind.com/geoip/docs/databases/asn?lang=en#blocks-files
        @MaxMindDbConstructor
        public ASN(
                @MaxMindDbParameter(name="autonomous_system_number") long number,
                @MaxMindDbParameter(name="autonomous_system_organization") String asname) {
            this.number = number;
            this.asname = asname;
        }

        public boolean isKnown() {
            return(number != 0);
        }

        @Override @NonNull
        public String toString() {
            if(number == 0)
                return "Unknown ASN";
            return "AS" + number + " - " + asname;
        }
    }

    public static class GeoInfo implements Serializable {
        public final String ip;
        public final String countryCode;
        public final String countryName;
        public final String flagEmoji;
        public final long asnNumber;
        public final String asnName;

        public GeoInfo(String ip, String countryCode, String countryName, String flagEmoji, long asnNumber, String asnName) {
            this.ip = ip != null ? ip : "";
            this.countryCode = countryCode != null ? countryCode : "";
            this.countryName = countryName != null ? countryName : "";
            this.flagEmoji = flagEmoji != null ? flagEmoji : "";
            this.asnNumber = asnNumber;
            this.asnName = asnName != null ? asnName : "";
        }

        public boolean hasCountry() {
            return countryCode != null && !countryCode.isEmpty();
        }

        public boolean hasAsn() {
            return asnNumber != 0;
        }

        @NonNull
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            if (hasCountry()) {
                if (!flagEmoji.isEmpty()) sb.append(flagEmoji).append(" ");
                sb.append(countryName).append(" (").append(countryCode).append(")");
            } else {
                sb.append("Unknown Country");
            }
            if (hasAsn()) {
                sb.append(" • AS").append(asnNumber);
                if (!asnName.isEmpty()) sb.append(" (").append(asnName).append(")");
            }
            return sb.toString();
        }
    }
}
