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

package org.sufficientlysecure.keychain.ssh.utils;

import java.security.NoSuchAlgorithmException;

public class SshUtils {

    public static String getCurveName(String curveOid) throws NoSuchAlgorithmException {
        // see RFC5656 section 10.{1,2}
        return switch (curveOid) {
            // REQUIRED curves
            case "1.2.840.10045.3.1.7" -> "nistp256";
            case "1.3.132.0.34" -> "nistp384";
            case "1.3.132.0.35" -> "nistp521";

            // RECOMMENDED curves
            case "1.3.132.0.1" -> "1.3.132.0.1";
            case "1.2.840.10045.3.1.1" -> "1.2.840.10045.3.1.1";
            case "1.3.132.0.33" -> "1.3.132.0.33";
            case "1.3.132.0.26" -> "1.3.132.0.26";
            case "1.3.132.0.27" -> "1.3.132.0.27";
            case "1.3.132.0.16" -> "1.3.132.0.16";
            case "1.3.132.0.36" -> "1.3.132.0.36";
            case "1.3.132.0.37" -> "1.3.132.0.37";
            case "1.3.132.0.38" -> "1.3.132.0.38";
            default ->
                    throw new NoSuchAlgorithmException("Can't translate curve OID to SSH curve identifier");
        };
    }
}
