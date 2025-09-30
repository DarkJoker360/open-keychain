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

import java.util.Arrays;

/**
 * SSH public key information for SSH agent protocol
 */
public class SshPublicKeyInfo {
    private final byte[] publicKey;
    private final byte[] comment;

    public SshPublicKeyInfo(byte[] publicKey, byte[] comment) {
        this.publicKey = publicKey;
        this.comment = comment;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getComment() {
        return comment;
    }

    public boolean publicKeyEquals(byte[] other) {
        return Arrays.equals(publicKey, other);
    }
}