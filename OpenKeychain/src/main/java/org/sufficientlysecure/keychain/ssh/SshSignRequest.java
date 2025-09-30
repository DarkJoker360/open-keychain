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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * SSH sign request parser for SSH agent protocol
 */
public class SshSignRequest {
    private final byte[] keyBlob;
    private final byte[] data;
    private final int flags;

    public SshSignRequest(byte[] contents) {
        if (contents == null) {
            throw new IllegalArgumentException("Contents cannot be null");
        }

        ByteBuffer buf = ByteBuffer.wrap(contents);
        buf.order(ByteOrder.BIG_ENDIAN);

        // Read key blob
        int keyBlobLen = buf.getInt();
        keyBlob = new byte[keyBlobLen];
        buf.get(keyBlob);

        // Read data
        int dataLen = buf.getInt();
        data = new byte[dataLen];
        buf.get(data);

        // Read flags
        flags = buf.getInt();
    }

    public byte[] getKeyBlob() {
        return keyBlob;
    }

    public byte[] getData() {
        return data;
    }

    public int getFlags() {
        return flags;
    }
}