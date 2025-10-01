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

import timber.log.Timber;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public class SshAgentMessage {

    // SSH Agent protocol message types
    public static final int SSH_AGENT_FAILURE = 5;
    public static final int SSH_AGENT_SUCCESS = 6;
    public static final int SSH_AGENTC_REQUEST_IDENTITIES = 11;
    public static final int SSH_AGENT_IDENTITIES_ANSWER = 12;
    public static final int SSH_AGENTC_SIGN_REQUEST = 13;
    public static final int SSH_AGENT_SIGN_RESPONSE = 14;
    public static final int SSH_AGENTC_EXTENSION = 27;
    public static final int SSH_AGENT_EXTENSION_FAILURE = 28;

    private final int type;
    private final byte[] contents;

    public SshAgentMessage(int type, byte[] contents) {
        this.type = type;
        this.contents = contents;
    }

    public int getType() {
        return type;
    }

    public byte[] getContents() {
        return contents;
    }

    // Legacy compatibility
    public byte getMessageType() {
        return (byte) type;
    }

    public byte[] getPayload() {
        return contents;
    }

    public static SshAgentMessage readFromStream(InputStream stream) throws IOException {
        byte[] lengthBytes = Utils.readExact(stream, Integer.BYTES);
        if (lengthBytes == null) {
            return null;
        }

        ByteBuffer lenBuf = ByteBuffer.wrap(lengthBytes);
        lenBuf.order(ByteOrder.BIG_ENDIAN);
        int len = lenBuf.getInt();

        int typeInt = stream.read();
        if (typeInt == -1) {
            throw new java.io.EOFException();
        }

        byte[] contents = null;
        if (len > 1) {
            contents = Utils.readExact(stream, len - 1);
            if (contents == null) {
                throw new java.io.EOFException();
            }
        }

        return new SshAgentMessage(typeInt, contents);
    }

    public void writeToStream(OutputStream stream) throws IOException {
        int bufSize = Integer.BYTES + 1 + (contents != null ? contents.length : 0);

        ByteBuffer buf = ByteBuffer.allocate(bufSize);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putInt(bufSize - Integer.BYTES);
        buf.put((byte) type);
        if (contents != null) {
            buf.put(contents);
        }

        stream.write(buf.array());
        stream.flush();
    }

    public static class Builder {
        private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        public Builder writeInt(int value) {
            ByteBuffer intBuffer = ByteBuffer.allocate(4);
            intBuffer.order(ByteOrder.BIG_ENDIAN);
            intBuffer.putInt(value);
            try {
                buffer.write(intBuffer.array());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return this;
        }

        public Builder writeString(String value) {
            byte[] stringBytes = value.getBytes(StandardCharsets.UTF_8);
            writeInt(stringBytes.length);
            try {
                buffer.write(stringBytes);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return this;
        }

        public Builder writeBytes(byte[] bytes) {
            writeInt(bytes.length);
            try {
                buffer.write(bytes);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return this;
        }

        public Builder writeByte(byte value) {
            buffer.write(value);
            return this;
        }

        public SshAgentMessage build(int messageType) {
            return new SshAgentMessage(messageType, buffer.toByteArray());
        }
    }

    public static class Reader {
        private final byte[] data;
        private int position = 0;

        public Reader(byte[] data) {
            this.data = data;
        }

        public int readInt() {
            if (position + 4 > data.length) {
                throw new RuntimeException("Not enough data to read int");
            }
            int value = ByteBuffer.wrap(data, position, 4).getInt();
            position += 4;
            return value;
        }

        public String readString() {
            int length = readInt();
            if (position + length > data.length) {
                throw new RuntimeException("Not enough data to read string");
            }
            String value = new String(data, position, length, StandardCharsets.UTF_8);
            position += length;
            return value;
        }

        public byte[] readBytes() {
            int length = readInt();
            if (position + length > data.length) {
                throw new RuntimeException("Not enough data to read bytes");
            }
            byte[] bytes = new byte[length];
            System.arraycopy(data, position, bytes, 0, length);
            position += length;
            return bytes;
        }

        public byte readByte() {
            if (position >= data.length) {
                throw new RuntimeException("Not enough data to read byte");
            }
            return data[position++];
        }

        public boolean hasMore() {
            return position < data.length;
        }
    }

    /**
     * Writer class for creating SSH agent messages without specifying message type upfront
     */
    public static class Writer {
        private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        public void writeInt(int value) {
            ByteBuffer intBuffer = ByteBuffer.allocate(4);
            intBuffer.order(ByteOrder.BIG_ENDIAN);
            intBuffer.putInt(value);
            try {
                buffer.write(intBuffer.array());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public void writeString(String value) {
            byte[] stringBytes = value.getBytes(StandardCharsets.UTF_8);
            writeInt(stringBytes.length);
            try {
                buffer.write(stringBytes);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public void writeBytes(byte[] bytes) {
            writeInt(bytes.length);
            try {
                buffer.write(bytes);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public void writeByte(byte value) {
            buffer.write(value);
        }

        public byte[] toByteArray() {
            // Create the complete message with length prefix
            byte[] payload = buffer.toByteArray();
            ByteArrayOutputStream message = new ByteArrayOutputStream();

            try {
                // Write message length (4 bytes)
                ByteBuffer lengthBuffer = ByteBuffer.allocate(4);
                lengthBuffer.order(ByteOrder.BIG_ENDIAN);
                lengthBuffer.putInt(payload.length);
                message.write(lengthBuffer.array());

                // Write payload
                message.write(payload);

                return message.toByteArray();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}