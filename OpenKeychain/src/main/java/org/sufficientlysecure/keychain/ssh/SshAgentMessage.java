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
import java.nio.charset.StandardCharsets;

public class SshAgentMessage {

    // SSH Agent protocol message types
    public static final byte SSH_AGENTC_REQUEST_IDENTITIES = 11;
    public static final byte SSH_AGENT_IDENTITIES_ANSWER = 12;
    public static final byte SSH_AGENTC_SIGN_REQUEST = 13;
    public static final byte SSH_AGENT_SIGN_RESPONSE = 14;
    public static final byte SSH_AGENT_FAILURE = 5;
    public static final byte SSH_AGENT_SUCCESS = 6;

    private final byte messageType;
    private final byte[] payload;

    public SshAgentMessage(byte messageType, byte[] payload) {
        this.messageType = messageType;
        this.payload = payload != null ? payload : new byte[0];
    }

    public byte getMessageType() {
        return messageType;
    }

    public byte[] getPayload() {
        return payload;
    }

    public static SshAgentMessage readFromStream(InputStream inputStream) throws IOException {
        // Read message length (4 bytes, big-endian)
        byte[] lengthBytes = new byte[4];
        int bytesRead = 0;
        while (bytesRead < 4) {
            int result = inputStream.read(lengthBytes, bytesRead, 4 - bytesRead);
            if (result == -1) {
                return null; // End of stream
            }
            bytesRead += result;
        }

        int messageLength = ByteBuffer.wrap(lengthBytes).getInt();
        if (messageLength <= 0 || messageLength > 1024 * 1024) { // 1MB max
            throw new IOException("Invalid SSH agent message length: " + messageLength);
        }

        // Read message type (1 byte)
        int messageTypeByte = inputStream.read();
        if (messageTypeByte == -1) {
            throw new IOException("Unexpected end of stream reading message type");
        }

        // Read payload (remaining bytes)
        byte[] payload = new byte[messageLength - 1];
        bytesRead = 0;
        while (bytesRead < payload.length) {
            int result = inputStream.read(payload, bytesRead, payload.length - bytesRead);
            if (result == -1) {
                throw new IOException("Unexpected end of stream reading payload");
            }
            bytesRead += result;
        }

        Timber.d("SSH Agent: Read message type %d, payload length %d", messageTypeByte, payload.length);
        return new SshAgentMessage((byte) messageTypeByte, payload);
    }

    public void writeToStream(OutputStream outputStream) throws IOException {
        // Calculate total message length (type + payload)
        int totalLength = 1 + payload.length;

        // Write length (4 bytes, big-endian)
        ByteBuffer lengthBuffer = ByteBuffer.allocate(4);
        lengthBuffer.putInt(totalLength);
        outputStream.write(lengthBuffer.array());

        // Write message type
        outputStream.write(messageType);

        // Write payload
        outputStream.write(payload);

        Timber.d("SSH Agent: Wrote message type %d, payload length %d", messageType, payload.length);
    }

    public static class Builder {
        private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        public Builder writeInt(int value) {
            ByteBuffer intBuffer = ByteBuffer.allocate(4);
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

        public SshAgentMessage build(byte messageType) {
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