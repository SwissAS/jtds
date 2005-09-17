// jTDS JDBC Driver for Microsoft SQL Server and Sybase
// Copyright (C) 2004 The jTDS Project
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
package net.sourceforge.jtds.jdbc;

import java.io.*;
import java.sql.*;

/**
 * An in-memory, disk or database representation of binary data.
 *
 * @author Brian Heineman
 * @author Mike Hutchinson
 * @version $Id: BlobImpl.java,v 1.27.2.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public class BlobImpl implements Blob {
	private static final byte[] EMPTY_BLOB = new byte[0];

    private ConnectionJDBC2 _connection;
	private byte[] _blob;

    /**
     * Constructs a new Blob instance.
     *
     * @param callerReference an object reference to the caller of this method;
     *        must be a <code>Connection</code>, <code>Statement</code> or
     *        <code>ResultSet</code>
     */
    BlobImpl(Object callerReference) {
        this(callerReference, EMPTY_BLOB);
    }

    /**
     * Constructs a new Blob instance.
     *
     * @param callerReference an object reference to the caller of this method;
     *        must be a <code>Connection</code>, <code>Statement</code> or
     *        <code>ResultSet</code>
     * @param blob the blob object to encapsulate
     */
    BlobImpl(Object callerReference, byte[] blob) {
        if (blob == null) {
            throw new IllegalArgumentException("blob cannot be null.");
        }

        _connection = Support.getConnection(callerReference);
        _blob = blob;
    }

    /**
     * Constructs a new Blob instance.
     *
     * @param callerReference an object reference to the caller of this method;
     *        must be a <code>Connection</code>, <code>Statement</code> or
     *        <code>ResultSet</code>
     * @param in the blob object to encapsulate
     */
    BlobImpl(Object callerReference, ResponseStream in) throws IOException {
        if (in == null) {
            throw new IllegalArgumentException("in cannot be null.");
        }

        _connection = Support.getConnection(callerReference);

        TextPtr tp = new TextPtr();

        in.read(tp.ptr);
        in.read(tp.ts);
        tp.len = in.readInt();

        _blob = new byte[tp.len];
        in.read(_blob);
    }

    /**
     * Returns an InputStream for the BLOB data.
     */
    public InputStream getBinaryStream() throws SQLException {
        return new ByteArrayInputStream(_blob);
    }

    public byte[] getBytes(long pos, int length) throws SQLException {
        if (pos < 1) {
            throw new SQLException(Messages.get("error.blobclob.badpos"), "HY090");
        } else if (length < 0) {
            throw new SQLException(Messages.get("error.blobclob.badlen"), "HY090");
        } else if (pos - 1 + length > length()) {
            // Don't throw an exception, just return as much data as available
            length = (int) (length() - pos + 1);
        }

        if (length == 0) {
            return EMPTY_BLOB;
        }

        InputStream inputStream = getBinaryStream();

        skip(inputStream, pos - 1);

        try {
            byte[] buffer = new byte[length];
            int bytesRead = 0, res;

            while ((res = inputStream.read(buffer, bytesRead, length - bytesRead)) != -1) {
                bytesRead += res;

                if (bytesRead == length) {
                    return buffer;
                }
            }

            throw new SQLException(Messages.get("error.blobclob.readlen"), "HY000");
        } catch (IOException e) {
            throw new SQLException(
                 Messages.get("error.generic.ioread", "byte", e.getMessage()),
                                    "HY000");
        }
    }

    /**
     * Returns the length of the value.
     */
    public long length() throws SQLException {
        return _blob.length;
    }

    public long position(byte[] pattern, long start) throws SQLException {
        return position(new BlobImpl(_connection, pattern), start);
    }

    public long position(Blob pattern, long start) throws SQLException {
        if (pattern == null) {
            throw new SQLException(Messages.get("error.blob.badpattern"), "HY024");
        }

        try {
            InputStream inputStream = getBinaryStream();
            long length = length() - pattern.length();
            boolean reset = true;

            // TODO Implement a better pattern matching algorithm
            for (long i = start; i < length; i++) {
                boolean found = true;
                int value;

                if (reset) {
                    inputStream = getBinaryStream();
                    skip(inputStream, i);
                    reset = false;
                }

                value = inputStream.read();

                InputStream patternInputStream = pattern.getBinaryStream();
                int searchValue;

                while ((searchValue = patternInputStream.read()) != -1) {
                    if (value != searchValue) {
                        found = false;
                        break;
                    }

                    reset = true;
                }

                if (found) {
                    return i;
                }
            }
        } catch (IOException e) {
            throw new SQLException(
                Messages.get("error.generic.ioread", "String", e.getMessage()),
                                   "HY000");
        }

        return -1;
    }

    public OutputStream setBinaryStream(final long pos) throws SQLException {
        long length = length();

        if (pos < 1) {
            throw new SQLException(Messages.get("error.blobclob.badpos"), "HY090");
        } else if (pos > length && pos != 1) {
            throw new SQLException(Messages.get("error.blobclob.badposlen"), "HY090");
        }

        return new BlobOutputStream(pos);
    }

    public int setBytes(long pos, byte[] bytes) throws SQLException {
        if (bytes == null) {
            throw new SQLException(Messages.get("error.blob.bytesnull"), "HY024");
        }

        return setBytes(pos, bytes, 0, bytes.length);
    }

    public int setBytes(long pos, byte[] bytes, int offset, int len)
            throws SQLException {
        OutputStream outputStream = setBinaryStream(pos);

        try {
            outputStream.write(bytes, offset, len);
            outputStream.close();
        } catch (IOException e) {
            throw new SQLException(Messages.get("error.generic.iowrite",
            		                                  "bytes",
													  e.getMessage()),
                                   "HY000");
        }

        return len;
    }

    /**
     * Truncates the value to the length specified.
     *
     * @param len the length to truncate the value to
     */
    public void truncate(long len) throws SQLException {
        long currentLength = length();

        if (len < 0) {
            throw new SQLException(Messages.get("error.blobclob.badlen"), "HY090");
        } else if (len > currentLength) {
            throw new SQLException(Messages.get("error.blobclob.lentoolong"), "HY090");
        }

        if (len == currentLength) {
            return;
        } else {
            _blob = getBytes(1, (int) len);
        }
    }

    private void skip(InputStream inputStream, long skip) throws SQLException {
        try {
            long skipped = inputStream.skip(skip);

            if (skipped != skip) {
                throw new SQLException(Messages.get("error.blobclob.badposlen"), "HY090");
            }
        } catch (IOException e) {
            throw new SQLException(Messages.get("error.generic.ioerror", e.getMessage()),
                                   "HY000");
        }
    }

    /**
     * Class to manage any Blob write.
     */
    class BlobOutputStream extends OutputStream {
        private OutputStream outputStream;
        private long curPos;

        BlobOutputStream(long pos) throws SQLException {
            curPos = pos - 1;

            try {
                updateOuputStream();
            } catch (IOException e) {
                throw new SQLException(Messages.get("error.generic.ioerror", e.getMessage()),
                                       "HY000");
            }
        }

        public void write(int b) throws IOException {
            outputStream.write(b);
            curPos++;
        }

        public void write(byte[] b, int off, int len) throws IOException {
            outputStream.write(b, off, len);
            curPos += len;
        }

        /**
         * Updates the <code>outputStream</code> member by creating the
         * appropriate type of output stream based upon the current
         * storage mechanism.
         *
         * @throws IOException if any failure occured while creating the
         *         output stream
         */
        void updateOuputStream() throws IOException {
            final long startPos = curPos;

            outputStream = new OutputStream() {
                int curPos = (int) startPos;
                boolean closed = false;

                private void checkOpen() throws IOException {
                    if (closed) {
                        throw new IOException("stream closed");
                    } else if (_blob == null) {
                        throw new IOException(
                                Messages.get("error.generic.iowrite", "byte", "_blob = NULL"));
                    }
                }

                public void write(int b) throws IOException {
                    checkOpen();

                    if (curPos + 1 > _blob.length) {
                        byte[] buffer = new byte[curPos + 1];

                        System.arraycopy(_blob, 0, buffer, 0, _blob.length);
                        _blob = buffer;
                    }

                    _blob[curPos++] = (byte) b;
                }

                public void write(byte[] b, int off, int len) throws IOException {
                    checkOpen();

                    if (b == null) {
                        throw new NullPointerException();
                    } else if (off < 0 || off > b.length || len < 0 ||
                            off + len > b.length || off + len < 0) {
                        throw new IndexOutOfBoundsException();
                    } else if (len == 0) {
                        return;
                    }

                    // Reallocate the buffer
                    if (curPos + len > _blob.length) {
                        byte[] buffer = new byte[curPos + len];

                        System.arraycopy(_blob, 0, buffer, 0, _blob.length);
                        _blob = buffer;
                    }

                    // Append the contents of b to the blob
                    System.arraycopy(b, off, _blob, curPos, len);
                    curPos += len;
                }

                public void close() {
                    closed = true;
                }
            };
        }

        public void flush() throws IOException {
            outputStream.flush();
        }

        public void close() throws IOException {
            outputStream.close();
        }
    };
}

