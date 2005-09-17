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

import net.sourceforge.jtds.util.ReaderInputStream;
import net.sourceforge.jtds.util.WriterOutputStream;

/**
 * An in-memory, disk or database representation of character data.
 * <p>
 * Implementation note:
 * <ol>
 * <li> Mostly Brian's original code but modified to include the
 *      ability to convert a stream into a String when required.
 * <li> SQLException messages loaded from properties file.
 * </ol>
 *
 * @author Brian Heineman
 * @author Mike Hutchinson
 * @version $Id: ClobImpl.java,v 1.32.2.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public class ClobImpl implements Clob {
	private static final String EMPTY_CLOB = "";

    private final ConnectionJDBC2 _connection;
    private String _clob;

    /**
     * Constructs a new Clob instance.
     *
     * @param callerReference an object reference to the caller of this method;
     *        must be a <code>Connection</code>, <code>Statement</code> or
     *        <code>ResultSet</code>
     */
    ClobImpl(Object callerReference) {
        this(callerReference, EMPTY_CLOB);
    }

    /**
     * Constructs a new Clob instance.
     *
     * @param callerReference an object reference to the caller of this method;
     *        must be a <code>Connection</code>, <code>Statement</code> or
     *        <code>ResultSet</code>
     * @param clob the clob object to encapsulate
     */
    ClobImpl(Object callerReference, String clob) {
        if (clob == null) {
            throw new IllegalArgumentException("clob cannot be null.");
        }

        _clob = clob;
        _connection = Support.getConnection(callerReference);
    }

    /**
     * Constructs a new Clob instance.
     *
     * @param callerReference an object reference to the caller of this method;
     *        must be a <code>Connection</code>, <code>Statement</code> or
     *        <code>ResultSet</code>
     * @param in the clob object to encapsulate
     * @param ntext <code>true</code> if the data type is NTEXT (i.e. Unicode)
     * @param charsetInfo the character set to be used for reading if the value
     *                    is not Unicode encoded (i.e. TEXT)
     */
    ClobImpl(Object callerReference, ResponseStream in, boolean ntext,
             CharsetInfo charsetInfo) throws IOException {
        if (in == null) {
            throw new IllegalArgumentException("in cannot be null.");
        }

        _connection = Support.getConnection(callerReference);

        // If the column doesn't have a specific character set, use the default
        if (charsetInfo == null) {
            charsetInfo = _connection.getCharsetInfo();
        }

        TextPtr tp = new TextPtr();

        in.read(tp.ptr);
        in.read(tp.ts);
        tp.len = in.readInt();

        if (ntext) {
            _clob = in.readUnicodeString(tp.len / 2);
        } else {
            _clob = in.readNonUnicodeString(tp.len, charsetInfo);
        }

        if (ntext && (tp.len & 0x01) != 0) {
            // If text size is set to an odd number e.g. 1
            // Then only part of a char is available.
            in.read(); // Discard!
        }
    }

    /**
     * Returns a new ascii stream for the CLOB data.
     */
    public InputStream getAsciiStream() throws SQLException {
        return new ReaderInputStream(getCharacterStream(), "ASCII");
    }

    /**
     * Returns a new reader for the CLOB data.
     */
    public Reader getCharacterStream() throws SQLException {
        return new StringReader(_clob);
    }

    public String getSubString(long pos, int length) throws SQLException {
        if (pos < 1) {
            throw new SQLException(Messages.get("error.blobclob.badpos"), "HY090");
        } else if (length < 0) {
            throw new SQLException(Messages.get("error.blobclob.badlen"), "HY090");
        } else if (pos - 1 + length > length()) {
            // Don't throw an exception, just return as much data as available
            length = (int) (length() - pos + 1);
        }

        if (length == 0) {
            return EMPTY_CLOB;
        }

        Reader reader = getCharacterStream();

        skip(reader, pos - 1);

        try {
            char[] buffer = new char[length];
            int bytesRead = 0, res;

            while ((res = reader.read(buffer, bytesRead, length - bytesRead)) != -1) {
                bytesRead += res;

                if (bytesRead == length) {
                    return new String(buffer);
                }
            }

            throw new SQLException(Messages.get("error.blobclob.readlen"), "HY000");
        } catch (IOException ioe) {
            throw new SQLException(
                 Messages.get("error.generic.ioread", "String", ioe.getMessage()),
                                    "HY000");
        }
    }

    /**
     * Returns the length of the value.
     */
    public long length() throws SQLException {
        return _clob.length();
    }

    public long position(String searchStr, long start) throws SQLException {
        return position(new ClobImpl(_connection, searchStr), start);
    }

    public long position(Clob searchStr, long start) throws SQLException {
        if (searchStr == null) {
            throw new SQLException(Messages.get("error.clob.searchnull"), "HY024");
        }

        try {
            Reader reader = getCharacterStream();
            long length = length() - searchStr.length();
            boolean reset = true;

            // TODO Implement a better pattern matching algorithm
            for (long i = start; i < length; i++) {
                boolean found = true;
                int value;

                if (reset) {
                    reader = getCharacterStream();
                    skip(reader, i);
                    reset = false;
                }

                value = reader.read();

                Reader searchReader = searchStr.getCharacterStream();
                int searchValue;

                while ((searchValue = searchReader.read()) != -1) {
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

    public OutputStream setAsciiStream(final long pos) throws SQLException {
        return new WriterOutputStream(setCharacterStream(pos), "ASCII");
    }

    public Writer setCharacterStream(final long pos) throws SQLException {
        long length = length();

        if (pos < 1) {
            throw new SQLException(Messages.get("error.blobclob.badpos"), "HY024");
        } else if (pos > length && pos != 1) {
            throw new SQLException(Messages.get("error.blobclob.badposlen"), "HY024");
        }

        return new ClobWriter(pos);
    }

    public int setString(long pos, String str) throws SQLException {
        if (str == null) {
            throw new SQLException(Messages.get("error.clob.strnull"), "HY090");
        }

        return setString(pos, str, 0, str.length());
    }

    public int setString(long pos, String str, int offset, int len)
    throws SQLException {
        Writer writer = setCharacterStream(pos);

        try {
            writer.write(str, offset, len);
            writer.close();
        } catch (IOException e) {
            throw new SQLException(
                Messages.get("error.generic.iowrite", "String", e.getMessage()),
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
        	_clob = getSubString(1, (int) len);
        }
    }

    private void skip(Reader reader, long skip) throws SQLException {
        try {
            long skipped = reader.skip(skip);

            if (skipped != skip) {
                throw new SQLException(Messages.get("error.blobclob.badposlen"), "HY090");
            }
        } catch (IOException e) {
            throw new SQLException(Messages.get("error.generic.ioerror", e.getMessage()),
                                   "HY000");
        }
    }

    /**
     * Class to manage any Clob write.
     */
    class ClobWriter extends Writer {
        Writer writer;
        long curPos;

        ClobWriter(long pos) throws SQLException {
            curPos = pos - 1;

            try {
                updateWriter();
            } catch (IOException e) {
                throw new SQLException(Messages.get("error.generic.ioerror", e.getMessage()),
                                       "HY000");
            }
        }

        public void write(int c) throws IOException {
            writer.write(c);
            curPos++;
        }

        public void write(char[] cbuf, int off, int len) throws IOException {
            writer.write(cbuf, off, len);
            curPos += len;
        }

        /**
         * Updates the <code>outputStream</code> member by creating the
         * approperiate type of output stream based upon the current
         * storage mechanism.
         *
         * @throws IOException if any failure occure while creating the
         *         output stream
         */
        void updateWriter() throws IOException {
            final long startPos = curPos;

            writer = new Writer() {
                int curPos = (int) startPos;
                boolean closed = false;
                char[] singleChar = new char[1];

                private void checkOpen() throws IOException {
                    if (closed) {
                        throw new IOException("stream closed");
                    } else if (_clob == null) {
                        throw new IOException(
                                Messages.get("error.generic.iowrite", "byte", "_clob = NULL"));
                    }
                }

                public void write(int c) throws IOException {
                    checkOpen();

                    singleChar[0] = (char) c;
                    write(singleChar, 0, 1);
                }

                public void write(char[] cbuf, int off, int len) throws IOException {
                    checkOpen();

                    if (cbuf == null) {
                        throw new NullPointerException();
                    } else if (off < 0 || len < 0 || off > cbuf.length
                               || off + len > cbuf.length || off + len < 0) {
                        throw new IndexOutOfBoundsException();
                    } else if (len == 0) {
                        return;
                    }

                    // FIXME - Optimize writes; reduce memory allocation by creating fewer objects.
                    if (curPos + 1 > _clob.length()) {
                        _clob += new String(cbuf, off, len);
                    } else {
                        String tmpClob = _clob;

                        _clob = tmpClob.substring(0, curPos) + new String(cbuf, off, len);

                        if (_clob.length() < tmpClob.length()) {
                            _clob += tmpClob.substring(curPos + len);
                        }
                    }

                    curPos += len;
                }

                public void flush() {
                }

                public void close() {
                    closed = true;
                }
            };
        }

        public void flush() throws IOException {
            writer.flush();
        }

        public void close() throws IOException {
            writer.close();
        }
    };
}
