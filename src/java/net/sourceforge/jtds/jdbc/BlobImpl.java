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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.sql.Blob;
import java.sql.SQLException;

/**
 * An in-memory or disk based representation of binary data.
 *
 * @author Brian Heineman
 * @author Mike Hutchinson
 * @version $Id: BlobImpl.java,v 1.3 2009-09-27 12:59:02 ickzon Exp $
 */
public class BlobImpl extends BlobBuffer implements Blob, Serializable {
    static final long serialVersionUID = -9113350639400455769L;
    /**
     * 0 length <code>byte[]</code> as initial value for empty
     * <code>Blob</code>s.
     */
    private static final byte[] EMPTY_BLOB = new byte[0];

    /**
     * Constructs a new empty <code>Blob</code> instance.
     *
     * @param connection a reference to the parent connection object
     */
    BlobImpl(final ConnectionImpl connection) {
        this(connection, EMPTY_BLOB);
    }

    /**
     * Constructs a new <code>Blob</code> instance initialized with data.
     *
     * @param connection a reference to the parent connection object
     * @param bytes      the blob object to encapsulate
     */
    BlobImpl(final ConnectionImpl connection, final byte[] bytes) {
        super(connection.getLobBuffer());
        if (bytes == null) {
            throw new IllegalArgumentException("bytes cannot be null");
        }
        setBuffer(bytes, false);
    }

    /**
     * Creates a Blob from an InputStream.
     *
     * @param connection the parent Connection Object.
     * @param in the InputStream with the BLOB data.
     * @param length the length of the BLOB data or -2 if not known.
     */
    BlobImpl(final ConnectionImpl connection, 
             final InputStream in, 
             final int length) throws IOException {
        super(connection, in, length);
    }

    //
    // ------ java.sql.Blob interface methods from here -------
    //

    public InputStream getBinaryStream() throws SQLException {
        return getBinaryStream(false);
    }

    public long position(Blob pattern, long start) throws SQLException {
        if (pattern == null) {
            throw new SQLException(Messages.get("error.blob.badpattern"), "HY009");
        }
        return position(pattern.getBytes(1, (int) pattern.length()), start);
    }

    public OutputStream setBinaryStream(final long pos) throws SQLException {
        try {
            return setBinaryStream(pos, false);
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "HY090");
        } catch (IOException e) {
            throw new SQLException(Messages.get("error.generic.ioerror",
                    e.getMessage()),
                    "HY000");
        }
    }

    public int setBytes(long pos, byte[] bytes) throws SQLException {
        if (bytes == null) {
            throw new SQLException(Messages.get("error.blob.bytesnull"), "HY009");
        }
        return setBytes(pos, bytes, 0, bytes.length);
    }

    public int setBytes(long pos, byte[] bytes, int offset, int len)
            throws SQLException {
        if (bytes == null) {
            throw new SQLException(Messages.get("error.blob.bytesnull"), "HY009");
        }
        // Force BlobBuffer to take a copy of the byte array
        // In many cases this is wasteful but the user may
        // reuse the byte buffer corrupting the original set
        return setBytes(pos, bytes, offset, len, true);
    }

    public long length() throws SQLException {
        return getLength();
    }

    @Override
    public void free() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public InputStream getBinaryStream(long pos, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }
}
