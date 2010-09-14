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

import java.sql.SQLException;
import java.sql.Types;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;

/**
 * This class is a descriptor for procedure and prepared statement parameters.
 *
 * @author Mike Hutchinson
 * @version $Id: ParamInfo.java,v 1.1 2007-09-10 19:19:31 bheineman Exp $
 */
class ParamInfo implements Cloneable {
    /** Flag as an input parameter. */
    final static int INPUT   = 0;
    /** Flag as an output parameter. */
    final static int OUTPUT  = 1;
    /** Flag as an return value parameter. */
    final static int RETVAL  = 2;
    /** Flag as a unicode parameter. */
    final static int UNICODE = 4;

    /** Internal TDS data type */
    int tdsType;
    /** JDBC type constant from java.sql.Types */
    int jdbcType;
    /** Formal parameter name eg @P1 */
    String name;
    /** SQL type name eg varchar(10) */
    String sqlType;
    /** Parameter offset in target SQL statement */
    int markerPos = -1;
    /** Current parameter value */
    Object value;
    /** Parameter decimal precision */
    int precision = -1;
    /** Parameter decimal scale */
    int scale = -1;
    /** Length of InputStream */
    int length = 0;
    /** Parameter is an output parameter */
    boolean isOutput;
    /** Parameter is used as  SP return value */
    boolean isRetVal;
    /** IN parameter has been set */
    boolean isSet;
    /** Parameter should be sent as unicode */
    boolean isUnicode;
    /** OUT parameter value is set.*/
    boolean isSetOut;
    /** OUT Parameter value. */
    Object outValue;

    /**
     * Construct a parameter with parameter marker offset.
     *
     * @param pos       the offset of the ? symbol in the target SQL string
     * @param isUnicode <code>true</code> if the parameter is Unicode encoded
     */
    ParamInfo(final int pos, final boolean isUnicode) {
        markerPos = pos;
        this.isUnicode = isUnicode;
    }

    /**
     * Construct a parameter for statement caching.
     *
     * @param name      the formal name of the parameter
     * @param pos       the offset of the ? symbol in the parsed SQL string
     * @param isRetVal  <code>true</code> if the parameter is a return value
     * @param isUnicode <code>true</code> if the parameter is Unicode encoded
     */
    ParamInfo(final String name, 
              final int pos, 
              final boolean isRetVal, 
              final boolean isUnicode) {
        this.name      = name;
        this.markerPos = pos;
        this.isRetVal  = isRetVal;
        this.isUnicode = isUnicode;
   }

    /**
     * Construct an initialised parameter with extra attributes.
     *
     * @param jdbcType the <code>java.sql.Type</code> constant describing this type
     * @param value    the initial parameter value
     * @param flags    the additional attributes eg OUTPUT, RETVAL, UNICODE etc.
     */
    ParamInfo(final int jdbcType, final Object value, final int flags)
    {
        this.jdbcType  = jdbcType;
        this.value     = value;
        this.isSet     = true;
        this.isOutput  = ((flags & OUTPUT) > 0) || ((flags & RETVAL) > 0);
        this.isRetVal  = ((flags & RETVAL)> 0);
        this.isUnicode = ((flags & UNICODE) > 0);
        if (value instanceof String) {
            this.length = ((String)value).length();
        } else
        if (value instanceof byte[]) {
            this.length = ((byte[])value).length;
        }
    }

    /**
     * Construct a parameter based on a result set column.
     *
     * @param ci     the column descriptor
     * @param name   the name for this parameter or null
     * @param value  the column data value
     * @param length the column data length
     */
    ParamInfo(final ColInfo ci, final String name, final Object value, final int length) {
        this.name      = name;
        this.tdsType   = ci.tdsType;
        this.scale     = ci.scale;
        this.precision = ci.precision;
        this.jdbcType  = ci.jdbcType;
        this.sqlType   = ci.sqlType;
        this.isUnicode = false;
        this.isSet     = true;
        this.value     = value;
        this.length    = length;
    }
    
    /**
     * Get the output parameter value.
     *
     * @return the OUT value as an <code>Object</code>
     * @throws SQLException if the parameter has not been set
     */
    Object getOutValue()
        throws SQLException {
        if (!isSetOut) {
            throw new SQLException(
                    Messages.get("error.callable.outparamnotset"), "HY010");
        }
        return outValue;
    }

    /**
     * Set the OUT parameter value.
     * @param value The data value.
     */
    void setOutValue(final Object value) {
        outValue= value;
        isSetOut = true;
    }

    /**
     * Clear the OUT parameter value and status.
     */
    void clearOutValue()
    {
        outValue = null;
        isSetOut = false;
    }

    /**
     * Clear the IN parameter value and status.
     */
    void clearInValue()
    {
        length = 0;
        value  = null;
        isSet  = false;
    }
    
    /**
     * See if the parameter value is convertable from unicode to the target charset. 
     * @param connection the current connection instance.
     * @return <code>booolean</code> true if value is convertable.
     * @throws IOException
     */
    boolean isConvertable(final ConnectionImpl connection) throws IOException {
        if (!(value instanceof String)) {
            loadString(connection);
        }
        if (value instanceof String) {
            CharsetEncoder cse = connection.getCharset().newEncoder();
            return cse.canEncode((String)value);
        }
        return true;
    }

    /**
     * Get the string value of the parameter.
     * 
     * @param connection the current Connection instance
     * @throws IOException if I/O error or encoding error.
     */
    void loadString(final ConnectionImpl connection) throws IOException {
        if (value instanceof InputStream) {
            value = new InputStreamReader((InputStream) value, 
                    connection.getCharset());
        }
        if (value instanceof Reader) {
            char[] buf = new char[length];
            Reader in = (Reader)value;
            int pos = 0;
            int bc;
            do {
                bc = in.read(buf, pos, buf.length - pos);
                if (bc < 0) {
                    break;
                }
                pos += bc;
            } while (pos < length);
            value = String.valueOf(buf, 0, pos);
            length = ((String) value).length();
        }
    }

    /**
     * Get the ANSI byte array value of the parameter.
     *
     * @param connection the current Connection instance
     * @throws IOException
     */
     void loadBytes(final ConnectionImpl connection) throws IOException {

        if (value instanceof InputStream) {
            byte[] buf = new byte[length];
            InputStream in = (InputStream)value;
            int pos = 0, res;
            while (pos != length && (res = in.read(buf, pos, length - pos)) != -1) {
                pos += res;
            }
            if (pos != length) {
                throw new java.io.IOException(Messages.get("error.io.outofdata"));
            }
            if (in.read() >= 0) {
                throw new java.io.IOException(Messages.get("error.io.toomuchdata"));
            }
            value = buf;
        } else 
        if (value instanceof Reader) {
            char[] buf = new char[length];
            Reader in = (Reader)value;
            int pos = 0, res;
            while (pos != length && (res = in.read(buf, pos, length - pos)) != -1) {
                pos += res;
            }
            if (pos != length) {
                throw new java.io.IOException(Messages.get("error.io.outofdata"));
            }

            if (in.read() >= 0) {
                throw new java.io.IOException(Messages.get("error.io.toomuchdata"));
            }
            ByteBuffer bb = connection.getCharset().encode(CharBuffer.wrap(buf));
            value = new byte[bb.remaining()];
            bb.get((byte[])value);
            length = ((byte[])value).length;
        } else
        if (value instanceof String) {
            ByteBuffer bb = connection.getCharset().encode((String)value);
            length = bb.remaining();
            value = new byte[length];
            bb.get((byte[])value);
        }
    }

    /**
     * Get the length of the parameter value in bytes.
     * <p/>Multi Byte Character sets will cause the string to be converted
     * so that the correct byte length can be determined.
     * 
     * @param connection the current Connection instance
     * @return the value length as a <code>int</code>.
     * @throws IOException
     */
    int getAnsiLength(final ConnectionImpl connection) throws IOException {
        if (connection.isWideChar()) {
            if (value instanceof Reader) {
                // Need to convert the String or Reader data to a byte array
                // to get correct size in bytes due to multi byte charset e.g. UTF-8
                char[] buf = new char[length];
                Reader in = (Reader)value;
                int pos = 0;
                int bc;
                do {
                    bc = in.read(buf, pos, buf.length - pos);
                    if (bc < 0) {
                        break;
                    }
                    pos += bc;
                } while (pos < length);
                ByteBuffer bb = connection.getCharset().encode(CharBuffer.wrap(buf));
                length = bb.remaining();
                value = new byte[length];
                bb.get((byte[])value, 0, length);
                value = String.valueOf(buf, 0, pos);
            }
            if (value instanceof String) {
                value  = ((String)value).getBytes(connection.getCharset().name());
                length = ((byte[])value).length;
            }
        }
        return (value == null)? 0: length;
    }
    
    /**
     * Get the length of the parameter value in characters.
     * 
     * @param connection the current Connection instance
     * @return the value length as a <code>int</code>.
     * @throws IOException
     */
    int getCharLength(final ConnectionImpl connection) throws IOException {
        if (connection.isWideChar()&& (value instanceof InputStream)) {
            // Need to convert the InputStream to a String to get 
            // correct size in characters due to multi byte charset e.g. UTF-8
            value = new InputStreamReader((InputStream) value, 
                    connection.getCharset());
            char[] buf = new char[length];
            Reader in = (Reader)value;
            int pos = 0;
            int bc;
            do {
                bc = in.read(buf, pos, 1024);
                if (bc < 0) {
                    break;
                }
                pos += bc;
            } while (bc == 1024);
            value = String.valueOf(buf, 0, pos);
            length = ((String) value).length();
        }
        return (value == null)? 0: length;
    }
    
    /**
     * Write the parameter value out as a byte stream.
     * @param out the TDS output stream.
     * @param connection the current connection instance.
     * @throws IOException
     */
    void writeBytes(final TdsStream out, final ConnectionImpl connection) throws IOException {
        if (value instanceof byte[]) {
            out.write((byte[])value);
        } else
        if (value instanceof InputStream) {
            byte buffer[] = new byte[1024];

            while (length > 0) {
                int res = ((InputStream)value).read(buffer);

                if (res < 0) {
                    throw new java.io.IOException(Messages.get("error.io.outofdata"));
                }

                out.write(buffer, 0, res);
                length -= res;
            }

            // XXX Not sure that this is actually an error
            if (length < 0 || ((InputStream)value).read() >= 0) {
                throw new java.io.IOException(Messages.get("error.io.toomuchdata"));
            }
        }
    }
    
    /**
     * Write the parameter value out as a UNICODE stream.
     * @param out the TDS output stream.
     * @param connection the current connection instance.
     * @throws IOException
     */
    void writeUnicode(final TdsStream out, final ConnectionImpl connection) throws IOException {
        if (value instanceof String) {
            out.writeUnicode((String)value);
        } else { 
            Object txt = value;
            if (txt instanceof InputStream) {
                txt = new InputStreamReader((InputStream) value, 
                                connection.getCharset()); 
            }
            if (txt instanceof Reader) {
                char buffer[] = new char[1024];
                for (int i = 0; i < length;) {
                    int result = ((Reader)txt).read(buffer);

                    if (result == -1) {
                        throw new java.io.IOException(Messages.get("error.io.outofdata"));
                    } else if (i + result > length) {
                        throw new java.io.IOException(Messages.get("error.io.toomuchdata"));
                    }
                    out.writeUnicode(buffer, result);
                    i += result;
                }
            }
        }
    }
    
    /**
     * Write the parameter value out as a byte character stream.
     * @param out the TDS output stream.
     * @param connection the current connection instance.
     * @throws IOException
     */
    void writeAnsi(final TdsStream out, final ConnectionImpl connection) throws IOException {
        if (value instanceof String) {
            out.write((String)value, connection.getCharset());
        } else
        if (value instanceof Reader) {
            char buffer[] = new char[1024];
            Charset charset = connection.getCharset();
            for (int i = 0; i < length;) {
                int result = ((Reader)value).read(buffer);

                if (result == -1) {
                    throw new java.io.IOException(Messages.get("error.io.outofdata"));
                } else if (i + result > length) {
                    throw new java.io.IOException(Messages.get("error.io.toomuchdata"));
                }
                out.write(buffer, result, charset);
                i += result;
            }
        } else 
        if (value instanceof InputStream) {
            byte buffer[] = new byte[1024];

            while (length > 0) {
                int res = ((InputStream)value).read(buffer);

                if (res < 0) {
                    throw new java.io.IOException(Messages.get("error.io.outofdata"));
                }

                out.write(buffer, 0, res);
                length -= res;
            }

            // XXX Not sure that this is actually an error
            if (length < 0 || ((InputStream)value).read() >= 0) {
                throw new java.io.IOException(Messages.get("error.io.toomuchdata"));
            }
        } else 
        if (value instanceof byte[]) {
            // Already converted by getAnsiLength()
            out.write((byte[])value);
        }
    }
    
    /**
     * Buffer InputStream and Reader parameters in memory so that the 
     * parameter values can be reused.
     * @param connection the current connection instance.
     */
    void buffer(ConnectionImpl connection) throws SQLException
    {
        if (value instanceof InputStream || value instanceof Reader) {
            try {
                if (jdbcType == Types.VARCHAR ||
                        jdbcType == Types.CHAR ||
                        jdbcType == Types.LONGVARCHAR) 
                {
                    loadString(connection);
                } else {
                    loadBytes(connection);
                }
            } catch (IOException ioe) {
                throw new SQLException(Messages.get("error.generic.ioerror"), "HY000");
            }
        }
    }

    /**
     * Creates a shallow copy of this <code>ParamInfo</code> instance. Used by
     * the <code>PreparedStatement</code> batching implementation to duplicate
     * parameters.
     */
    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException ex) {
            // Will not happen
            return null;
        }
    }
}
