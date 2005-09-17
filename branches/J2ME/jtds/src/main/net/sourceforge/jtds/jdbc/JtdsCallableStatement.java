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

import java.net.URL;
import java.net.MalformedURLException;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Date;
import java.sql.SQLException;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * jTDS implementation of the java.sql.CallableStatement interface.
 *<p>
 * Implementation note:
 * <ol>
 * <li>This class is a simple subclass of PreparedStatement and mainly adds support for
 * setting parameters.
 * <li>The class supports named parameters in a similar way to the
 * patch supplied by Tommy Sandstrom to the original jTDS code.
 * </ol>
 *
 * @author Mike Hutchinson
 * @version $Id: JtdsCallableStatement.java,v 1.12.4.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public class JtdsCallableStatement extends JtdsPreparedStatement implements CallableStatement {
    /** Last parameter retrieved was null. */
    protected boolean paramWasNull = false;

    /**
     * Construct a CallableStatement object.
     *
     * @param connection The connection owning this statement.
     * @param sql The SQL statement specifying the procedure to call.
     * @throws SQLException
     */
    JtdsCallableStatement(ConnectionJDBC2 connection, String sql)
        throws SQLException {
        super(connection, sql, false);
    }

    /**
     * Retrieve the value of an output parameter.
     *
     * @param parameterIndex the ordinal position of the parameter
     * @return the parameter value as an <code>Object</code>
     * @throws SQLException if the parameter has not been set
     */
    protected Object getOutputValue(int parameterIndex)
            throws SQLException {
        ParamInfo parameter = getParameter(parameterIndex);
        if (!parameter.isOutput) {
            throw new SQLException(
                    Messages.get("error.callable.notoutput",
                            new Integer(parameterIndex)),
                    "07000");
        }
        Object value = parameter.getOutValue();
        paramWasNull = (value == null);
        return value;
    }

    /**
     * Check that this statement is still open.
     *
     * @throws SQLException if statement closed.
     */
    protected void checkOpen() throws SQLException {
        if (closed) {
            throw new SQLException(
                    Messages.get("error.generic.closed", "CallableStatement"), "HY010");
        }
    }

// ---------- java.sql.CallableStatement methods follow ----------

    public boolean wasNull() throws SQLException {
        checkOpen();

        return paramWasNull;
    }

    public byte getByte(int parameterIndex) throws SQLException {
        return ((Integer) Support.convert(this, getOutputValue(parameterIndex), java.sql.Types.TINYINT, null)).byteValue();
    }

    public double getDouble(int parameterIndex) throws SQLException {
        return ((Double) Support.convert(this, getOutputValue(parameterIndex), java.sql.Types.DOUBLE, null)).doubleValue();
    }

    public float getFloat(int parameterIndex) throws SQLException {
        return ((Double) Support.convert(this, getOutputValue(parameterIndex), java.sql.Types.FLOAT, null)).floatValue();
    }

    public int getInt(int parameterIndex) throws SQLException {
        return ((Integer) Support.convert(this, getOutputValue(parameterIndex), java.sql.Types.INTEGER, null)).intValue();
    }

    public long getLong(int parameterIndex) throws SQLException {
        return ((Long) Support.convert(this, getOutputValue(parameterIndex), java.sql.Types.BIGINT, null)).longValue();
    }

    public short getShort(int parameterIndex) throws SQLException {
        return ((Integer) Support.convert(this, getOutputValue(parameterIndex), java.sql.Types.SMALLINT, null)).shortValue();
    }

    public boolean getBoolean(int parameterIndex) throws SQLException {
        return ((Boolean) Support.convert(this, getOutputValue(parameterIndex), BOOLEAN, null)).booleanValue();
    }

    public byte[] getBytes(int parameterIndex) throws SQLException {
        return ((byte[]) Support.convert(this, getOutputValue(parameterIndex), java.sql.Types.VARBINARY, connection.getCharset()));
    }

    public void registerOutParameter(int parameterIndex, int sqlType) throws SQLException {
        if (sqlType == java.sql.Types.DECIMAL
            || sqlType == java.sql.Types.NUMERIC) {
            registerOutParameter(parameterIndex, sqlType, -1);
        } else {
            registerOutParameter(parameterIndex, sqlType, 0);
        }
    }

    public void registerOutParameter(int parameterIndex, int sqlType, int scale)
        throws SQLException {
        ParamInfo pi = getParameter(parameterIndex);

        pi.isOutput = true;

        if (Support.getJdbcTypeName(sqlType).equals("ERROR")) {
            throw new SQLException(Messages.get("error.generic.badtype",
                    Integer.toString(sqlType)), "HY092");
        }

        if (sqlType == java.sql.Types.CLOB) {
            pi.jdbcType = java.sql.Types.LONGVARCHAR;
        } else if (sqlType == java.sql.Types.BLOB) {
            pi.jdbcType = java.sql.Types.LONGVARBINARY;
        } else {
            pi.jdbcType = sqlType;
        }

        pi.scale = scale;
    }

    public Object getObject(int parameterIndex) throws SQLException {
        Object value = getOutputValue(parameterIndex);

        // Don't return UniqueIdentifier objects as the user won't know how to
        // handle them
        if (value instanceof UniqueIdentifier) {
            return value.toString();
        }

        return value;
    }

    public String getString(int parameterIndex) throws SQLException {
        return (String) Support.convert(this, getOutputValue(parameterIndex), java.sql.Types.VARCHAR, connection.getCharset());
    }

    public void registerOutParameter(int parameterIndex, int sqlType, String typeName)
        throws SQLException {
        notImplemented("CallableStatement.registerOutParameter(int, int, String");
    }

    public URL getURL(int parameterIndex) throws SQLException {
        String url = (String) Support.convert(this,
                getOutputValue(parameterIndex), java.sql.Types.VARCHAR,
                connection.getCharset());

        try {
            return new java.net.URL(url);
        } catch (MalformedURLException e) {
            throw new SQLException(Messages.get("error.resultset.badurl", url), "22000");
        }
    }

    public Blob getBlob(int parameterIndex) throws SQLException {
        byte[] value = getBytes(parameterIndex);

        if (value == null) {
            return null;
        }

        return new BlobImpl(connection, value);
    }

    public Clob getClob(int parameterIndex) throws SQLException {
        String value = getString(parameterIndex);

        if (value == null) {
            return null;
        }

        return new ClobImpl(connection, value);
    }

    public Date getDate(int parameterIndex) throws SQLException {
        return (java.sql.Date) Support.convert(this,
                getOutputValue(parameterIndex), java.sql.Types.DATE, null);
    }

    public Time getTime(int parameterIndex) throws SQLException {
        return (Time) Support.convert(this, getOutputValue(parameterIndex), java.sql.Types.TIME, null);
    }

    public Timestamp getTimestamp(int parameterIndex) throws SQLException {
        return (Timestamp) Support.convert(this, getOutputValue(parameterIndex), java.sql.Types.TIMESTAMP, null);
    }

    public Date getDate(int parameterIndex, Calendar cal) throws SQLException {
        java.sql.Date date = getDate(parameterIndex);

        if (date != null && cal != null) {
            TimeZone timeZone = TimeZone.getDefault();
            long newTime = date.getTime();

            newTime -= cal.getTimeZone().getRawOffset();
            newTime += timeZone.getRawOffset();
            date = new java.sql.Date(newTime);
        }

        return date;
    }

    public Time getTime(int parameterIndex, Calendar cal) throws SQLException {
        java.sql.Time time = getTime(parameterIndex);

        if (time != null && cal != null) {
            TimeZone timeZone = TimeZone.getDefault();
            long newTime = time.getTime();

            newTime -= cal.getTimeZone().getRawOffset();
            newTime += timeZone.getRawOffset();
            time = new java.sql.Time(newTime);
        }

        return time;
    }

    public Timestamp getTimestamp(int parameterIndex, Calendar cal)
        throws SQLException {
        Timestamp timestamp = getTimestamp(parameterIndex);

        if (timestamp != null && cal != null) {
            TimeZone timeZone = TimeZone.getDefault();
            long newTime = timestamp.getTime();

            newTime -= cal.getTimeZone().getRawOffset();
            newTime += timeZone.getRawOffset();
            timestamp = new Timestamp(newTime);
        }

        return timestamp;
    }
}
