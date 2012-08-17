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

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.net.MalformedURLException;
import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.DatabaseMetaData;
import java.sql.Date;
import java.sql.NClob;
import java.sql.ParameterMetaData;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.Time;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Map;

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
 * @version $Id: CallableStatementImpl.java,v 1.4 2009-09-27 12:59:02 ickzon Exp $
 */
public class CallableStatementImpl extends PreparedStatementImpl implements CallableStatement {
    /** Last parameter retrieved was null. */
    private boolean paramWasNull;

    /**
     * Construct a CallableStatement object.
     *
     * @param connection The connection owning this statement.
     * @param sql The SQL statement specifying the procedure to call.
     * @param resultSetType The result set type eg FORWARD_ONLY.
     * @param concurrency   The result set concurrency eg READ_ONLY.
     * @throws SQLException
     */
    CallableStatementImpl(final ConnectionImpl connection, 
                          final String sql, 
                          final int resultSetType, 
                          final int concurrency)
        throws SQLException {
        super(connection, normalizeCall(sql), resultSetType, concurrency, false);
    }

    /**
     * This method converts native call syntax into (hopefully) valid JDBC
     * escape syntax.
     * <p/>
     * <b>Note:</b> This method is required for backwards compatibility with
     * previous versions of jTDS. Strictly speaking only the JDBC syntax needs
     * to be recognised, constructions such as "?=#testproc ?,?" are neither
     * valid native syntax nor valid escapes. All the substrings and trims
     * below are not as bad as they look. The objects created all refer back to
     * the original sql string it is just the start and length positions which
     * change.
     *
     * @param sql the SQL statement to process
     * @return the SQL, possibly in original form
     */
    static String normalizeCall(String sql) {
        String original = sql;
        sql = sql.trim();

        if (sql.length() > 0 && sql.charAt(0) == '{') {
            return original; // Assume already escaped
        }
        
        // Avoid turning non-call statements into stored procedure calls and 
        // failing by generating syntax errors such as "execute select ..."
        // Ideally users should not use callable statements except for SPs.
        if (sql.length() > 6) {
            String keyword = sql.substring(0, 7);
            if (keyword.equalsIgnoreCase("select ") 
                || keyword.equalsIgnoreCase("insert ") 
                || keyword.equalsIgnoreCase("update ")
                || keyword.equalsIgnoreCase("delete ")) {
                return original;
            }
        }

        if (sql.length() > 4 && sql.substring(0, 5).equalsIgnoreCase("exec ")) {
            sql = sql.substring(4).trim();
        } else if (sql.length() > 7 && sql.substring(0, 8).equalsIgnoreCase("execute ")){
            sql = sql.substring(7).trim();
        }

        if (sql.length() > 1 && sql.charAt(0) == '?') {
            sql = sql.substring(1).trim();

            if (sql.length() < 1 || sql.charAt(0) != '=') {
                return original; // Give up, error will be reported elsewhere
            }

            sql = sql.substring(1).trim();

            // OK now reconstruct as JDBC escaped call
            return "{?=call " + sql + '}';
        }

        return "{call " + sql + '}';
    }

    /**
     * Find a parameter by name.
     *
     * @param name The name of the parameter to locate.
     * @param set True if function is called from a set / register method.
     * @return The parameter index as an <code>int</code>.
     * @throws SQLException
     */
    int findParameter(final String name, final boolean set)
        throws SQLException {
        checkOpen();
        for (int i = 0; i < parameters.length; i++){
            if (parameters[i].name != null && parameters[i].name.equalsIgnoreCase(name))
                return i + 1;
        }

        if (set && !name.equalsIgnoreCase("@return_status")) {
            for (int i = 0; i < parameters.length; i++){
                if (parameters[i].name == null) {
                    parameters[i].name = name;

                    return i + 1;
                }
            }
        }

        throw new SQLException(Messages.get("error.callable.noparam", name), "07000");
    }

    /**
     * Retrieve the value of an output parameter.
     *
     * @param parameterIndex the ordinal position of the parameter
     * @return the parameter value as an <code>Object</code>
     * @throws SQLException if the parameter has not been set
     */
    Object getOutputValue(final int parameterIndex)
            throws SQLException {
        checkOpen();
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
     * Execute the SQL batch on a MS server.
     * @param size the total size of the batch.
     * @param executeSize the maximum number of statements to send in one request.
     * @param counts the returned update counts.
     * @return Chained exceptions linked to a <code>SQLException</code>.
     * @throws SQLException
     */
    SQLException executeMSBatch(final int size, 
                                final int executeSize, 
                                final ArrayList<Integer> counts)
    throws SQLException
    {
        if (parameters.length == 0) {
            // There are no parameters each SQL call is the same so
            // execute as a simple batch
            // NB. This chains back up to JtdsStatement eventually
            return super.executeMSBatch(size, executeSize, counts);
        }
        SQLException sqlEx = null;
        for (int i = 0; i < size;) {
            Object value = batchValues.get(i++);
            // Execute batch now if max size reached or end of batch
            boolean executeNow = (i % executeSize == 0) || i == size;

            // procName will contain the procedure name for CallableStatements
            // and null for PreparedStatements
            tdsExecute(sql, procName, (ParamInfo[])value, false, 0, -1, -1, executeNow);

            // If the batch has been sent, process the results
            if (executeNow) {
                sqlEx = getBatchCounts(counts, sqlEx);

                // If a serious error then we stop execution now as count 
                // is too small.
                if (sqlEx != null && counts.size() != i) {
                    break;
                }
            }
        }
        return sqlEx;
    }

    /**
     * Execute the SQL batch on a Sybase server.
     * <p/>For the rare case of CallableStatement batches each statement
     * is executed individually. This ensures that problems with the server
     * reading into the middle of a statement are avoided.
     * See bug report [1374518] for more details.
     * @param size the total size of the batch.
     * @param executeSize the maximum number of statements to send in one request.
     * @param counts the returned update counts.
     * @return Chained exceptions linked to a <code>SQLException</code>.
     * @throws SQLException
     */
    SQLException executeSybaseBatch(final int size, 
                                    final int executeSize, 
                                    final ArrayList<Integer> counts)
    throws SQLException
    {
        if (parameters.length == 0) {
            // No parameters so we can execute as a simple batch
            return super.executeSybaseBatch(size, executeSize, counts);
        }

        SQLException sqlEx = null;
        
        for (int i = 0; i < size;) {
            Object value = batchValues.get(i);
            ++i;
            tdsExecute(sql, procName, (ParamInfo[])value, true, 0, -1, -1, true);

            // If the batch has been sent, process the results
            sqlEx = getBatchCounts(counts, sqlEx);
 
            // If a serious error then we stop execution now as count 
            // is too small.
            if (sqlEx != null && counts.size() != i) {
                break;
            }
        }
        return sqlEx;
    }


// ---------- java.sql.CallableStatement methods follow ----------

    
    public ParameterMetaData getParameterMetaData() throws SQLException {
        checkOpen();
        if (procName == null || procName.length() == 0) {
            // fall back on PreparedStatement method
            return super.getParameterMetaData();
        }
        String catalog = connection.getCatalog();
        String schema  = null;
        String spName;
        // procName can be a fully qualified name
        int dotPos = procName.lastIndexOf('.');
        if (dotPos > 0) {
            spName = procName.substring(dotPos + 1);

            int nextPos = procName.lastIndexOf('.', dotPos-1);
            if (nextPos + 1 < dotPos) {
                schema = procName.substring(nextPos + 1, dotPos);
                if (schema.trim().length() == 0) {
                    schema = null;
                }
            }
            dotPos = nextPos;
            nextPos = procName.lastIndexOf('.', dotPos-1);
            if (nextPos + 1 < dotPos) {
                catalog = procName.substring(nextPos + 1, dotPos);
            }
        } else {
            spName = procName;
        }
        //
        // Now use the standard meta data method to get the parameters
        //
        DatabaseMetaData dbmd = connection.getMetaData();
        ResultSet rs = dbmd.getProcedureColumns(catalog, schema, spName, "%");
        if (!rs.next()) {
            if (spName.toLowerCase().startsWith("sp_")) {
                // OK See if a system procedure instead
                rs = dbmd.getProcedureColumns("master", "dbo", spName, "%");
                if (!rs.next()) {
                    // fall back on PreparedStatement method
                    return super.getParameterMetaData();
                }
            } else {
                // fall back on PreparedStatement method
                return super.getParameterMetaData();
            }
        }
        ParamInfo pcopy[] = parameters.clone();
        int i = 0;
        //
        // Merge the column meta data into parameters
        //
        do {
            if (i >= pcopy.length) {
                // Fewer user parameters than the proc
                break;
            }
            if (rs.getString(4).equalsIgnoreCase("@return_value")) {
                if (!pcopy[i].isRetVal) {
                    // User did not specify a return param so skip
                    continue;
                }
            } else {
                if (pcopy[i].isRetVal) {
                    // User specified a return param but no meta data
                    pcopy[i].jdbcType = Types.INTEGER;
                    pcopy[i].sqlType = "int";
                    pcopy[i].length    = 11;
                    pcopy[i].precision = 12;
                    pcopy[i].scale     = 0;
                    pcopy[i].isSet     = true;
                    pcopy[i].value     = null;
                    i++;
                    if (i >= pcopy.length) {
                        break;
                    }
                }
            }
            pcopy[i].isOutput  = (rs.getInt(5) == DatabaseMetaData.procedureColumnInOut ||
                                    rs.getInt(5) == DatabaseMetaData.procedureColumnOut);
            pcopy[i].jdbcType  = rs.getInt(6);
            pcopy[i].sqlType   = rs.getString(7);
// FIXME: check for every server type which one is correct
//            pcopy[i].precision = rs.getInt(7);
//            pcopy[i].sqlType   = rs.getString(8);
            pcopy[i].precision = rs.getInt(8);
            pcopy[i].length    = rs.getInt(9);
            pcopy[i].scale     = rs.getInt(10);
            pcopy[i].isSet     = true;
            pcopy[i].value     = (rs.getInt(12) == DatabaseMetaData.procedureNullable)? "": null;
            i++;
        } while (rs.next());
        
        // Will never reach here
        return new ParameterMetaDataImpl(pcopy, connection);
    }
    
    public boolean wasNull() throws SQLException {
        checkOpen();

        return paramWasNull;
    }

    public byte getByte(int parameterIndex) throws SQLException {
        return ((Integer) Support.convert(connection, getOutputValue(parameterIndex), java.sql.Types.TINYINT, null)).byteValue();
    }

    public double getDouble(int parameterIndex) throws SQLException {
        return ((Double) Support.convert(connection, getOutputValue(parameterIndex), java.sql.Types.DOUBLE, null)).doubleValue();
    }

    public float getFloat(int parameterIndex) throws SQLException {
        return ((Float) Support.convert(connection, getOutputValue(parameterIndex), java.sql.Types.REAL, null)).floatValue();
    }

    public int getInt(int parameterIndex) throws SQLException {
        return ((Integer) Support.convert(connection, getOutputValue(parameterIndex), java.sql.Types.INTEGER, null)).intValue();
    }

    public long getLong(int parameterIndex) throws SQLException {
        return ((Long) Support.convert(connection, getOutputValue(parameterIndex), java.sql.Types.BIGINT, null)).longValue();
    }

    public short getShort(int parameterIndex) throws SQLException {
        return ((Integer) Support.convert(connection, getOutputValue(parameterIndex), java.sql.Types.SMALLINT, null)).shortValue();
    }

    public boolean getBoolean(int parameterIndex) throws SQLException {
        return ((Boolean) Support.convert(connection, getOutputValue(parameterIndex), java.sql.Types.BOOLEAN, null)).booleanValue();
    }

    public byte[] getBytes(int parameterIndex) throws SQLException {
        checkOpen();
        return ((byte[]) Support.convert(connection, getOutputValue(parameterIndex), java.sql.Types.VARBINARY, null));
    }

    public void registerOutParameter(int parameterIndex, int sqlType) throws SQLException {
        if (sqlType == java.sql.Types.DECIMAL
            || sqlType == java.sql.Types.NUMERIC) {
            registerOutParameter(parameterIndex, sqlType, ConnectionImpl.DEFAULT_SCALE);
        } else {
            registerOutParameter(parameterIndex, sqlType, 0);
        }
    }

    public void registerOutParameter(int parameterIndex, int sqlType, int scale)
        throws SQLException {
        checkOpen();

        if (scale < 0 || scale > connection.getMaxPrecision()) {
            throw new SQLException(Messages.get("error.generic.badscale"), "HY092");
        }

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

        // If the user requested String/byte[] instead of LOBs, do the conversion
        if (!connection.getUseLOBs()) {
            value = Support.convertLOB(value);
        }

        return value;
    }

    public String getString(int parameterIndex) throws SQLException {
        checkOpen();
        return (String) Support.convert(connection, getOutputValue(parameterIndex),
                java.sql.Types.VARCHAR, null);
    }

    public void registerOutParameter(int parameterIndex, int sqlType, String typeName)
        throws SQLException {
        notImplemented("CallableStatement.registerOutParameter(int, int, String");
    }

    public byte getByte(String parameterName) throws SQLException {
        return getByte(findParameter(parameterName, false));
    }

    public double getDouble(String parameterName) throws SQLException {
        return getDouble(findParameter(parameterName, false));
    }

    public float getFloat(String parameterName) throws SQLException {
        return getFloat(findParameter(parameterName, false));
    }

    public int getInt(String parameterName) throws SQLException {
        return getInt(findParameter(parameterName, false));
    }

    public long getLong(String parameterName) throws SQLException {
        return getLong(findParameter(parameterName, false));
    }

    public short getShort(String parameterName) throws SQLException {
        return getShort(findParameter(parameterName, false));
    }

    public boolean getBoolean(String parameterName) throws SQLException {
        return getBoolean(findParameter(parameterName, false));
    }

    public byte[] getBytes(String parameterName) throws SQLException {
        return getBytes(findParameter(parameterName, false));
    }

    public void setByte(String parameterName, byte x) throws SQLException {
        setByte(findParameter(parameterName, true), x);
    }

    public void setDouble(String parameterName, double x) throws SQLException {
        setDouble(findParameter(parameterName, true), x);
    }

    public void setFloat(String parameterName, float x) throws SQLException {
        setFloat(findParameter(parameterName, true), x);
    }

    public void registerOutParameter(String parameterName, int sqlType)
        throws SQLException {
        registerOutParameter(findParameter(parameterName, true), sqlType);
    }

    public void setInt(String parameterName, int x) throws SQLException {
        setInt(findParameter(parameterName, true), x);
    }

    public void setNull(String parameterName, int sqlType) throws SQLException {
        setNull(findParameter(parameterName, true), sqlType);
    }

    public void registerOutParameter(String parameterName, int sqlType, int scale)
        throws SQLException {
        registerOutParameter(findParameter(parameterName, true), sqlType, scale);
    }

    public void setLong(String parameterName, long x) throws SQLException {
        setLong(findParameter(parameterName, true), x);
    }

    public void setShort(String parameterName, short x) throws SQLException {
        setShort(findParameter(parameterName, true), x);
    }

    public void setBoolean(String parameterName, boolean x) throws SQLException {
        setBoolean(findParameter(parameterName, true), x);
    }

    public void setBytes(String parameterName, byte[] x) throws SQLException {
        setBytes(findParameter(parameterName, true), x);
    }

    public BigDecimal getBigDecimal(int parameterIndex) throws SQLException {
        return (BigDecimal) Support.convert(connection,
                getOutputValue(parameterIndex), java.sql.Types.DECIMAL, null);
    }

    public BigDecimal getBigDecimal(int parameterIndex, int scale) throws SQLException {
        BigDecimal bd = (BigDecimal) Support.convert(connection,
                getOutputValue(parameterIndex), java.sql.Types.DECIMAL, null);

        return bd.setScale(scale);
    }

    public URL getURL(int parameterIndex) throws SQLException {
        checkOpen();
        String url = (String) Support.convert(connection,
                getOutputValue(parameterIndex), java.sql.Types.VARCHAR, null);

        try {
            return new java.net.URL(url);
        } catch (MalformedURLException e) {
            throw new SQLException(Messages.get("error.resultset.badurl", url), "22000");
        }
    }

    public Array getArray(int parameterIndex) throws SQLException {
        notImplemented("CallableStatement.getArray");
        return null;
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
        return (java.sql.Date) Support.convert(connection,
                getOutputValue(parameterIndex), java.sql.Types.DATE, null);
    }

    public Ref getRef(int parameterIndex) throws SQLException {
        notImplemented("CallableStatement.getRef");
        return null;
    }

    public Time getTime(int parameterIndex) throws SQLException {
        return (Time) Support.convert(connection, getOutputValue(parameterIndex), java.sql.Types.TIME, null);
    }

    public Timestamp getTimestamp(int parameterIndex) throws SQLException {
        return (Timestamp) Support.convert(connection, getOutputValue(parameterIndex), java.sql.Types.TIMESTAMP, null);
    }

    public void setAsciiStream(String parameterName, InputStream x, int length)
        throws SQLException {
        setAsciiStream(findParameter(parameterName, true), x, length);
    }

    public void setBinaryStream(String parameterName, InputStream x, int length)
        throws SQLException {
        setBinaryStream(findParameter(parameterName, true), x, length);
    }

    public void setCharacterStream(String parameterName, Reader reader, int length)
        throws SQLException {
        setCharacterStream(findParameter(parameterName, true), reader, length);
    }

    public Object getObject(String parameterName) throws SQLException {
        return getObject(findParameter(parameterName, false));
    }

    public void setObject(String parameterName, Object x) throws SQLException {
        setObject(findParameter(parameterName, true), x);
    }

    public void setObject(String parameterName, Object x, int targetSqlType)
        throws SQLException {
        setObject(findParameter(parameterName, true), x, targetSqlType);
    }

    public void setObject(String parameterName, Object x, int targetSqlType, int scale)
        throws SQLException {
        setObject(findParameter(parameterName, true), x, targetSqlType, scale);
    }

    @Override
    public Object getObject(int parameterIndex, Map<String, Class<?>> map) throws SQLException {
        notImplemented("CallableStatement.getObject(int, Map)");
        return null;
    }

    public String getString(String parameterName) throws SQLException {
        return getString(findParameter(parameterName, false));
    }

    public void registerOutParameter(String parameterName, int sqlType, String typeName)
        throws SQLException {
        notImplemented("CallableStatement.registerOutParameter(String, int, String");
    }

    public void setNull(String parameterName, int sqlType, String typeName)
        throws SQLException {
        notImplemented("CallableStatement.setNull(String, int, String");
    }

    public void setString(String parameterName, String x) throws SQLException {
        setString(findParameter(parameterName, true), x);
    }

    public BigDecimal getBigDecimal(String parameterName) throws SQLException {
        return getBigDecimal(findParameter(parameterName, false));
    }

    public void setBigDecimal(String parameterName, BigDecimal x)
        throws SQLException {
        setBigDecimal(findParameter(parameterName, true), x);
    }

    public URL getURL(String parameterName) throws SQLException {
        return getURL(findParameter(parameterName, false));
    }

    public void setURL(String parameterName, URL x) throws SQLException {
        setObject(findParameter(parameterName, true), x);
    }

    public Array getArray(String parameterName) throws SQLException {
        return getArray(findParameter(parameterName, false));
    }

    public Blob getBlob(String parameterName) throws SQLException {
        return getBlob(findParameter(parameterName, false));
    }

    public Clob getClob(String parameterName) throws SQLException {
        return getClob(findParameter(parameterName, false));
    }

    public Date getDate(String parameterName) throws SQLException {
        return getDate(findParameter(parameterName, false));
    }

    public void setDate(String parameterName, Date x) throws SQLException {
        setDate(findParameter(parameterName, true), x);
    }

    public Date getDate(int parameterIndex, Calendar cal) throws SQLException {
        java.sql.Date date = getDate(parameterIndex);

        if (date != null && cal != null) {
            date = new java.sql.Date(new DateTime().timeToZone(date, cal));
        }

        return date;
    }

    public Ref getRef(String parameterName) throws SQLException {
        return getRef(findParameter(parameterName, false));
    }

    public Time getTime(String parameterName) throws SQLException {
        return getTime(findParameter(parameterName, false));
    }

    public void setTime(String parameterName, Time x) throws SQLException {
        setTime(findParameter(parameterName, true), x);
    }

    public Time getTime(int parameterIndex, Calendar cal) throws SQLException {
        java.sql.Time time = getTime(parameterIndex);

        if (time != null && cal != null) {
            time = new java.sql.Time(new DateTime().timeToZone(time, cal));
        }

        return time;
    }

    public Timestamp getTimestamp(String parameterName) throws SQLException {
        return getTimestamp(findParameter(parameterName, false));
    }

    public void setTimestamp(String parameterName, Timestamp x) throws SQLException {
        setTimestamp(findParameter(parameterName, true), x);
    }

    public Timestamp getTimestamp(int parameterIndex, Calendar cal)
        throws SQLException {
        Timestamp timestamp = getTimestamp(parameterIndex);

        if (timestamp != null && cal != null) {
            timestamp = new Timestamp(new DateTime().timeToZone(timestamp, cal));
        }

        return timestamp;
    }

    @Override
    public Object getObject(String parameterName, Map<String, Class<?>> map) throws SQLException {
         return getObject(findParameter(parameterName, false), map);
    }

    public Date getDate(String parameterName, Calendar cal) throws SQLException {
        return getDate(findParameter(parameterName, false), cal);
    }

    public Time getTime(String parameterName, Calendar cal) throws SQLException {
        return getTime(findParameter(parameterName, false), cal);
    }

    public Timestamp getTimestamp(String parameterName, Calendar cal)
        throws SQLException {
        return getTimestamp(findParameter(parameterName, false), cal);
    }

    public void setDate(String parameterName, Date x, Calendar cal)
        throws SQLException {
        setDate(findParameter(parameterName, true), x, cal);
    }

    public void setTime(String parameterName, Time x, Calendar cal)
        throws SQLException {
        setTime(findParameter(parameterName, true), x, cal);
    }

    public void setTimestamp(String parameterName, Timestamp x, Calendar cal)
        throws SQLException {
        setTimestamp(findParameter(parameterName, true), x, cal);
    }

    @Override
    public Reader getCharacterStream(int parameterIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Reader getCharacterStream(String parameterName) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Reader getNCharacterStream(int parameterIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Reader getNCharacterStream(String parameterName) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public NClob getNClob(int parameterIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public NClob getNClob(String parameterName) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public String getNString(int parameterIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public String getNString(String parameterName) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public RowId getRowId(int parameterIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public RowId getRowId(String parameterName) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public java.sql.SQLXML getSQLXML(int parameterIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public java.sql.SQLXML getSQLXML(String parameterName) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setAsciiStream(String parameterName, InputStream x)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setAsciiStream(String parameterName, InputStream x, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setBinaryStream(String parameterName, InputStream x)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setBinaryStream(String parameterName, InputStream x, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setBlob(String parameterName, Blob x) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setBlob(String parameterName, InputStream inputStream)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setBlob(String parameterName, InputStream inputStream,
            long length) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setCharacterStream(String parameterName, Reader reader)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setCharacterStream(String parameterName, Reader reader,
            long length) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setClob(String parameterName, Clob x) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setClob(String parameterName, Reader reader)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setClob(String parameterName, Reader reader, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNCharacterStream(String parameterName, Reader value)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNCharacterStream(String parameterName, Reader value,
            long length) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNClob(String parameterName, NClob value) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNClob(String parameterName, Reader reader)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNClob(String parameterName, Reader reader, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNString(String parameterName, String value)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setRowId(String parameterName, RowId x) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setSQLXML(String parameterName, java.sql.SQLXML xmlObject)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    //// JDBC4.1 demarcation, do NOT put any JDBC3/4.0 code below this line ////

    @Override
    public void closeOnCompletion() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public boolean isCloseOnCompletion() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public <T> T getObject(int parameterIndex, Class<T> type) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public <T> T getObject(String parameterName, Class<T> type) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }
}