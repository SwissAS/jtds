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
import java.sql.Array;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.ParameterMetaData;
import java.sql.PreparedStatement;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.text.NumberFormat;
import java.util.concurrent.Semaphore;



/**
 * jTDS implementation of the java.sql.PreparedStatement interface.
 * <p>
 * Implementation notes:
 * <ol>
 * <li>Generally a simple subclass of Statement mainly adding support for the
 *     setting of parameters.
 * <li>The stream logic is taken over from the work Brian did to add Blob support
 *     to the original jTDS.
 * <li>Use of Statement specific method calls eg executeQuery(sql) is blocked by
 *     this version of the TdsCore. This is unlike the original jTDS but inline
 *     with all the other JDBC drivers that I have been able to test.
 * </ol>
 *
 * @author Mike Hutchinson
 * @author Brian Heineman
 * @version $Id: PreparedStatementImpl.java,v 1.6 2009-12-07 08:56:33 ickzon Exp $
 */
public class PreparedStatementImpl extends StatementImpl implements PreparedStatement {

    /** The SQL statement being prepared. */
    final String sql;
    /** The original SQL statement provided at construction time. */
    private final String originalSql;
    /** The procedure name for CallableStatements. */
    String procName;
    /** The parameter list for the call. */
    ParamInfo[] parameters;

    /** The first SQL keyword in the SQL string.*/
    private String sqlWord;
    /** True to return generated keys. */
    private boolean returnKeys;
    /** Used to format numeric values when scale is specified. */
    private static NumberFormat f = NumberFormat.getInstance();
    /** Collection of handles used by this statement */
    private Collection<ProcEntry> handles;

    /**
     * Construct a new preparedStatement object.
     *
     * @param connection The parent connection.
     * @param sql   The SQL statement to prepare.
     * @param resultSetType The result set type eg SCROLLABLE etc.
     * @param concurrency The result set concurrency eg READONLY.
     * @param returnKeys True if generated keys should be returned.
     * @throws SQLException
     */
    PreparedStatementImpl(final ConnectionImpl connection,
                          final String sql,
                          final int resultSetType,
                          final int concurrency,
                          final boolean returnKeys)
        throws SQLException 
    {
        super(connection, resultSetType, concurrency);

        // returned by toString()
        originalSql = sql;

        ArrayList<ParamInfo> params = new ArrayList<ParamInfo>();
        String[] parsedSql = SQLParser.parse(sql, params, connection, false);

        if (parsedSql[0].length() == 0) {
            throw new SQLException(Messages.get("error.prepare.nosql"), "07000");
        }

        if (parsedSql[1].length() > 1) {
            // Procedure call
            procName = parsedSql[1];
        }

        sqlWord = parsedSql[2];

        if (returnKeys && sqlWord.equalsIgnoreCase("insert")) {
            if (connection.getServerType() == TdsCore.SQLSERVER
                    && connection.getMetaData().getDatabaseMajorVersion() >= 8) {
                this.sql = parsedSql[0] + " SELECT SCOPE_IDENTITY() AS " + GEN_KEY_COL;
            } else {
                this.sql = parsedSql[0] + " SELECT @@IDENTITY AS " + GEN_KEY_COL;
            }
            this.returnKeys = true;
        } else {
            this.sql = parsedSql[0];
            this.returnKeys = false;
        }
        
        parameters = params.toArray(new ParamInfo[params.size()]);
    }

    /**
     * Returns the SQL command provided at construction time.
     */
    public String toString() {
        return originalSql;
    }

    /**
     * Report that user tried to call a method not supported on this type of statement.
     *
     * @param method The method name to report in the error message.
     * @throws SQLException
     */
    void notSupported(final String method) throws SQLException {
        throw new SQLException(
                Messages.get("error.generic.notsup", method), "HYC00");
    }

    /**
     * Execute the SQL batch on a MS server.
     * <p/>When running with prepareSQL = 1 or 3, the driver will first prepare
     * temporary stored procedures or statements for each parameter combination
     * found in the batch. The handles to these pre-preared statements will then
     * be used to execute the actual batch statements. 
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
            return super.executeMSBatch(size, executeSize, counts);
        }
        SQLException sqlEx = null;
        String procHandle[] =  new String[size];
        //
        // Prepare any statements before executing the batch
        //
        if (connection.getDataSource().getPrepareSql() == TdsCore.TEMPORARY_STORED_PROCEDURES
             || connection.getDataSource().getPrepareSql() == TdsCore.PREPARE) {
            for (int i = 0; i < size; i++) {
                // Prepare the statement
                procHandle[i] = connection.prepareSQL(this, sql, (ParamInfo[])batchValues.get(i), false, false);
            }
        }
        for (int i = 0; i < size;) {
            Object value = batchValues.get(i++);
            // Execute batch now if max size reached or end of batch
            boolean executeNow = (i % executeSize == 0) || i == size;

            // procName will contain the procedure name for CallableStatements
            // and null for PreparedStatements
            tdsExecute(sql, procHandle[i-1], (ParamInfo[])value, false, 0, -1, -1, executeNow);

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
     * <p/>Sybase needs to have the SQL concatenated into one TDS language
     * packet followed by up to 1000 parameters. This method will be overriden for 
     * CallableStatements.
     * @param size the total size of the batch.
     * @param executeSize the maximum number of statements to send in one request.
     * @param counts the returned update counts.
     * @return Chained exceptions linked to a <code>SQLException</code>.
     * @throws SQLException
     */
    SQLException executeSybaseBatch(final int size, 
                                    int executeSize, 
                                    final ArrayList<Integer> counts)
    throws SQLException
    {
        if (parameters.length == 0) {
            // There are no parameters each SQL call is the same so
            // execute as a simple batch
            return super.executeSybaseBatch(size, executeSize, counts);
        }        
        // Revise the executeSize down if too many parameters will be required.
        // Be conservative the actual maximums are 256 for older servers and 2048.
        int maxParams = 
            (connection.getMetaData().getDatabaseMajorVersion() < 12 ||
             (connection.getMetaData().getDatabaseMajorVersion() == 12 &&
              connection.getMetaData().getDatabaseMinorVersion() < 50))? 200: 1000;
        StringBuffer sqlBuf = new StringBuffer(size * 32);
        SQLException sqlEx = null;
        if (parameters.length * executeSize > maxParams) {
            executeSize = maxParams / parameters.length;
            if (executeSize <= 0) {
                executeSize = 1;
            }
        }
        ArrayList<ParamInfo> paramList = new ArrayList<ParamInfo>();
        for (int i = 0; i < size;) {
            Object value = batchValues.get(i);
            ++i;
            // Execute batch now if max size reached or end of batch
            boolean executeNow = (i % executeSize == 0) || i == size;

            int offset = sqlBuf.length();
            sqlBuf.append(sql).append(' ');
            for (int n = 0; n < parameters.length; n++) {
                ParamInfo p = ((ParamInfo[])value)[n];
                // Allow for the position of the '?' marker in the buffer
                p.markerPos += offset;
                paramList.add(p);
            }
            if (executeNow) {
                ParamInfo args[];
                args = paramList.toArray(new ParamInfo[paramList.size()]);
                tdsExecute(sqlBuf.toString(), null, args, false, 0, -1, -1, true);
                sqlBuf.setLength(0);
                paramList.clear();
                // If the batch has been sent, process the results
                sqlEx = getBatchCounts(counts, sqlEx);

                // If a serious error or a server error then we stop
                // execution now as count is too small.
                if (sqlEx != null && counts.size() != i) {
                    break;
                }
            }
        }
        return sqlEx;
    }

    /**
     * Check the supplied index and return the selected parameter.
     *
     * @param parameterIndex the parameter index 1 to n.
     * @return the parameter as a <code>ParamInfo</code> object.
     * @throws SQLException if the statement is closed;
     *                      if <code>parameterIndex</code> is less than 0;
     *                      if <code>parameterIndex</code> is greater than the
     *                      number of parameters;
     *                      if <code>checkIfSet</code> was <code>true</code>
     *                      and the parameter was not set
     */
    ParamInfo getParameter(final int parameterIndex) throws SQLException {
        checkOpen();

        if (parameterIndex < 1 || parameterIndex > parameters.length) {
            throw new SQLException(Messages.get("error.prepare.paramindex",
                                                      Integer.toString(parameterIndex)),
                                                      "07009");
        }

        ParamInfo pi = parameters[parameterIndex - 1];

        return pi;
    }

    /**
     * Generic setObject method.
     *
     * @param parameterIndex Parameter index 1 to n.
     * @param x The value to set.
     * @param targetSqlType The java.sql.Types constant describing the data.
     * @param scale The decimal scale -1 if not set.
     */
    public void setObjectBase(final int parameterIndex, 
                              Object x, 
                              int targetSqlType, 
                              final int scale)
            throws SQLException 
    {
        checkOpen();

        int length = 0;

        if (targetSqlType == java.sql.Types.CLOB) {
            targetSqlType = java.sql.Types.LONGVARCHAR;
        } else if (targetSqlType == java.sql.Types.BLOB) {
            targetSqlType = java.sql.Types.LONGVARBINARY;
        }

        if (x != null) {
            x = Support.convert(connection, x, targetSqlType, null);

            if (scale >= 0) {
                if (x instanceof BigDecimal) {
                    x = ((BigDecimal) x).setScale(scale, BigDecimal.ROUND_HALF_UP);
                } else if (x instanceof Number) {
                    synchronized (f) {
                        f.setGroupingUsed(false);
                        f.setMaximumFractionDigits(scale);
                        x = Support.convert(connection, f.format(x), targetSqlType, null);
                    }
                }
            }

            if (x instanceof Blob) {
                Blob blob = (Blob) x;
                length = (int) blob.length();
                x = blob.getBinaryStream();
            } else if (x instanceof Clob) {
                Clob clob = (Clob) x;
                length = (int) clob.length();
                x = clob.getCharacterStream();
            }
        }

        setParameter(parameterIndex, x, targetSqlType, scale, length);
    }

    /**
     * Update the ParamInfo object for the specified parameter.
     *
     * @param parameterIndex Parameter index 1 to n.
     * @param x The value to set.
     * @param targetSqlType The java.sql.Types constant describing the data.
     * @param scale The decimal scale -1 if not set.
     * @param length The length of the data item.
     */
    void setParameter(final int parameterIndex, 
                      Object x, 
                      final int targetSqlType, 
                      final int scale, 
                      final int length)
        throws SQLException 
    {
        ParamInfo pi = getParameter(parameterIndex);

        if (Support.getJdbcTypeName(targetSqlType).equals("ERROR")) {
            throw new SQLException(Messages.get("error.generic.badtype",
                                Integer.toString(targetSqlType)), "HY092");
        }

        // Update parameter descriptor
        if (targetSqlType == java.sql.Types.DECIMAL
            || targetSqlType == java.sql.Types.NUMERIC) {

            pi.precision = connection.getMaxPrecision();
            if (x instanceof BigDecimal) {
                x = Support.normalizeBigDecimal((BigDecimal) x, pi.precision);
                pi.scale = ((BigDecimal) x).scale();
            } else {
                pi.scale = (scale < 0) ? ConnectionImpl.DEFAULT_SCALE : scale;
            }
        } else {
            pi.scale = (scale < 0) ? 0 : scale;
        }

        if (x instanceof String) {
            pi.length = ((String) x).length();
        } else if (x instanceof byte[]) {
            pi.length = ((byte[]) x).length;
        } else {
            pi.length   = length;
        }

        if (x instanceof Date) {
            x = new DateTime((Date) x);
        } else if (x instanceof Time) {
            x = new DateTime((Time) x);
        } else if (x instanceof Timestamp) {
            x = new DateTime((Timestamp) x);
        }

        pi.value       = x;
        pi.jdbcType    = targetSqlType;
        pi.isSet       = true;
        pi.isUnicode   = connection.getSendUnicode();
    }

    /**
     * Update the cached column meta data information.
     *
     * @param value The Column meta data array.
     */
    void setColMetaData(final ColInfo[] value) {
        colMetaData = value;
    }

    /**
     * Update the cached parameter meta data information.
     *
     * @param value The Column meta data array.
     */
    void setParamMetaData(final ParamInfo[] value) {
        for (int i = 0; value != null && i < value.length && i < parameters.length; i++) {
            if (!parameters[i].isSet) {
                // Only update parameter descriptors if the user
                // has not yet set them.
                parameters[i].jdbcType = value[i].jdbcType;
                parameters[i].isOutput = value[i].isOutput;
                parameters[i].precision = value[i].precision;
                parameters[i].scale = value[i].scale;
                parameters[i].sqlType = value[i].sqlType;
            }
        }
    }

    /**
     * Retrieve the prepared statement handle collection.
     * @return The handle list as a <code>Collection</code>.
     */
    Collection<ProcEntry> getStatementHandles()
    {
        if (handles == null) {
            handles = new HashSet<ProcEntry>(10);
        }
        return handles;
    }
    
// -------------------- java.sql.PreparedStatement methods follow -----------------

    public void close() throws SQLException {
        try {
            super.close();
        } finally {
            // Null these fields to reduce memory usage while
            // wating for Statement.finalize() to execute.
            handles = null;
            parameters = null;
        }
    }

    public int executeUpdate() throws SQLException {
        checkOpen();
        initialize();
        
        Semaphore connectionLock = null;
        try {
            connectionLock = lockConnection();
            if (procName == null && !(this instanceof CallableStatementImpl)) {
                // The connection lock ensures that rollback() isn't called
                // between the moment when the statement is prepared and the moment
                // when it's executed.
                String spName = connection.prepareSQL(this, sql, parameters, returnKeys, false);
                executeSQL(sql, spName, parameters, returnKeys, true, false);
            } else {
                executeSQL(sql, procName, parameters, returnKeys, true, false);
            }
        } finally {
            freeConnection(connectionLock);
        }

        int res = getUpdateCount();
        return res == -1 ? 0 : res;
    }

    public void addBatch() throws SQLException {
        checkOpen();

        if (batchValues == null) {
            batchValues = new ArrayList<Object>();
        }

        if (parameters.length == 0) {
            // This is likely to be an error. Batch execution
            // of a prepared statement with no parameters means
            // exactly the same SQL will be executed each time!
            batchValues.add(sql);
        } else {
            //
            // Check all parameters are input only and have values set
            //
            for (int i = 0; i < parameters.length; i++){
                if (parameters[i].isOutput) {
                    throw new SQLException(Messages.get("error.prepare.outbatchparam",
                            Integer.toString(i + 1)), "07000");
                }
                if (!parameters[i].isSet){
                    throw new SQLException(Messages.get("error.prepare.paramnotset",
                            Integer.toString(i + 1)), "07000");
                }
            }
            batchValues.add(parameters);

            ParamInfo tmp[] = new ParamInfo[parameters.length];

            for (int i = 0; i < parameters.length; ++i) {
                tmp[i] = (ParamInfo) parameters[i].clone();
            }

            parameters = tmp;
        }
    }

    public void clearParameters() throws SQLException {
        checkOpen();

        for (int i = 0; i < parameters.length; i++) {
            parameters[i].clearInValue();
        }
    }

    public boolean execute() throws SQLException {
        checkOpen();
        initialize();
        boolean useCursor = useCursor(returnKeys, sqlWord);

        Semaphore connectionLock = null;
        try {
            connectionLock = lockConnection();
            if (procName == null && !(this instanceof CallableStatementImpl)) {
                // The connection lock ensures that rollback() isn't called
                // between the moment when the statement is prepared and the moment
                // when it's executed.
                String spName = connection.prepareSQL(this, sql, parameters, returnKeys, useCursor);
                return executeSQL(sql, spName, parameters, returnKeys, false, useCursor);
            }
            return executeSQL(sql, procName, parameters, returnKeys, false, useCursor);
        } finally {
            freeConnection(connectionLock);
        }
    }

    public void setByte(int parameterIndex, byte x) throws SQLException {
        setParameter(parameterIndex, new Integer(x & 0xFF), java.sql.Types.TINYINT, 0, 0);
    }

    public void setDouble(int parameterIndex, double x) throws SQLException {
        setParameter(parameterIndex, new Double(x), java.sql.Types.DOUBLE, 0, 0);
    }

    public void setFloat(int parameterIndex, float x) throws SQLException {
        setParameter(parameterIndex, new Float(x), java.sql.Types.REAL, 0, 0);
    }

    public void setInt(int parameterIndex, int x) throws SQLException {
        setParameter(parameterIndex, new Integer(x), java.sql.Types.INTEGER, 0, 0);
    }

    public void setNull(int parameterIndex, int sqlType) throws SQLException {
        if (sqlType == java.sql.Types.CLOB) {
            sqlType = java.sql.Types.LONGVARCHAR;
        } else if (sqlType == java.sql.Types.BLOB) {
            sqlType = java.sql.Types.LONGVARBINARY;
        }

        setParameter(parameterIndex, null, sqlType, -1, 0);
    }

    public void setLong(int parameterIndex, long x) throws SQLException {
        setParameter(parameterIndex, new Long(x), java.sql.Types.BIGINT, 0, 0);
    }

    public void setShort(int parameterIndex, short x) throws SQLException {
        setParameter(parameterIndex, new Integer(x), java.sql.Types.SMALLINT, 0, 0);
    }

    public void setBoolean(int parameterIndex, boolean x) throws SQLException {
        setParameter(parameterIndex, x ? Boolean.TRUE : Boolean.FALSE, java.sql.Types.BOOLEAN, 0, 0);
    }

    public void setBytes(int parameterIndex, byte[] x) throws SQLException {
        setParameter(parameterIndex, x, java.sql.Types.BINARY, 0, 0);
    }

    public void setAsciiStream(int parameterIndex, InputStream inputStream, int length)
        throws SQLException {
        if (inputStream == null || length < 0) {
            setParameter(parameterIndex, null, java.sql.Types.LONGVARCHAR, 0, 0);
        } else {
            try {
                setCharacterStream(parameterIndex, new InputStreamReader(inputStream, "US-ASCII"), length);
            } catch (UnsupportedEncodingException e) {
                // Should never happen!
            }
        }
    }

    public void setBinaryStream(int parameterIndex, InputStream x, int length)
        throws SQLException {
        checkOpen();

        if (x == null || length < 0) {
            setBytes(parameterIndex, null);
        } else {
            setParameter(parameterIndex, x, java.sql.Types.LONGVARBINARY, 0, length);
        }
    }

    public void setUnicodeStream(int parameterIndex, InputStream inputStream, int length)
        throws SQLException {
        checkOpen();
        if (inputStream == null || length < 0) {
            setString(parameterIndex, null);
        } else {
            try {
               length /= 2;
               char[] tmp = new char[length];
               int pos = 0;
               int b1 = inputStream.read();
               int b2 = inputStream.read();

               while (b1 >= 0 && b2 >= 0 && pos < length) {
                   tmp[pos++] = (char) (((b1 << 8) &0xFF00) | (b2 & 0xFF));
                   b1 = inputStream.read();
                   b2 = inputStream.read();
               }
               setString(parameterIndex, new String(tmp, 0, pos));
            } catch (java.io.IOException e) {
                throw new SQLException(Messages.get("error.generic.ioerror",
                                                           e.getMessage()), "HY000");
            }
        }
    }

    public void setCharacterStream(int parameterIndex, Reader reader, int length)
        throws SQLException {
        if (reader == null || length < 0) {
            setParameter(parameterIndex, null, java.sql.Types.LONGVARCHAR, 0, 0);
        } else {
            setParameter(parameterIndex, reader, java.sql.Types.LONGVARCHAR, 0, length);
        }
    }

    public void setObject(int parameterIndex, Object x) throws SQLException {
        setObjectBase(parameterIndex, x, Support.getJdbcType(x), -1);
    }

    public void setObject(int parameterIndex, Object x, int targetSqlType)
        throws SQLException {
        setObjectBase(parameterIndex, x, targetSqlType, -1);
    }

    public void setObject(int parameterIndex, Object x, int targetSqlType, int scale)
        throws SQLException {
        checkOpen();
        if (scale < 0 || scale > connection.getMaxPrecision()) {
            throw new SQLException(Messages.get("error.generic.badscale"), "HY092");
        }
        setObjectBase(parameterIndex, x, targetSqlType, scale);
    }

    public void setNull(int parameterIndex, int sqlType, String typeName) throws SQLException {
        notImplemented("PreparedStatement.setNull(int, int, String)");
    }

    public void setString(int parameterIndex, String x) throws SQLException {
        setParameter(parameterIndex, x, java.sql.Types.VARCHAR, 0, 0);
    }

    public void setBigDecimal(int parameterIndex, BigDecimal x) throws SQLException {
        setParameter(parameterIndex, x, java.sql.Types.DECIMAL, -1, 0);
    }

    public void setURL(int parameterIndex, URL url) throws SQLException {
        setString(parameterIndex, (url == null)? null: url.toString());
    }

    public void setArray(int arg0, Array arg1) throws SQLException {
        notImplemented("PreparedStatement.setArray");
    }

    public void setBlob(int parameterIndex, Blob x) throws SQLException {
        if (x == null) {
            setBytes(parameterIndex, null);
        } else {
            long length = x.length();

            if (length > Integer.MAX_VALUE) {
                throw new SQLException(Messages.get("error.resultset.longblob"), "24000");
            }

            setBinaryStream(parameterIndex, x.getBinaryStream(), (int) x.length());
        }
    }

    public void setClob(int parameterIndex, Clob x) throws SQLException {
        if (x == null) {
            setString(parameterIndex, null);
        } else {
            long length = x.length();

            if (length > Integer.MAX_VALUE) {
                throw new SQLException(Messages.get("error.resultset.longclob"), "24000");
            }

            setCharacterStream(parameterIndex, x.getCharacterStream(), (int) x.length());
        }
    }

    public void setDate(int parameterIndex, Date x) throws SQLException {
        setParameter(parameterIndex, x, java.sql.Types.DATE, 0, 0);
    }

    public ParameterMetaData getParameterMetaData() throws SQLException {
        checkOpen();

        //
        // NB. This is usable only with the JDBC3 version of the interface.
        //
        if (connection.getServerType() == TdsCore.SYBASE ||
            connection.getServerType() == TdsCore.ANYWHERE) {
            // Sybase does return the parameter types for prepared sql.
            connection.prepareSQL(this, sql, new ParamInfo[0], false, false);
        }
        return new ParameterMetaDataImpl(parameters, connection);
    }

    public void setRef(int parameterIndex, Ref x) throws SQLException {
        notImplemented("PreparedStatement.setRef");
    }

    public ResultSet executeQuery() throws SQLException {
        checkOpen();
        initialize();
        boolean useCursor = useCursor(false, null);

        Semaphore connectionLock = null;
        try {
            connectionLock = lockConnection();
            if (procName == null && !(this instanceof CallableStatementImpl)) {
                // The connection lock ensures that rollback() isn't called
                // between the moment when the statement is prepared and the moment
                // when it's executed.
                String spName = connection.prepareSQL(this, sql, parameters, false, useCursor);
                return executeSQLQuery(sql, spName, parameters, useCursor);
            }
            return executeSQLQuery(sql, procName, parameters, useCursor);
        } finally {
            freeConnection(connectionLock);
        }
    }

    public ResultSetMetaData getMetaData() throws SQLException {
        checkOpen();
        if (connection.getServerType() == TdsCore.ANYWHERE)
            throw new SQLFeatureNotSupportedException();

        if (colMetaData == null && currentResult == null) {
            //
            // No cached meta data and no current ResultSet to
            // provide the meta data. Now need to query the server.
            //
            Semaphore connectionLock = null;
            try {
                connectionLock = lockConnection();
                if (connection.getServerType() == TdsCore.SYBASE) {
                    // Sybase can provide meta data as a by product of preparing the call.
                    connection.prepareSQL(this, sql, new ParamInfo[0], false, false);

                    if (colMetaData == null) {
                        return null; // Sorry still no go
                    }
                } else if (connection.getServerType() == TdsCore.ANYWHERE) {
                    // Sybase can provide meta data as a by product of preparing the call.
                    connection.prepareSQL(this, sql, new ParamInfo[0], false, false);

                    if (colMetaData == null) {
                        return null; // Sorry still no go
                    }
                } else {
                    // For Microsoft set all parameters to null and execute the query.
                    // SET FMTONLY ON asks the server just to return meta data.
                    // This only works for select statements
                    if (!sqlWord.equals("select")) {
                        return null;
                    }

                    // Copy parameters to avoid corrupting any values already set
                    // by the user as we need to set a flag and null out the data.
                    ParamInfo[] params = new ParamInfo[parameters.length];
                    for (int i = 0; i < params.length; i++) {
                        params[i] = new ParamInfo(parameters[i].markerPos, false);
                        params[i].isSet = true;
                    }

                    // Substitute nulls into SQL String
                    StringBuffer testSql = new StringBuffer(sql.length() + 128);
                    testSql.append("SET FMTONLY ON ");
                    testSql.append(
                            Support.substituteParameters(sql, params, connection));
                    testSql.append(" SET FMTONLY OFF");

                    try {
                        tdsExecute(testSql.toString(), null, null, false, 0, 0,0, true);
                        processResults(true);
                        ResultSetImpl rs = getTdsResultSet();
                        if (rs != null) {
                            colMetaData = rs.getColumns();
                        }
                    } catch (SQLException e) {
                        // Ensure FMTONLY is switched off!
                        submitSQL("SET FMTONLY OFF");
                        return null;
                    }
                }
            } finally {
                freeConnection(connectionLock);
            }
        }
        if (colMetaData == null) {
            // If we get here it is because we can use the meta
            // data from an existing ResultSet.
            colMetaData = currentResult.columns;
        }
        return new ResultSetMetaDataImpl(colMetaData,
                ResultSetImpl.getColumnCount(colMetaData),
                connection.getUseLOBs());
    }

    public void setTime(int parameterIndex, Time x) throws SQLException {
        setParameter( parameterIndex, x, java.sql.Types.TIME, 0, 0 );
    }

    public void setTimestamp(int parameterIndex, Timestamp x) throws SQLException {
        setParameter(parameterIndex, x, java.sql.Types.TIMESTAMP, 0, 0);
    }

    public void setDate(int parameterIndex, Date x, Calendar cal)
        throws SQLException {

        if (x != null && cal != null) {
            x = new java.sql.Date(new DateTime().timeFromZone(x, cal));
        }

        setDate(parameterIndex, x);
    }

    public void setTime(int parameterIndex, Time x, Calendar cal)
        throws SQLException {

        if (x != null && cal != null) {
            x = new Time(new DateTime().timeFromZone(x, cal));
        }

        setTime(parameterIndex, x);
    }

    public void setTimestamp(int parameterIndex, Timestamp x, Calendar cal)
        throws SQLException {

        if (x != null && cal != null) {
            x = new java.sql.Timestamp(new DateTime().timeFromZone(x, cal));
        }

        setTimestamp(parameterIndex, x);
    }

    public int executeUpdate(String sql) throws SQLException {
        notSupported("executeUpdate(String)");
        return 0;
    }

    public void addBatch(String sql) throws SQLException {
        notSupported("executeBatch(String)");
    }

    public boolean execute(String sql) throws SQLException {
        notSupported("execute(String)");
        return false;
    }

    public int executeUpdate(String sql, int getKeys) throws SQLException {
        notSupported("executeUpdate(String, int)");
        return 0;
    }

    public boolean execute(String arg0, int arg1) throws SQLException {
        notSupported("execute(String, int)");
        return false;
    }

    public int executeUpdate(String arg0, int[] arg1) throws SQLException {
        notSupported("executeUpdate(String, int[])");
        return 0;
    }

    public boolean execute(String arg0, int[] arg1) throws SQLException {
        notSupported("execute(String, int[])");
        return false;
    }

    public int executeUpdate(String arg0, String[] arg1) throws SQLException {
        notSupported("executeUpdate(String, String[])");
        return 0;
    }

    public boolean execute(String arg0, String[] arg1) throws SQLException {
        notSupported("execute(String, String[])");
        return false;
    }

    public ResultSet executeQuery(String sql) throws SQLException {
        notSupported("executeQuery(String)");
        return null;
    }

    @Override
    public void setAsciiStream(int parameterIndex, InputStream x)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setAsciiStream(int parameterIndex, InputStream x, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setBinaryStream(int parameterIndex, InputStream x)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setBinaryStream(int parameterIndex, InputStream x, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setBlob(int parameterIndex, InputStream inputStream)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setBlob(int parameterIndex, InputStream inputStream, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setCharacterStream(int parameterIndex, Reader reader)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setCharacterStream(int parameterIndex, Reader reader,
            long length) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setClob(int parameterIndex, Reader reader) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setClob(int parameterIndex, Reader reader, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNCharacterStream(int parameterIndex, Reader value)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNCharacterStream(int parameterIndex, Reader value,
            long length) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNClob(int parameterIndex, NClob value) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNClob(int parameterIndex, Reader reader) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNClob(int parameterIndex, Reader reader, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNString(int parameterIndex, String value)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setRowId(int parameterIndex, RowId x) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setSQLXML(int parameterIndex, java.sql.SQLXML xmlObject)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public boolean isPoolable() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setPoolable(boolean poolable) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }
}
