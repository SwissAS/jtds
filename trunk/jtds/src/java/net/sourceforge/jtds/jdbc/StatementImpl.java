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

import java.nio.charset.Charset;
import java.sql.BatchUpdateException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.concurrent.Semaphore;

import net.sourceforge.jtds.util.Logger;

/**
 * jTDS implementation of the java.sql.Statement interface.
 * <p/> This class includes a finalize method which increases the chances of the
 * statement being closed tidly in a pooled environment where the user has
 * forgotten to explicitly close the statement before it goes out of scope.
 *
 * @see java.sql.Statement
 * @see java.sql.Connection#createStatement()
 * @see java.sql.ResultSet
 *
 * @author Mike Hutchinson
 * @version $Id: StatementImpl.java,v 1.5 2009-09-27 12:59:02 ickzon Exp $
 */
public class StatementImpl implements java.sql.Statement {
    /*
     * Constants used in anticipation of JDBC 4
     */
    public static final int SQLXML = 2009;
    /*
     * Misc Constants.
     */
    /** Default fetchsize for resultsets. */
    static final int DEFAULT_FETCH_SIZE = 100;
    /** Default column name for generated keys. */
    static final String GEN_KEY_COL = "JTDS$GEN$KEY$VALUE";
    /** Used to optimize the {@link #getDynamicParameters()} call */
    static final ParamInfo[] EMPTY_PARAMETER_INFO = new ParamInfo[0];
    // 
    // Shared instance variables 
    //
    /** The connection owning this statement object. */
    ConnectionImpl connection;
    /** The current <code>ResultSet</code>. */
    ResultSetImpl currentResult;
    /** Batched SQL Statement array. */
    ArrayList<Object> batchValues;
    /** The cached column meta data. */
    ColInfo[] colMetaData;

    //
    // Private instance variables
    //
    /** The cursor name to be used for positioned updates. */
    private String cursorName;
    /** The read query timeout in seconds */
    private int queryTimeout;
    /** The fetch direction for result sets. */
    private int fetchDirection = ResultSet.FETCH_FORWARD;
    /** The type of result sets created by this statement. */
    private int resultSetType = ResultSet.TYPE_FORWARD_ONLY;
    /** The concurrency of result sets created by this statement. */
    private int resultSetConcurrency = ResultSet.CONCUR_READ_ONLY;
    /** The fetch size (default 100, only used by cursor
     * <code>ResultSet</code>s).
     */
    private int fetchSize = DEFAULT_FETCH_SIZE;
    /** True if this statement is closed. */
    private boolean closed;
    /** The maximum field size (not used at present). */
    private int maxFieldSize;
    /** The maximum number of rows to return (not used at present). */
    private int maxRows;
    /** True if SQL statements should be preprocessed. */
    private boolean escapeProcessing = true;
    /** Dummy result set for getGeneratedKeys. */
    private ResultSetImpl genKeyResultSet;
    /** List of open result sets. */
    private ArrayList<ResultSet> openResultSets;
    //
    // TDS Protcol context variables
    //
    /** The stored procedure return status. */
    private Integer returnStatus;
    /** The return parameter meta data object for the current procedure call. */
    private ParamInfo returnParam;
    /** The array of parameter meta data objects for the current procedure call. */
    private ParamInfo[] parameters;
    /** The index of the next output parameter to populate. */
    private int nextParam = -1;
    /** The head of the diagnostic messages chain. */
    private final SQLDiagnostic messages;
    /** The TDS Results. */
    protected ArrayList<Object> results; // FIXME: change visibility back to private as soon as the ASA impl is adapted accordingly
    /** Next result pointer. */
    private int nextResult;
    /** The array of column meta data objects for the current result set. */
    private ColInfo[] columns;
    /** The array of column data objects in the current row. */
    private Object[] rowBuffer;
    /** The dynamic parameters from the last TDS_DYNAMIC token. */
    private ColInfo[] dynamParamInfo;
    /** The dynamic parameter data from the last TDS_DYNAMIC token. */
    private Object[] dynamParamData;
    /** The current result set.*/
    private ResultSetImpl resultSet;
    /** Special result set for cursor ops. */
    private ResultSetImpl cursorResultSet;
    /** The base TdsCore instance. */
    private final TdsCore tds; 
    /** Only return the last update count. */
    private boolean lastUpdateCount;
    /** Executing batch. */
    private boolean executeBatch;
    
    /**
     * Construct a new Statement object.
     *
     * @param connection The parent connection.
     * @param resultSetType The result set type for example TYPE_FORWARD_ONLY.
     * @param resultSetConcurrency The concurrency for example CONCUR_READ_ONLY.
     */
    StatementImpl(final ConnectionImpl connection,
                  final int resultSetType,
                  final int resultSetConcurrency) throws SQLException 
    {
        if (Logger.isTraceActive()){
            Logger.printMethod(this, null, 
                    new Object[]{connection, new Integer(resultSetType), 
                                    new Integer(resultSetConcurrency)});
        }
        //
        // This is a good point to do common validation of the result set type
        //
        if (resultSetType < ResultSet.TYPE_FORWARD_ONLY
                || resultSetType > ResultSet.TYPE_SCROLL_SENSITIVE + 1) {
            String method;
            if (this instanceof CallableStatementImpl) {
                method = "prepareCall";
            } else if (this instanceof PreparedStatementImpl) {
                method = "prepareStatement";
            } else {
                method = "createStatement";
            }
            throw new SQLException(
                       Messages.get("error.generic.badparam",
                               "resultSetType",
                               method),
                    "HY092");
        }
        //
        // Ditto for the result set concurrency
        //
        if (resultSetConcurrency < ResultSet.CONCUR_READ_ONLY
                || resultSetConcurrency > ResultSet.CONCUR_UPDATABLE + 2) {
                String method;
                if (this instanceof CallableStatementImpl) {
                    method = "prepareCall";
                } else if (this instanceof PreparedStatementImpl) {
                    method = "prepareStatement";
                } else {
                    method = "createStatement";
                }
                throw new SQLException(
                        Messages.get("error.generic.badparam",
                                "resultSetConcurrency",
                                method),
                        "HY092");
        }

        this.connection = connection;
        this.resultSetType = resultSetType;
        this.resultSetConcurrency = resultSetConcurrency;
        int serverType = TdsCore.SQLSERVER;
        if (connection.getDataSource().getServerType().equals("sybase")) {
            serverType = TdsCore.SYBASE;
        } else if (connection.getDataSource().getServerType().equals("anywhere")) {
            serverType = TdsCore.ANYWHERE;
        }
        messages   = new SQLDiagnostic(serverType);
        results    = new ArrayList<Object>();
        tds        = connection.getBaseTds();
    }

    /**
     * Called when this object goes out of scope to close any
     * <code>ResultSet</code> object and this statement.
     */
    public void finalize() throws Throwable {
        super.finalize();
        try {
            if (!closed) {
                close();
            }
        } catch (SQLException e) {
            // Ignore errors
        }
    }

    /**
     * Check that this statement is still open.
     *
     * @throws SQLException if statement closed.
     */
    void checkOpen() throws SQLException {
        if (closed || connection == null || connection.isClosed()) {
            String name = getClass().getName();
            name = name.substring(name.lastIndexOf('.') + 1);
            name = name.substring(0, name.indexOf("Impl"));
            throw new SQLException(
                    Messages.get("error.generic.closed", name), "HY010");
        }
    }

    /**
     * Check that the exception is caused by the failure to open a
     * cursor and not by a more serious SQL error.
     *
     * @param e the exception returned by the cursor class
     * @throws SQLException if exception is not due to a cursor error
     */
    private void checkCursorException(final SQLException e) throws SQLException{
        //
        // Clear the cursorResultSet global that may have been left set
        // by MSCursorResultSet to prevent it being used for a subsequent
        // normal result set.
        //
        cursorResultSet = null;
        //
        if (connection == null
                || connection.isClosed()
                || "HYT00".equals(e.getSQLState())
                || "HY008".equals(e.getSQLState())) {
                // Serious error or timeout so return exception to caller
                throw e;
            }
        if (connection.getServerType() == TdsCore.SYBASE) {
            // Allow retry for Sybase
            return;
        }
        // FIXME: what about ASA?
        //
        // Check cursor specific errors and ranges for SQL Server
        //
        int error = e.getErrorCode();
        if (error >= 16900 && error <= 16999) {
            // Errors in this range are all related to the cursor API.
            // This is true for all versions of SQL Server.
            return;
        }
        if (error == 6819) {
            // A FOR XML clause was found
            return;
        }
        if (error == 8654) {
            // A inrow textptr exists
            return;
        }
        if (error == 8162) {
            // Formal parameter '%.*ls' was defined as OUTPUT but the actual
            // parameter not declared OUTPUT. This happens when trying to
            // execute a stored procedure with output parameters via a cursor.
            return;
        }
        //
        // More serious error we should rethrow the error and
        // not allow the driver to re-execute sql.
        //
        throw e;
    }

    /**
     * Report that user tried to call a method which has not been implemented.
     *
     * @param method The method name to report in the error message.
     * @throws SQLException
     */
    void notImplemented(final String method) throws SQLException {
        throw new SQLException(
                Messages.get("error.generic.notimp", method), "HYC00");
    }

    /**
     * Close current result set (if any).
     */
    private void closeCurrentResultSet() throws SQLException {
        try {
            if (currentResult != null) {
                currentResult.close();
            }
        } catch (SQLException e) {
            // Ignore
        } finally {
            currentResult = null;
        }
    }

    /**
     * Close all result sets.
     */
    private void closeAllResultSets() throws SQLException {
        try {
            if (openResultSets != null) {
                for (int i = 0; i < openResultSets.size(); i++) {
                    ResultSetImpl rs = (ResultSetImpl) openResultSets.get(i);
                    if (rs != null) {
                        rs.close();
                    }
                }
            }
            closeCurrentResultSet();
        } finally {
            openResultSets = null;
        }
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
        SQLException sqlEx = null;

        for (int i = 0; i < size;) {
            Object value = batchValues.get(i);
            ++i;
            // Execute batch now if max size reached or end of batch
            boolean executeNow = (i % executeSize == 0) || i == size;

           tdsExecute((String)value, null, null, false, 0, -1, -1, executeNow);

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
     * packet. This method will be overriden for PreparedStatements.
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
        StringBuilder sql = new StringBuilder(size * 32); // Make buffer reasonable size
        SQLException sqlEx = null;

        for (int i = 0; i < size;) {
            Object value = batchValues.get(i);
            ++i;
            // Execute batch now if max size reached or end of batch
            boolean executeNow = (i % executeSize == 0) || i == size;

            sql.append((String)value).append(' ');
            
            if (executeNow) {
                tdsExecute(sql.toString(), null, null, false, 0, -1, -1, true);
                sql.setLength(0);
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
     * Executes SQL to obtain a result set.
     *
     * @param sql       the SQL statement to execute
     * @param spName    optional stored procedure name
     * @param params    optional parameters
     * @param useCursor whether a cursor should be created for the SQL
     * @return the result set generated by the query
     */
    ResultSet executeSQLQuery(final String sql,
                              final String spName,
                              final ParamInfo[] params,
                              final boolean useCursor)
            throws SQLException {

        String warningMessage = null;
        //
        // Try to open a cursor result set if required
        //
        if (useCursor) {
            try {
                if (connection.getServerType() == TdsCore.SQLSERVER) {
                    currentResult =
                            new MSCursorResultSet(this,
                                    sql,
                                    spName,
                                    params);

                    return currentResult;
                }
                // Use client side cursor for Sybase
                currentResult =
                        new CachedResultSet(this,
                                sql,
                                spName,
                                params);

                return currentResult;
            } catch (SQLException e) {
                checkCursorException(e);
                warningMessage = '[' + e.getSQLState() + "] " + e.getMessage();
            }
        }

        //
        // Could not open a cursor (or was not requested) so try a direct select
        //
        if (spName != null
                && connection.getDataSource().getCacheMetaData()
                && connection.getDataSource().getPrepareSql() == TdsCore.PREPARE
                && colMetaData != null
                && connection.getServerType() == TdsCore.SQLSERVER) {
            // There is cached meta data available for this
            // prepared statement
            setColumns(colMetaData);
            tdsExecute(sql, spName, params, true, queryTimeout, maxRows,
                    maxFieldSize, true);
        } else {
            tdsExecute(sql, spName, params, false, queryTimeout, maxRows,
                    maxFieldSize, true);
        }

        // Update warning chain if cursor was downgraded before processing results
        if (warningMessage != null) {
            messages.addWarning(new SQLWarning(
                    Messages.get("warning.cursordowngraded", warningMessage), "01000"));
        }

        // Ignore update counts preceding the result set. All drivers seem to
        // do this.
        currentResult = getTdsResultSet();

        // check for server side errors
        messages.checkErrors();
        if (currentResult  == null) {
            throw new SQLException(
                    Messages.get("error.statement.noresult"), "24000");
        }

        return currentResult;
    }

    /**
     * Executes any type of SQL.
     *
     * @param sql        the SQL statement to execute
     * @param spName     optional stored procedure name
     * @param params     optional parameters
     * @param returnKeys whether the statement returns generated keys
     * @param update     whether the caller is {@link #executeUpdate}
     * @param useCursor  whether the requested result set type or concurrency
     *                   or connection properties request usage of a cursor
     * @return <code>true</code> if the first result is a result set
     * @throws SQLException if an error condition occurs
     */
    boolean executeSQL(final String sql,
                       final String spName,
                       final ParamInfo[] params,
                       final boolean returnKeys,
                       final boolean update,
                       final boolean useCursor)
            throws SQLException 
    {
       
        String warningMessage = null;
        //
        // For SQL Server, try to open a cursor result set if required
        // (and possible).
        //
        if (connection.getServerType() == TdsCore.SQLSERVER && !update && useCursor) {
            try {
                currentResult = new MSCursorResultSet(this, sql, spName, params);

                return true;
            } catch (SQLException e) {
                checkCursorException(e);
                warningMessage = '[' + e.getSQLState() + "] " + e.getMessage();
            }
        }

        //
        // We are talking to a Sybase server or we could not open a cursor
        // or we did not have a SELECT so just execute the SQL normally.
        //
        tdsExecute(sql, spName, params, false, queryTimeout, maxRows,
                maxFieldSize, true);

        if (warningMessage != null) {
            // Update warning chain if cursor was downgraded
            messages.addWarning(new SQLWarning(Messages.get(
                    "warning.cursordowngraded", warningMessage), "01000"));
        }

        if (update && getTdsResultSet() != null) {
            // Throw exception but queue up any previous ones
            SQLException ex = new SQLException(
                        Messages.get("error.statement.nocount"), "07000");
                ex.setNextException(messages.getExceptions());
                throw ex;
        }
        messages.checkErrors();
        currentResult = null;
        if (nextResult < results.size() && results.get(nextResult) instanceof ResultSetImpl) {
            currentResult = (ResultSetImpl)results.get(nextResult);
            return true;
        }
        return false;
    }

    /**
     * Initialize the <code>Statement</code>, by cleaning up all queued and
     * unprocessed results. Called by all execute methods.
     *
     * @throws SQLException if an error occurs
     */
    void initialize() throws SQLException {
        genKeyResultSet = null;
        clearWarnings();
        closeAllResultSets();
    }

    /**
     * Implements the common functionality for plain statement {@link #execute}
     * and {#link #executeUpdate}: basic checks, cleaning up of previous
     * results, setting up and executing the query and loading the first
     * results.
     *
     * @param sql    an SQL <code>INSERT</code>, <code>UPDATE</code> or
     *               <code>DELETE</code> statement or an SQL statement that
     *               returns nothing, such as an SQL DDL statement
     * @param autoGeneratedKeys a flag indicating whether auto-generated keys
     *               should be made available for retrieval
     * @param update boolean flag indicating whether the caller is
     *               {@link #executeUpdate} -- in this case an exception is
     *               thrown if the first result is not an update count and no
     *               cursor is created (direct execution)
     * @return <code>true</code> if the first result is a
     *         <code>ResultSet</code>, <code>false</code> if it's an update
     *         count
     * @see #execute
     * @see #executeUpdate
     */
    private boolean executeInternal(String sql, 
                                    final int autoGeneratedKeys, 
                                    final boolean update)
            throws SQLException 
    {
        initialize();

        if (sql == null || sql.length() == 0) {
            throw new SQLException(Messages.get("error.generic.nosql"), "HY000");
        }

        boolean returnKeys;
        String sqlWord = "";
        if (escapeProcessing) {
            String tmp[] = SQLParser.parse(sql, null, connection, false);

            if (tmp[1].length() != 0) {
                throw new SQLException(
                        Messages.get("error.statement.badsql"), "07000");
            }

            sql = tmp[0];
            sqlWord = tmp[2];
        } else {
            // Escape processing turned off so
            // see if we can extract "insert" from start of statement
            sql = sql.trim();
            if (sql.length() > 5) {
                sqlWord = sql.substring(0,6).toLowerCase();
            }
        }

        if (autoGeneratedKeys == RETURN_GENERATED_KEYS) {
            returnKeys = sqlWord.equals("insert");
        } else if (autoGeneratedKeys == NO_GENERATED_KEYS) {
            returnKeys = false;
        } else {
            throw new SQLException(
                    Messages.get("error.generic.badoption",
                            Integer.toString(autoGeneratedKeys),
                            "autoGeneratedKeys"),
                    "HY092");
        }

        if (returnKeys) {
            if (connection.getServerType() == TdsCore.SQLSERVER
                    && connection.getMetaData().getDatabaseMajorVersion() >= 8) {
                sql += " SELECT SCOPE_IDENTITY() AS " + GEN_KEY_COL;
            } else {
                sql += " SELECT @@IDENTITY AS " + GEN_KEY_COL;
            }
        }
        Semaphore connectionLock = null;
        try {
            connectionLock = lockConnection();
            if (update) {
                setLastUpdateCount(connection.getDataSource().getLastUpdateCount());
            }
            return executeSQL(sql, null, null, returnKeys, update,
                                !update && useCursor(returnKeys, sqlWord));
        } finally {
            setLastUpdateCount(false);
            freeConnection(connectionLock);
        }
    }

    /**
     * Determines whether a cursor should be used based on the requested result
     * set type and concurrency, whether a cursor name has been set, the
     * <code>useCursors</code> connection property has been set, the first
     * word in the SQL query is either SELECT or EXEC/EXECUTE and no generated
     * keys are returned.
     *
     * @param returnKeys indicates whether keys will be returned by the query
     * @param sqlWord    the first word in the SQL query; can be
     *                   <code>null</code> if the caller is
     *                   {@link #executeQuery}
     * @return <code>true</code> if a cursor should be used, <code>false</code>
     *         if not
     */
    boolean useCursor(final boolean returnKeys, final String sqlWord) {
        return (resultSetType != ResultSet.TYPE_FORWARD_ONLY
                    || resultSetConcurrency != ResultSet.CONCUR_READ_ONLY
                    || connection.getDataSource().getUseCursors()
                    || cursorName != null)
                && !returnKeys
                && (sqlWord == null || sqlWord.equals("select") || sqlWord.startsWith("exec"));
    }

    /**
     * Retrieve the default fetch size for this statement.
     *
     * @return the default fetch size for a new <code>ResultSet</code>
     */
    int getDefaultFetchSize() {
        return (0 < maxRows && maxRows < DEFAULT_FETCH_SIZE)
                ? maxRows : DEFAULT_FETCH_SIZE;
    }

    /**
     * Retrieve the closed status for this statement.
     * @return <code>boolean</code> true if statement closed.
     */
    @Override
    public boolean isClosed()
    {
        return closed;
    }
    
    /**
     * Retrieve the SQL cursor name.
     * @return The cursor name as a <code>String</code>.
     */
    String getCursorName()
    {
        return cursorName;
    }
        
    /**
     * Retrieve the update count from the current TDS token.
     *
     * @return The update count as an <code>Integer</code>.
     */
    private Integer getBatchUpdateCount() throws SQLException {
        if (nextResult < results.size()) {
            Object res = results.get(nextResult++);
            if (res instanceof ResultSetImpl) {
                // Serious error, statement must not return a result set
                throw new SQLException(
                        Messages.get("error.statement.batchnocount"),
                        "07000");                
            }
            return (Integer)res;
        }
        return null;
    }
        
    /**
     * Obtain the counts from a batch of SQL updates.
     * <p/>
     * If an error occurs Sybase will continue processing a batch consisting of
     * TDS_LANGUAGE records whilst SQL Server will usually stop after the first
     * error except when the error is caused by a duplicate key.
     * Sybase will also stop after the first error when executing RPC calls.
     * Care is taken to ensure that <code>SQLException</code>s are chained
     * because there could be several errors reported in a batch.
     *
     * @param counts the <code>ArrayList</code> containing the update counts
     * @param sqlEx  any previous <code>SQLException</code>(s) encountered
     * @return updated <code>SQLException</code> or <code>null</code> if no
     *         error has yet occured
     */
    SQLException getBatchCounts(final ArrayList<Integer> counts, 
                                SQLException sqlEx) {
        try {
            Integer count;
            while ((count = getBatchUpdateCount()) != null) {
                counts.add(count);
            }
            SQLException e = messages.getExceptions();
            if (e != null) {
                if (sqlEx == null) {
                    sqlEx = e;
                } else {
                    sqlEx.setNextException(e);
                }
            }
        } catch (SQLException e) {
            if (sqlEx == null) {
                sqlEx = e;
            } else {
                sqlEx.setNextException(e);
            }
        }
        messages.clearExceptions();
        return sqlEx;
    }

    //
    //       ------------------ TdsContext methods --------------------
    //
    //  --- The following routines are called back from the TdsCore instance ---
    //
    
    /**
     * Initialise the context ready for processing a new response.
     */
    void initContext()
    {
        Logger.printMethod(this, "initContext", null);
        results.clear();
        resultSet = null;
        rowBuffer = null;
        nextParam = -1;
        nextResult = 0;
        parameters = null;
        returnParam = null;
        returnStatus = null;
        dynamParamInfo = null;
        dynamParamData = null;        
        messages.clearExceptions();
    }

    /**
     * Set the dynamic parameter meta data (TDS 5.0 only).
     * @param ci the metadata for the dynamic parameters that will be returned.
     */
    void setDynamParamInfo(final ColInfo[] ci) {
        dynamParamInfo = ci;
    }
    
    /**
     * Set the actual dynamic parameter values (TDS 5.0 only).
     * @param data the dynamic parameter data values.
     */
    void setDynamParamData(final Object[] data) {
        dynamParamData = data;
    }
    
    /**
     * Retrieve the dynamic parameter meta data (TDS 5.0 only). 
     * @return the parameter data as a <code>ColInfo[]</code>.
     */
    ColInfo[] getDynamParamInfo()
    {
        return dynamParamInfo;
    }
    
    /**
     * Retrieve the dynamic parameter data values (TDS 5.0 only). 
     * @return the parameter data as a <code>Object[]</code>.
     */
    Object[] getDynamParamData()
    {
        return dynamParamData;
    }
    
    /**
     * Set the column meta data describing the current result set.
     * @param columns the result set metadata.
     */
    void setColumns(final ColInfo[] columns) {
        this.columns = columns;
    }
    
    /**
     * Retrieve the current result set column descriptors.
     *
     * @return The column descriptors as a <code>ColInfo[]</code>.
     */
    ColInfo[] getColumns() {
        return columns;
    }
    
    /**
     * Retrieve the current result set row buffer.
     * @return the row buffer as an <code>Object[]</code>.
     */
    Object[] getRowBuffer()  {
        if (resultSet == null) {
            // With TDS 4.2 & 7.0 cursor operations with no meta data do not
            // send any result set meta data packets at all not even the 
            // empty one sent by TDS8+
            addResultSet();
        }
//        if (rowBuffer == null || rowBuffer.length != columns.length) {
            rowBuffer = new Object[columns.length];
//        }
        return rowBuffer;
    }
        
    /**
     * Add a new ResultSet to the result queue.
     */
    void addResultSet() {
        if (columns == null) {
            throw new IllegalStateException("No column metadata available");
        }
        if (cursorResultSet == null) {
            resultSet = new ResultSetImpl(this, ResultSet.CONCUR_READ_ONLY, ResultSet.TYPE_FORWARD_ONLY);
        } else {
            resultSet = cursorResultSet;
            cursorResultSet = null;
        }
        resultSet.setColumns(columns);
        results.add(resultSet);
    }
        
    /**
     * Add a new data row to the current TdsResultSet.
     * @throws SQLException
     */
    void addRow() {
        resultSet.addRow(rowBuffer);
    }
    
    /**
     * Add an update count to the result queue.
     * @param count the count value.
     */
    void addUpateCount(final Integer count) {
        results.add(count);
    }
    
    /**
     * Set the end of result set flag on the current result set.
     * @throws SQLException
     */
    void setEndOfResults() throws SQLException {
        if (resultSet == null) {
            throw new IllegalStateException("Expected a current result set");
        }
        resultSet.setEof();
        //
        // See if this result set was actually the results of a
        // select @@identity for a getGeneratedKeys.
        //
        if (resultSet.getColumns().length == 1 
            && resultSet.getColumns()[0].name.equalsIgnoreCase(StatementImpl.GEN_KEY_COL)) {
            // Save the result set and contents
            if (genKeyResultSet == null) {
                genKeyResultSet = resultSet;
                genKeyResultSet.getColumns()[0].name = "ID";
            } else {
                genKeyResultSet.append(resultSet);
            }
            // Now delete generated keys RS from general results stack
            results.remove(results.size()-1);
        }
        resultSet = null;
        rowBuffer = null;
    }

    /**
     * Set the RPC parameter values.
     * @param parameters the parameter list.
     */
    void setParameters(final ParamInfo[] parameters) {
        this.parameters = parameters;
        if (parameters != null && parameters[0].isRetVal) {
            nextParam = 0;
            returnParam = parameters[0];
        }
    }
    
    /**
     * Retrieve the RPC parameter list.
     * @return the parameter list as a <code>ParamInfo[]</code>.
     */
    ParamInfo[] getParameters() {
        return parameters;
    }
    
    /**
     * Set the stored procedure return parameter to an integer value.
     * @param value the return status value.
     * @throws SQLException
     */
    void setReturnParam(final int value) throws SQLException {
        returnStatus = new Integer(value);
        if (returnParam != null) {
            returnParam.setOutValue(Support.convert(connection,
                    returnStatus,
                    returnParam.jdbcType,
                    null));
        }
    }
    
    /**
     * Set the stored procedure return parameter to an Object value.
     * @param value the return status value.
     * @param col the parameter meta data.
     * @throws SQLException
     */
    void setReturnParam(final Object value, final ColInfo col) throws SQLException 
    {
        if (returnParam != null) {
            if (value != null) {
                returnParam.setOutValue(
                    Support.convert(connection, value,
                                    returnParam.jdbcType,
                                    col.charset));
            } else {
                returnParam.setOutValue(null);
            }
        }
        
    }
    
    /**
     * Set the next output parameter value from the result stream.
     * @param value the parameter value.
     * @param col the parameter metadata.
     * @throws SQLException
     */
    void setNextOutputParam(final Object value, final ColInfo col) throws SQLException 
    {
        if (parameters == null) {
            return; // TODO Error if not assigned?
        }
        while (++nextParam < parameters.length) {
            if (parameters[nextParam].isOutput) {
                Charset charset;
                if (col != null) {
                    charset = col.charset;
                } else {
                    charset = connection.getCharset();
                }
                if (value != null) {
                    parameters[nextParam].setOutValue(
                        Support.convert(connection, value,
                                parameters[nextParam].jdbcType,
                                charset));
                } else {
                    parameters[nextParam].setOutValue(null);
                }
                break;
            }
        }        
    }
    
    /**
     * Retrieve the parameter meta data from a Sybase prepare.
     *
     * @return The parameter descriptors as a <code>ParamInfo[]</code>.
     */
    ParamInfo[] getDynamicParameters() {
        if (dynamParamInfo != null) {
            ParamInfo[] params = new ParamInfo[dynamParamInfo.length];

            for (int i = 0; i < params.length; i++) {
                ColInfo ci = dynamParamInfo[i];
                params[i] = new ParamInfo(ci, ci.realName, null, 0);
            }

            return params;
        }

        return EMPTY_PARAMETER_INFO;
    }
    
    /**
     * Retrieve the value of the next parameter index.
     * @return the index value as an <code>int</code>.
     */
    int getParamIndex() {
        return nextParam;
    }
    
    //
    // ---- These methods called from higher level routines in the driver ----
    //
    
    /**
     * Set last update count.
     * @param value the new value of the lastUpdateCount flag.
     */
    void setLastUpdateCount(final boolean value) {
        lastUpdateCount = value;
    }
    
    /**
     * Retrieve the last update count flag.
     * @return the value of the last update count flag as a <code>boolean</code>.
     */
    boolean isLastUpdateCount() {
        return lastUpdateCount;
    }
    
    /**
     * Set executeBatch flag.
     * @param value the new value of the executeBatch flag.
     */
    void setExecuteBatch(final boolean value) {
        executeBatch = value;
    }
    
    /**
     * Retrieve the executeBatch flag.
     * @return the value of the exeuteBatch flag as a <code>boolean</code>.
     */
    boolean isExecuteBatch() {
        return executeBatch;
    }


    /**
     * Obtain an exclusive lock on the connection to prevent other
     * requests interleaving with this one.
     * @return the connection lock as a <code>Sempahore</code>.
     * @throws SQLException
     */
    Semaphore lockConnection() throws SQLException
    {
        return tds.getMutex(this);
    }

    /**
     * Free the exclusive lock on the connection.
     * @param connectionLock the connection lock object.
     */
    void freeConnection(final Semaphore connectionLock) {
        // Ensure that cursor result set cannot be accidentally reused
        cursorResultSet = null;
        // 
        if (connectionLock != null) {
            connectionLock.release();
        }
    }
    
    /**
     * Send a simple SQL statement to the server.
     * @param sql the SQL statement to execute.
     * @throws SQLException
     */
    void submitSQL(final String sql) throws SQLException {
        tds.submitSQL(this, sql);
    }
    
    /**
     * Obtain more data from the TDS results stream.
     * @param all set to true to empty result queue.
     * @throws SQLException
     */
    synchronized void processResults(final boolean all) throws SQLException {
        tds.processResults(this, all);
    }
        
    /**
     * Retrieve the diagnostic messages object.
     * @return the diagnostic messages as a <code>SQLDiagnostic</code> object.
     */
    SQLDiagnostic getMessages()
    {
        return messages;
    }
    
    /**
     * Retrieve the return status for the current stored procedure.
     *
     * @return The return status as an <code>Integer</code>.
     */
    Integer getReturnStatus() {
        return returnStatus;
    }
        
    
    /**
     * Retrieve the current result set.
     *
     * @return The result set as a <code>ResultSetImpl</code> or null 
     * if there is no result set or more than one in the response.
     */
    ResultSetImpl getTdsResultSet( ) throws SQLException
    {
        ResultSetImpl target = null;
        for (int i = 0; i < results.size(); i++) {
            Object result = results.get(i);
            if (result instanceof ResultSetImpl) {
                if (target != null) {
                    // More than one result set!
                    target = null;
                    break;
                }
                target = (ResultSetImpl)result;
            }
        }
        return target;
    }
    
    /**
     * Retrieve the last update count.
     *
     * @return The update count as an <code>int</code>.
     */
     int getTdsUpdateCount( ) throws SQLException
     {
        for (int i = results.size() - 1; i >= 0; i--) {
            Object res = results.get(i);
            if (res instanceof Integer) {
                return ((Integer)res).intValue(); 
            }
        }
        return -1;
     }

     /**
     * Send an SQL statement with optional parameters to the server.
     *
     * @param sql          SQL statement to execute
     * @param procName     stored procedure to execute or <code>null</code>
     * @param parameters   parameters for call or null
     * @param noMetaData   suppress meta data for cursor calls
     * @param timeOut      optional query timeout or 0
     * @param maxRows      the maximum number of data rows to return (-1 to
     *                     leave unaltered)
     * @param maxFieldSize the maximum number of bytes in a column to return
     *                     (-1 to leave unaltered)
     * @param sendNow      whether to send the request now or not
     * @throws SQLException if an error occurs
     */
    void tdsExecute(final String sql,
                    final String procName,
                    final ParamInfo[] parameters,
                    final boolean noMetaData,
                    final int timeOut,
                    final int maxRows,
                    final int maxFieldSize,
                    final boolean sendNow)
            throws SQLException {
         //
         // Send the request to the server
         tds.executeSQL(this, sql, procName, parameters, 
                        noMetaData, timeOut, maxRows, 
                        maxFieldSize, sendNow);         
    }

    /**
     * For cursor operations we want the TDS layer to update the
     * current cursor result set and not create a new one for each
     * fetch operation.
     * @param rs the cursor result set.
     */
    void setCursorResultSet(final ResultSetImpl rs) {
        this.cursorResultSet = rs;
    }
    
    // ------------------ java.sql.Statement methods ----------------------

    public int getFetchDirection() throws SQLException {
        checkOpen();

        return fetchDirection;
    }

    public int getFetchSize() throws SQLException {
        checkOpen();

        return fetchSize;
    }

    public int getMaxFieldSize() throws SQLException {
        checkOpen();

        return maxFieldSize;
    }

    public int getMaxRows() throws SQLException {
        checkOpen();

        return maxRows;
    }

    public int getQueryTimeout() throws SQLException {
        checkOpen();

        return queryTimeout;
    }

    public int getResultSetConcurrency() throws SQLException {
        checkOpen();

        return resultSetConcurrency;
    }

    public int getResultSetHoldability() throws SQLException {
        checkOpen();

        return ResultSet.HOLD_CURSORS_OVER_COMMIT;
    }

    public int getResultSetType() throws SQLException {
        checkOpen();

        return resultSetType;
    }
    
    public int getUpdateCount() throws SQLException {
        checkOpen();
        if (nextResult < results.size()) {
            Object cnt = results.get(nextResult);
            if (cnt instanceof Integer) {
                int count = ((Integer)results.get(nextResult)).intValue();
                return count < 0? 0: count;
            }
        }
        return -1;
    }

    public void cancel() throws SQLException {
        checkOpen();

        tds.cancel(this, false);
    }

    public void clearBatch() throws SQLException {
        checkOpen();

        if (batchValues != null) {
            batchValues.clear();
        }
    }

    public void clearWarnings() throws SQLException {
        checkOpen();

        messages.clearWarnings();
    }

    public void close() throws SQLException {
        Logger.printMethod(this, "close", null);
        if (!closed) {
            SQLException closeEx = null;
            try {
                closeAllResultSets();
                messages.checkErrors();
            } catch (SQLException ex) {
                if (!"HYT00".equals(ex.getSQLState())
                        && !"HY008".equals(ex.getSQLState())) {
                    // Only throw exceptions not caused by cancels or timeouts
                    closeEx = ex;
                }
            } finally {
                SQLException releaseEx = null;
                try {
                    // Check for server side errors
                    messages.checkErrors();
                } catch (SQLException ex) {
                    // Remember any exception thrown
                    releaseEx = ex;
                    // Queue up any result set close exceptions
                    if (closeEx != null) {
                        releaseEx.setNextException(closeEx);
                    }
                } finally {
                    // Clean up everything
                    closed = true;
                    connection.removeStatement(this);
                    connection = null;

                    // Re-throw any caught exception
                    if (releaseEx != null) {
                        throw releaseEx;
                    }
                }
            }
            // Throw any exception caught during result set close
            if (closeEx != null) {
                throw closeEx;
            }
        } 
    }

    public boolean getMoreResults() throws SQLException {
        checkOpen();

        return getMoreResults(CLOSE_ALL_RESULTS);
    }

    /**
     * Execute batch of SQL Statements.
     * <p/>
     * The JDBC3 standard says that the behaviour of this method must be
     * consistent for any DBMS. As Sybase (and to a lesser extent SQL Server)
     * will sometimes continue after a batch execution error, the only way to
     * comply with the standard is to always return an array of update counts
     * the same size as the batch list. Slots in the array beyond the last
     * executed statement are set to <code>EXECUTE_FAILED</code>.
     *
     * @return update counts as an <code>int[]</code>
     */
    public int[] executeBatch()
            throws SQLException, BatchUpdateException {
        checkOpen();
        initialize();

        if (batchValues == null || batchValues.size() == 0) {
            return new int[0];
        }
        int size = batchValues.size();
        int executeSize = connection.getDataSource().getBatchSize();
        executeSize = (executeSize == 0) ? Integer.MAX_VALUE : executeSize;
        SQLException sqlEx = null;
        ArrayList<Integer> counts = new ArrayList<Integer>(size);
        
        Semaphore connectionLock = null;
        try {
            connectionLock = lockConnection();
            setExecuteBatch(true);
            setLastUpdateCount(connection.getDataSource().getLastUpdateCount());
            if (connection.getServerType() == TdsCore.SYBASE ||
                connection.getServerType() == TdsCore.ANYWHERE &&
                connection.getTdsVersion() == TdsCore.TDS50) {
                sqlEx = executeSybaseBatch(size, executeSize, counts);
            } else {
                sqlEx = executeMSBatch(size, executeSize, counts);
            }
            //
            // Ensure array is the same size as the original statement list
            //
            //
            // Copy the update counts into the int array
            //
            int updateCounts[] = new int[size];
            int results = counts.size();
            for (int i = 0; i < results && i < updateCounts.length; i++) {
                updateCounts[i] = counts.get(i).intValue();
            }
            //
            // Pad any remaining slots with EXECUTE_FAILED
            //
            for (int i = results; i < updateCounts.length; i++) {
                updateCounts[i] = Statement.EXECUTE_FAILED;
            }
            //
            // See if we should return an exception
            //
            if (sqlEx != null) {
                BatchUpdateException batchEx =
                        new BatchUpdateException(sqlEx.getMessage(),
                                                 sqlEx.getSQLState(),
                                                 sqlEx.getErrorCode(),
                                                 updateCounts);
                // Chain any other exceptions
                batchEx.setNextException(sqlEx.getNextException());
                throw batchEx;
            }
            return updateCounts;
        } catch (BatchUpdateException ex) {
            // If it's a BatchUpdateException let it go
            throw ex;
        } catch (SQLException ex) {
            // An SQLException can only occur while sending the batch
            // (getBatchCounts() doesn't throw SQLExceptions), so we have to
            // end the batch and return the partial results
            // FIXME What should we send here to flush out the batch?
            // Come to think of it, is there any circumstance under which this
            // could actually happen without the connection getting closed?
            // No counts will have been returned either as last packet will not
            // have been sent.
            throw new BatchUpdateException(ex.getMessage(), ex.getSQLState(),
                    ex.getErrorCode(), new int[0]);
        } finally {
            setLastUpdateCount(false);
            setExecuteBatch(false);
            freeConnection(connectionLock);
            clearBatch();
        }
    }

    public void setFetchDirection(int direction) throws SQLException {
        checkOpen();
        switch (direction) {
        case ResultSet.FETCH_UNKNOWN:
        case ResultSet.FETCH_REVERSE:
        case ResultSet.FETCH_FORWARD:
            fetchDirection = direction;
            break;

        default:
            throw new SQLException(
                    Messages.get("error.generic.badoption",
                            Integer.toString(direction),
                            "direction"),
                    "24000");
        }
    }

    public void setFetchSize(int rows) throws SQLException {
        checkOpen();

        if (rows < 0) {
            throw new SQLException(
                    Messages.get("error.generic.optltzero", "setFetchSize"),
                    "HY092");
        } else if (maxRows > 0 && rows > maxRows) {
            throw new SQLException(
                    Messages.get("error.statement.gtmaxrows"), "HY092");
        }
        
        if (rows == 0) {
            rows = getDefaultFetchSize();
        }
        fetchSize = rows;
    }

    public void setMaxFieldSize(int max) throws SQLException {
        checkOpen();

        if (max < 0) {
            throw new SQLException(
                Messages.get("error.generic.optltzero", "setMaxFieldSize"),
                    "HY092");
        }

        maxFieldSize = max;
    }

    public void setMaxRows(int max) throws SQLException {
        checkOpen();

        if (max < 0) {
            throw new SQLException(
                Messages.get("error.generic.optltzero", "setMaxRows"),
                    "HY092");
        }
        if (max > 0 && max < fetchSize && cursorName == null) {
            // Just for consistency with setFetchSize()
            fetchSize = max;
        }
        maxRows = max;
    }

    public void setQueryTimeout(int seconds) throws SQLException {
        checkOpen();

        if (seconds < 0) {
            throw new SQLException(
                Messages.get("error.generic.optltzero", "setQueryTimeout"),
                    "HY092");
        }

        queryTimeout = seconds;
    }

    public boolean getMoreResults(int current) throws SQLException {
        checkOpen();

        switch (current) {
            case CLOSE_ALL_RESULTS:
                closeAllResultSets();
                break;
            case CLOSE_CURRENT_RESULT:
                closeCurrentResultSet();
                break;
            case KEEP_CURRENT_RESULT:
                // If there is an open result set it is transferred to
                // the list of open result sets. For ResultSetImpl
                // result sets we cache the remaining data. For CachedResultSet
                // result sets the data is already cached.
                if (openResultSets == null) {
                    openResultSets = new ArrayList<ResultSet>();
                }
                if (currentResult instanceof MSCursorResultSet
                        || currentResult instanceof CachedResultSet) {
                    // NB. Due to restrictions on the way API cursors are
                    // created, MSCursorResultSet can never be followed by
                    // any other result sets, update counts or return variables.
                    openResultSets.add(currentResult);
                } else if (currentResult != null) {
                    openResultSets.add(currentResult);
                }
                currentResult = null;
                break;
            default:
                throw new SQLException(
                        Messages.get("error.generic.badoption",
                                Integer.toString(current),
                                "current"),
                        "HY092");
        }
        //
        // If fetching subsequent results cache any pending result sets first
        //
        if (resultSet != null) {
            synchronized(this) {
                while (resultSet != null && !resultSet.isEof()) {
                    tds.processResults(this, false);
                }
            }
        }
        //
        // Throw any pending SQLExceptions
        //
        messages.checkErrors();
        currentResult = null;
        //
        // Now find next result set or count
        //
        while (++nextResult < results.size()) {
            Object res = results.get(nextResult);
            if (res instanceof ResultSetImpl) {
                currentResult = (ResultSetImpl)res;
                return true;
            }
            int count = ((Integer)res).intValue();
            if (count == -1 || count >= 0) {
                // Valid count not SUCCESS_NO_INFO or EXECUTE_FAILED
                return false;
            }
        }
        
        return false;
    }

    public void setEscapeProcessing(boolean enable) throws SQLException {
        checkOpen();

        escapeProcessing = enable;
    }

    public int executeUpdate(String sql) throws SQLException {
        return executeUpdate(sql, NO_GENERATED_KEYS);
    }

    public void addBatch(String sql) throws SQLException {
        checkOpen();

        if (sql == null) {
            throw new NullPointerException();
        }

        if (batchValues == null) {
            batchValues = new ArrayList<Object>();
        }

        if (escapeProcessing) {
            String tmp[] = SQLParser.parse(sql, null, connection, false);

            if (tmp[1].length() != 0) {
                throw new SQLException(
                        Messages.get("error.statement.badsql"), "07000");
            }

            sql = tmp[0];
        }

        batchValues.add(sql);
    }

    public void setCursorName(String name) throws SQLException {
        checkOpen();
        cursorName = name;
        if (name != null) {
            // Reset statement type to JDBC 1 default.
            resultSetType = ResultSet.TYPE_FORWARD_ONLY;
            fetchSize = 1; // Needed for positioned updates
        }
    }

    public boolean execute(String sql) throws SQLException {
        checkOpen();

        return executeInternal(sql, NO_GENERATED_KEYS, false);
    }

    public int executeUpdate(String sql, int autoGeneratedKeys) throws SQLException {
        checkOpen();

        if (executeInternal(sql, autoGeneratedKeys, true)) {
            // Throw exception but queue up any previous ones
            SQLException ex = new SQLException(
                    Messages.get("error.statement.nocount"), "07000");
            ex.setNextException(messages.getExceptions());
            throw ex;            
        }
        
        int res = getUpdateCount();
        return res == -1 ? 0 : res;
    }

    public boolean execute(String sql, int autoGeneratedKeys) throws SQLException {
        checkOpen();

        return executeInternal(sql, autoGeneratedKeys, false);
    }

    public int executeUpdate(String sql, int[] columnIndexes) throws SQLException {
        checkOpen();

        if (columnIndexes == null) {
            throw new SQLException(
                Messages.get("error.generic.nullparam", "executeUpdate"),"HY092");
        } else if (columnIndexes.length != 1) {
            throw new SQLException(
                Messages.get("error.generic.needcolindex", "executeUpdate"),"HY092");
        }

        return executeUpdate(sql, RETURN_GENERATED_KEYS);
    }

    public boolean execute(String sql, int[] columnIndexes) throws SQLException {
        checkOpen();

        if (columnIndexes == null) {
            throw new SQLException(
                Messages.get("error.generic.nullparam", "execute"),"HY092");
        } else if (columnIndexes.length != 1) {
            throw new SQLException(
                Messages.get("error.generic.needcolindex", "execute"),"HY092");
        }

        return executeInternal(sql, RETURN_GENERATED_KEYS, false);
    }

    public Connection getConnection() throws SQLException {
        checkOpen();

        return connection;
    }

    public ResultSet getGeneratedKeys() throws SQLException {
        checkOpen();

        if (genKeyResultSet == null) {
            String colNames[] = {"ID"};
            int    colTypes[] = {Types.INTEGER};
            //
            // Return an empty result set
            //
            ResultSetImpl rs = new ResultSetImpl(this, colNames, colTypes);
            rs.setResultSetConcurrency(ResultSet.CONCUR_READ_ONLY);
            genKeyResultSet = rs;
        }

        return genKeyResultSet;
    }

    public ResultSet getResultSet() throws SQLException {
        checkOpen();
        //
        if (currentResult instanceof MSCursorResultSet/* ||
            currentResult instanceof CachedResultSet*/) {
            return currentResult;
        }
        //
        // See if we are returning a forward read only resultset
        //
        if (currentResult == null ||
            (resultSetType == ResultSet.TYPE_FORWARD_ONLY &&
                    resultSetConcurrency == ResultSet.CONCUR_READ_ONLY)) {
            return currentResult;
        }
        //
        // OK Now create a CachedResultSet based on the existing result set.
        //
        //
        // OK If the user requested an updateable result set tell them
        // they can't have one!
        //
        if (resultSetConcurrency != ResultSet.CONCUR_READ_ONLY) {
            getMessages().addWarning(new SQLWarning(
                Messages.get("warning.cursordowngraded",
                             "CONCUR_READ_ONLY"), "01000"));
        }
        //
        // If the user requested a scroll sensitive cursor tell them
        // they can't have that either!
        //
        if (resultSetType >= ResultSet.TYPE_SCROLL_SENSITIVE) {
            currentResult.setResultSetType(ResultSet.TYPE_SCROLL_INSENSITIVE);
            getMessages().addWarning(new SQLWarning(
                Messages.get("warning.cursordowngraded",
                             "TYPE_SCROLL_INSENSITIVE"), "01000"));
        }

        return currentResult;
    }

    public SQLWarning getWarnings() throws SQLException {
        checkOpen();

        return messages.getWarnings();
    }

    public int executeUpdate(String sql, String[] columnNames) throws SQLException {
        checkOpen();

        if (columnNames == null) {
            throw new SQLException(
                Messages.get("error.generic.nullparam", "executeUpdate"),"HY092");
        } else if (columnNames.length != 1) {
            throw new SQLException(
                Messages.get("error.generic.needcolname", "executeUpdate"),"HY092");
        }

        return executeUpdate(sql, RETURN_GENERATED_KEYS);
    }

    public boolean execute(String sql, String[] columnNames) throws SQLException {
        checkOpen();

        if (columnNames == null) {
            throw new SQLException(
                Messages.get("error.generic.nullparam", "execute"),"HY092");
        } else if (columnNames.length != 1) {
            throw new SQLException(
                Messages.get("error.generic.needcolname", "execute"),"HY092");
        }

        return executeInternal(sql, RETURN_GENERATED_KEYS, false);
    }

    public ResultSet executeQuery(String sql) throws SQLException {
        checkOpen();
        initialize();

        if (sql == null || sql.length() == 0) {
            throw new SQLException(Messages.get("error.generic.nosql"), "HY000");
        }
        if (escapeProcessing) {
            String tmp[] = SQLParser.parse(sql, null, connection, false);

            if (tmp[1].length() != 0) {
                throw new SQLException(
                    Messages.get("error.statement.badsql"), "07000");
            }

            sql = tmp[0];
        }
        Semaphore connectionLock = null;
        try {
            connectionLock = lockConnection();
            return executeSQLQuery(sql, null, null, useCursor(false, null));
        } finally {
            freeConnection(connectionLock);
        }
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
