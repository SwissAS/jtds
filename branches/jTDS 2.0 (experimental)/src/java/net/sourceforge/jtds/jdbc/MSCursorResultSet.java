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

import java.math.BigDecimal;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.Types;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.concurrent.Semaphore;

import net.sourceforge.jtds.util.Logger;

/**
 * This class extends the JtdsResultSet to support scrollable and or
 * updateable cursors on Microsoft servers.
 * <p>The undocumented Microsoft sp_cursor procedures are used.
 * <p>
 * Implementation notes:
 * <ol>
 * <li>All of Alin's cursor result set logic is incorporated here.
 * <li>This logic was originally implemented in the JtdsResultSet class but on reflection
 * it seems that Alin's original approch of having a dedicated cursor class leads to a more
 * flexible and maintainable design.
 * </ol>
 *
 * @author Alin Sinpalean
 * @author Mike Hutchinson
 * @version $Id: MSCursorResultSet.java,v 1.1 2007-09-10 19:19:32 bheineman Exp $
 */
public class MSCursorResultSet extends ResultSetImpl {
    /*
     * Constants
     */
    private static final Integer FETCH_FIRST    = new Integer(1);
    private static final Integer FETCH_NEXT     = new Integer(2);
    private static final Integer FETCH_PREVIOUS = new Integer(4);
    private static final Integer FETCH_LAST     = new Integer(8);
    private static final Integer FETCH_ABSOLUTE = new Integer(16);
    private static final Integer FETCH_RELATIVE = new Integer(32);
    private static final Integer FETCH_REPEAT   = new Integer(128);
    private static final Integer FETCH_INFO     = new Integer(256);
    
    private static final int CURSOR_TYPE_KEYSET = 0x01;
    private static final int CURSOR_TYPE_DYNAMIC = 0x02;
    private static final int CURSOR_TYPE_FORWARD = 0x04;
    private static final int CURSOR_TYPE_STATIC = 0x08;
    private static final int CURSOR_TYPE_FASTFORWARDONLY = 0x10;
    private static final int CURSOR_TYPE_PARAMETERIZED = 0x1000;
    private static final int CURSOR_TYPE_AUTO_FETCH = 0x2000;

    private static final int CURSOR_CONCUR_READ_ONLY = 1;
    private static final int CURSOR_CONCUR_SCROLL_LOCKS = 2;
    private static final int CURSOR_CONCUR_OPTIMISTIC = 4;
    private static final int CURSOR_CONCUR_OPTIMISTIC_VALUES = 8;

    private static final Integer CURSOR_OP_INSERT = new Integer(4);
    private static final Integer CURSOR_OP_UPDATE = new Integer(33);
    private static final Integer CURSOR_OP_DELETE = new Integer(34);

    /**
     * The row is dirty and needs to be reloaded (internal state).
     */
    private static final Integer SQL_ROW_DIRTY   = new Integer(0);

    /**
     * The row is valid.
     */
    //private static final Integer SQL_ROW_SUCCESS = new Integer(1);

    /**
     * The row has been deleted.
     */
    private static final Integer SQL_ROW_DELETED = new Integer(2);

    /*
     * Instance variables.
     */
    /** Set when <code>moveToInsertRow()</code> was called. */
    private boolean onInsertRow;
    /** The "insert row". */
    private ParamInfo[] insertRow;
    /** The "update row". */
    private ParamInfo[] updateRow;
    /** Actual position of the cursor. */
    private int cursorPos;
    /** The cursor is being built asynchronously. */
    private boolean asyncCursor;
    /** The cursor name to be used for positioned updates. */
    private String cursorName;

    //
    // Fixed sp_XXX parameters
    //
    /** Cursor handle parameter. */
    private final ParamInfo PARAM_CURSOR_HANDLE = new ParamInfo(Types.INTEGER, null, ParamInfo.INPUT);

    /** <code>sp_cursorfetch</code> fetchtype parameter. */
    private final ParamInfo PARAM_FETCHTYPE = new ParamInfo(Types.INTEGER, null, ParamInfo.INPUT);

    /** <code>sp_cursorfetch</code> rownum IN parameter (for actual fetches). */
    private final ParamInfo PARAM_ROWNUM_IN = new ParamInfo(Types.INTEGER, null, ParamInfo.INPUT);

    /** <code>sp_cursorfetch</code> numrows IN parameter (for actual fetches). */
    private final ParamInfo PARAM_NUMROWS_IN = new ParamInfo(Types.INTEGER, null, ParamInfo.INPUT);

    /** <code>sp_cursorfetch</code> rownum OUT parameter (for FETCH_INFO). */
    private final ParamInfo PARAM_ROWNUM_OUT = new ParamInfo(Types.INTEGER, null, ParamInfo.OUTPUT);

    /** <code>sp_cursorfetch</code> numrows OUT parameter (for FETCH_INFO). */
    private final ParamInfo PARAM_NUMROWS_OUT = new ParamInfo(Types.INTEGER, null, ParamInfo.OUTPUT);

    /** <code>sp_cursor</code> optype parameter. */
    private final ParamInfo PARAM_OPTYPE = new ParamInfo(Types.INTEGER, null, ParamInfo.INPUT);

    /** <code>sp_cursor</code> rownum parameter. */
    private final ParamInfo PARAM_ROWNUM = new ParamInfo(Types.INTEGER, new Integer(1), ParamInfo.INPUT);

    /** <code>sp_cursor</code> table parameter. */
    private final ParamInfo PARAM_TABLE = new ParamInfo(Types.VARCHAR, "", ParamInfo.UNICODE);

    private final StatementImpl statement;
    private final ConnectionImpl connection;
    
    /**
     * Construct a cursor result set using Microsoft sp_cursorcreate etc.
     *
     * @param statement       the parent statement object
     * @param sql             the SQL statement used to build the result set
     * @param procName        an optional stored procedure name
     * @param procedureParams parameters for prepared statements
     * @throws SQLException
     */
    MSCursorResultSet(final StatementImpl statement,
                      final String sql,
                      final String procName,
                      final ParamInfo[] procedureParams)
            throws SQLException 
    {
        super(statement, statement.getResultSetType(), statement.getResultSetConcurrency());

        PARAM_NUMROWS_IN.value = new Integer(getFetchSize());
        rows = new ArrayList<Object[]>(getFetchSize());
        connection = (ConnectionImpl)statement.getConnection();
        this.statement = statement;
        cursorCreate(sql, procName, procedureParams,
                statement.getResultSetType(),
                statement.getResultSetConcurrency());
        if (asyncCursor) {
            // Obtain a provisional row count for the result set
            cursorFetch(FETCH_REPEAT, 0, false);
        }
    }

    /**
     * Set the specified column's data value.
     *
     * @param colIndex index of the column
     * @param value    new column value
     * @return the value, possibly converted to an internal type
     */
    Object setColValue(int colIndex, 
                       final int jdbcType, 
                       Object value, 
                       final int length)
            throws SQLException 
    {
        checkOpen();
        checkUpdateable();
        if (colIndex < 1 || colIndex > columnCount) {
            throw new SQLException(Messages.get("error.resultset.colindex",
                    Integer.toString(colIndex)),
                    "07009");
        }
        //
        // Convert java date/time objects to internal DateTime objects
        //
        if (value instanceof java.sql.Timestamp) {
            value = new DateTime((java.sql.Timestamp) value);
        } else if (value instanceof java.sql.Date) {
            value = new DateTime((java.sql.Date) value);
        } else if (value instanceof java.sql.Time) {
            value = new DateTime((java.sql.Time) value);
        }

        if (!onInsertRow && getCurrentRow() == null) {
            throw new SQLException(Messages.get("error.resultset.norow"), "24000");
        }
        colIndex--;
        ParamInfo pi;
        ColInfo ci = columns[colIndex];

        if (onInsertRow) {
            pi = insertRow[colIndex];
        } else {
            if (updateRow == null) {
                updateRow = new ParamInfo[columnCount];
            }
            pi = updateRow[colIndex];
        }

        if (pi == null) {
            if (connection.getTdsVersion() >= TdsCore.TDS70 
                && (connection.getSendUnicode() 
                    || ci.charset != connection.getCharset())) {
                    // Need to send as Unicode
                    pi = new ParamInfo(-1, true);
            } else {
                // OK to send as characters
                pi = new ParamInfo(-1, false);
            }
            pi.name = '@'+ci.realName;
            if (onInsertRow) {
                insertRow[colIndex] = pi;
            } else {
                updateRow[colIndex] = pi;
            }
        }

        if (value == null) {
            pi.value    = null;
            pi.length   = 0;
            pi.jdbcType = ci.jdbcType;
            pi.isSet    = true;
            if (pi.jdbcType == Types.NUMERIC || pi.jdbcType == Types.DECIMAL) {
                pi.scale = ConnectionImpl.DEFAULT_SCALE;
            } else {
                pi.scale = 0;
            }
        } else {
            pi.value     = value;
            pi.length    = length;
            pi.isSet     = true;
            pi.jdbcType  = jdbcType;
            if (pi.value instanceof BigDecimal) {
                pi.scale = ((BigDecimal)pi.value).scale();
            } else {
                pi.scale = 0;
            }
        }

        return value;
    }

    /**
     * Get the specified column's data item.
     *
     * @param index the column index in the row
     * @return the column value as an <code>Object</code>
     * @throws SQLException if the index is out of bounds or there is no
     *                      current row
     */
    Object getColumn(final int index) throws SQLException {
        checkOpen();

        currentRow = getCurrentRow();

        if (currentRow != null && SQL_ROW_DIRTY.equals(currentRow[columns.length - 1])) {
            cursorFetch(FETCH_REPEAT, 0, true);
        }
        
        return super.getColumn(index);
    }

    /**
     * Translates a JDBC result set type into SQL Server native @scrollOpt value
     * for use with stored procedures such as sp_cursoropen, sp_cursorprepare
     * or sp_cursorprepexec.
     *
     * @param resultSetType        JDBC result set type (one of the
     *                             <code>ResultSet.TYPE_<i>XXX</i></code>
     *                             values)
     * @param resultSetConcurrency JDBC result set concurrency (one of the
     *                             <code>ResultSet.CONCUR_<i>XXX</i></code>
     *                             values)
     * @return a value for the @scrollOpt parameter
     */
    public static int getCursorScrollOpt(final int resultSetType,
                                         final int resultSetConcurrency,
                                         final boolean parameterized) 
    {
        int scrollOpt;

        switch (resultSetType) {
            case TYPE_SCROLL_INSENSITIVE:
                scrollOpt = CURSOR_TYPE_STATIC;
                break;

            case TYPE_SCROLL_SENSITIVE:
                scrollOpt = CURSOR_TYPE_KEYSET;
                break;

            case TYPE_SCROLL_SENSITIVE + 1:
                scrollOpt = CURSOR_TYPE_DYNAMIC;
                break;

            case TYPE_FORWARD_ONLY:
            default:
                scrollOpt = (resultSetConcurrency == CONCUR_READ_ONLY)
                        ? (CURSOR_TYPE_FASTFORWARDONLY | CURSOR_TYPE_AUTO_FETCH)
                        : CURSOR_TYPE_FORWARD;
                break;
        }

        // If using sp_cursoropen need to set a flag on scrollOpt.
        // The 0x1000 tells the server that there is a parameter
        // definition and user parameters present. If this flag is
        // not set the driver will ignore the additional parameters.
        if (parameterized) {
            scrollOpt |= CURSOR_TYPE_PARAMETERIZED;
        }

        return scrollOpt;
    }

    /**
     * Translates a JDBC result set concurrency into SQL Server native @ccOpt
     * value for use with stored procedures such as sp_cursoropen,
     * sp_cursorprepare or sp_cursorprepexec.
     *
     * @param resultSetConcurrency JDBC result set concurrency (one of the
     *                             <code>ResultSet.CONCUR_<i>XXX</i></code>
     *                             values)
     * @return a value for the @scrollOpt parameter
     */
    public static int getCursorConcurrencyOpt(final int resultSetConcurrency) {
        switch (resultSetConcurrency) {
            case CONCUR_UPDATABLE:
                return CURSOR_CONCUR_OPTIMISTIC;

            case CONCUR_UPDATABLE + 1:
                return CURSOR_CONCUR_SCROLL_LOCKS;

            case CONCUR_UPDATABLE + 2:
                return CURSOR_CONCUR_OPTIMISTIC_VALUES;

            case CONCUR_READ_ONLY:
            default:
                return CURSOR_CONCUR_READ_ONLY;
        }
    }

    /**
     * Create a new Cursor result set using the internal sp_cursoropen procedure.
     *
     * @param sql The SQL SELECT statement.
     * @param procName Optional procedure name for cursors based on a stored procedure.
     * @param parameters Optional stored procedure parameters.
     * @throws SQLException
     */
    private void cursorCreate(String sql,
                              String procName,
                              ParamInfo[] parameters,
                              final int resultSetType,
                              final int concurrency)
            throws SQLException 
    {
        int prepareSql = connection.getDataSource().getPrepareSql();
        Integer prepStmtHandle = null;
        cursorName = statement.getCursorName();
        int actualConcurrency = concurrency;
        int actualResultSetType = resultSetType;
        //
        // If this cursor is going to be a named forward only cursor
        // force the concurrency to be updateable.
        // TODO: Cursor is updateable unless user appends FOR READ to the select
        // but we would need to parse the SQL to discover 
        //
        if (cursorName != null
            && resultSetType == ResultSet.TYPE_FORWARD_ONLY
            && concurrency == ResultSet.CONCUR_READ_ONLY) {
            actualConcurrency = ResultSet.CONCUR_UPDATABLE;
        }
        //
        // Simplify future tests for parameters
        //
        if (parameters != null && parameters.length == 0) {
            parameters = null;
        }
        //
        // SQL 6.5 does not support stored procs (with params) in the sp_cursor call
        // will need to substitute any parameter values into the SQL.
        //
        if (connection.getBaseTds().getTdsVersion() == TdsCore.TDS42) {
            prepareSql = TdsCore.UNPREPARED;
            if (parameters != null) {
                procName = null;
            }
        }
        //
        // If we are running in unprepare mode and there are parameters
        // substitute these into the SQL statement now.
        //
        if (parameters != null && prepareSql == TdsCore.UNPREPARED) {
            sql = Support.substituteParameters(sql, parameters, connection);
            parameters = null;
        }
        //
        // For most prepare modes we need to substitute parameter
        // names for the ? markers.
        //
        if (parameters != null) {
            if (procName == null || !procName.startsWith("#jtds")) {
                sql = Support.substituteParamMarkers(sql, parameters);
            }
        }
        //
        // There are generally three situations in which procName is not null:
        // 1. Running in prepareSQL=1 and contains a temp proc name e.g. #jtds00001
        //    in which case we need to generate an SQL statement exec #jtds...
        // 2. Running in prepareSQL=3 and contains an existing statement handle.
        // 3. CallableStatement in which case the SQL string has a valid exec
        //    statement and we can ignore procName.
        //
        if (procName != null) {
            if (procName.startsWith("#jtds")) {
                StringBuffer buf = new StringBuffer(procName.length() + 16
                        + (parameters != null ? parameters.length * 5 : 0));
                buf.append("EXEC ").append(procName).append(' ');
                for (int i = 0; parameters != null && i < parameters.length; i++) {
                    if (i != 0) {
                        buf.append(',');
                    }
                    if (parameters[i].name != null) {
                        buf.append(parameters[i].name);
                    } else {
                        buf.append("@P").append(i);
                    }
                }
                sql = buf.toString();
            } else if (TdsCore70.isPreparedProcedureName(procName)) {
                //
                // Prepared Statement Handle
                // At present procName is set to the value obtained by
                // the connection.prepareSQL() call in JtdsPreparedStatement.
                // This handle was obtained using sp_cursorprepare not sp_prepare
                // so it's ok to use here.
                //
                try {
                    prepStmtHandle = new Integer(procName);
                } catch (NumberFormatException e) {
                    throw new IllegalStateException(
                               "Invalid prepared statement handle: " +
                                      procName);
                }
            }
        }

        //
        // Select the correct type of Server side cursor to
        // match the scroll and concurrency options.
        //
        int scrollOpt = getCursorScrollOpt(actualResultSetType, actualConcurrency,
                parameters != null);
        int ccOpt = getCursorConcurrencyOpt(actualConcurrency);
        //
        // Create parameter objects
        //
        // Setup scroll options parameter
        //
        ParamInfo pScrollOpt  = new ParamInfo(Types.INTEGER, new Integer(scrollOpt), ParamInfo.OUTPUT);
        //
        // Setup concurrency options parameter
        //
        ParamInfo pConCurOpt  = new ParamInfo(Types.INTEGER, new Integer(ccOpt), ParamInfo.OUTPUT);
        //
        // Setup number of rows parameter
        //
        ParamInfo pRowCount   = new ParamInfo(Types.INTEGER, new Integer(getFetchSize()), ParamInfo.OUTPUT);
        //
        // Setup cursor handle parameter
        //
        ParamInfo pCursor = new ParamInfo(Types.INTEGER, null, ParamInfo.OUTPUT);
        //
        // Setup statement handle param
        //
        ParamInfo pStmtHand = null;
        //
        // Setup parameter definitions parameter
        //
        ParamInfo pParamDef = null;
        if (parameters != null ) {
            // Parameter declarations
            pParamDef  = new ParamInfo(Types.LONGVARCHAR,
                    ((TdsCore70)connection.getBaseTds()).getParameterDefinitions(parameters),
                    ParamInfo.UNICODE);
        }
        //
        // Setup SQL statement parameter
        //
        ParamInfo pSQL = new ParamInfo(Types.LONGVARCHAR, sql, ParamInfo.UNICODE);
        //
        // OK now open the Cursor
        //
        if (prepareSql == TdsCore.PREPARE && prepStmtHandle != null) {
            // Use sp_cursorexecute approach
            procName = "sp_cursorexecute";
            if (parameters == null) {
                parameters = new ParamInfo[5];
            } else {
                ParamInfo[] params = new ParamInfo[5 + parameters.length];
                System.arraycopy(parameters, 0, params, 5, parameters.length);
                parameters = params;
            }
            // Setup statement handle param
            pStmtHand = new ParamInfo(Types.INTEGER, prepStmtHandle, ParamInfo.OUTPUT);
            pStmtHand.isOutput = false;
            pStmtHand.value = prepStmtHandle;
            parameters[0] = pStmtHand;
            // Setup cursor handle param
            parameters[1] = pCursor;
            // Setup scroll options (mask off parameter flag)
            pScrollOpt.value = new Integer(scrollOpt & ~CURSOR_TYPE_PARAMETERIZED);
        } else {
            // Use sp_cursoropen approach
            procName = "sp_cursoropen";
            if (parameters == null) {
                parameters = new ParamInfo[5];
            } else {
                ParamInfo[] params = new ParamInfo[6 + parameters.length];
                System.arraycopy(parameters, 0, params, 6, parameters.length);
                parameters = params;
                parameters[5] = pParamDef;
            }
            // Setup cursor handle param
            parameters[0] = pCursor;
            // Setup statement param
            parameters[1] = pSQL;
        }
        // Setup scroll options
        parameters[2] = pScrollOpt;
        // Setup concurrency options
        parameters[3] = pConCurOpt;
        // Setup numRows parameter
        parameters[4] = pRowCount;
        statement.setCursorResultSet(this);
        rows.clear();
        statement.tdsExecute(null, procName, parameters, false,
                statement.getQueryTimeout(), statement.getMaxRows(),
                statement.getMaxFieldSize(), true);

        // Load column meta data and any eventual rows (fast forward cursors)
        processOutput(true);
        if ((scrollOpt & CURSOR_TYPE_AUTO_FETCH) != 0) {
            // If autofetching, the cursor position is on the first row
            cursorPos = 1;
        }

        // Check the return value
        Integer retVal = statement.getReturnStatus();
        if ((retVal == null) || (retVal.intValue() != 0 && retVal.intValue() != 2)) {
            throw new SQLException(Messages.get("error.resultset.openfail"), "24000");
        }

        // Cursor is being built asynchronously so rowsInResult is not set
        asyncCursor = (retVal.intValue() == 2);

        //
        // Retrieve values of output parameters
        //
        PARAM_CURSOR_HANDLE.value = pCursor.getOutValue();
        int actualScroll = ((Integer) pScrollOpt.getOutValue()).intValue();
        int actualCc     = ((Integer) pConCurOpt.getOutValue()).intValue();
        rowsInResult = ((Integer) pRowCount.getOutValue()).intValue();

        //
        // Set the cursor name if required allowing positioned updates.
        // We need to do this here as any downgrade warnings will be wiped
        // out by the executeSQL call.
        //
        if (cursorName != null) {
            ParamInfo params[] = new ParamInfo[3];
            params[0] = PARAM_CURSOR_HANDLE;
            PARAM_OPTYPE.value = new Integer(2);
            params[1] = PARAM_OPTYPE;
            params[2] = new ParamInfo(Types.VARCHAR, cursorName, ParamInfo.UNICODE);
            statement.tdsExecute(null, "sp_cursoroption", params, false, 0, -1, -1, true);
            if (statement.getReturnStatus().intValue() != 0) {
                statement.getMessages().addException(
                        new SQLException(Messages.get("error.resultset.openfail"), "24000"));
            }
            statement.getMessages().checkErrors();
        }
        //
        // Check for downgrade of scroll or concurrency options
        //
        if ((actualScroll != (scrollOpt & 0xFFF)) || (actualCc != ccOpt)) {
            boolean downgradeWarning = false;

            if (actualScroll != scrollOpt) {
                switch (actualScroll) {
                    case CURSOR_TYPE_FORWARD:
                    case CURSOR_TYPE_FASTFORWARDONLY:
                        actualResultSetType = TYPE_FORWARD_ONLY;
                        break;

                    case CURSOR_TYPE_STATIC:
                        actualResultSetType = TYPE_SCROLL_INSENSITIVE;
                        break;

                    case CURSOR_TYPE_KEYSET:
                        actualResultSetType = TYPE_SCROLL_SENSITIVE;
                        break;

                    case CURSOR_TYPE_DYNAMIC:
                        actualResultSetType = TYPE_SCROLL_SENSITIVE + 1;
                        break;

                    default:
                        statement.getMessages().addWarning(new SQLWarning(
                                Messages.get("warning.cursortype", Integer.toString(actualScroll)),
                                "01000"));
                }
                downgradeWarning = actualResultSetType < resultSetType;
            }
            
            if (actualCc != ccOpt) {
                switch (actualCc) {
                    case CURSOR_CONCUR_READ_ONLY:
                        actualConcurrency = CONCUR_READ_ONLY;
                        break;

                    case CURSOR_CONCUR_OPTIMISTIC:
                        actualConcurrency = CONCUR_UPDATABLE;
                        break;

                    case CURSOR_CONCUR_SCROLL_LOCKS:
                        actualConcurrency = CONCUR_UPDATABLE + 1;
                        break;

                    case CURSOR_CONCUR_OPTIMISTIC_VALUES:
                        actualConcurrency = CONCUR_UPDATABLE + 2;
                        break;

                    default:
                        statement.getMessages().addWarning(new SQLWarning(
                                Messages.get("warning.concurrtype", Integer.toString(actualCc)),
                                "01000"));
                }
                downgradeWarning = actualConcurrency < concurrency;
            }
                        
            if (downgradeWarning) {
                // SAfe This warning goes to the Statement, not the ResultSet
                statement.getMessages().addWarning(new SQLWarning(
                        Messages.get( "warning.cursordowngraded",
                                actualResultSetType + "/" + actualConcurrency),
                        "01000"));
            }
        }
        setResultSetType(actualResultSetType);
        setResultSetConcurrency(actualConcurrency);
    }

    /**
     * Fetch the next result row from a cursor using the internal sp_cursorfetch procedure.
     *
     * @param fetchType The type of fetch eg FETCH_ABSOLUTE.
     * @param rowNum The row number to fetch.
     * @return <code>boolean</code> true if a result set row is returned.
     * @throws SQLException
     */
    private boolean cursorFetch(final Integer fetchType, 
                                int rowNum, 
                                final boolean getMutex)
            throws SQLException 
    {
        //
        // Reading a new row will clear the warning chain
        //
        statement.getMessages().clearWarnings();
        
        if (fetchType != FETCH_ABSOLUTE && fetchType != FETCH_RELATIVE) {
            rowNum = 1;
        }

        ParamInfo[] param = new ParamInfo[4];
        // Setup cursor handle param
        param[0] = PARAM_CURSOR_HANDLE;

        // Setup fetchtype param
        PARAM_FETCHTYPE.value = fetchType;
        param[1] = PARAM_FETCHTYPE;

        // Setup rownum
        PARAM_ROWNUM_IN.value = new Integer(rowNum);
        param[2] = PARAM_ROWNUM_IN;
        // Setup numRows parameter

        if (((Integer) PARAM_NUMROWS_IN.value).intValue() != getFetchSize()) {
            // If the fetch size changed, update the parameter and cache size
            PARAM_NUMROWS_IN.value = new Integer(getFetchSize());
//            rows = new ArrayList(getFetchSize());
        }
        param[3] = PARAM_NUMROWS_IN;
        Semaphore connectionLock = null;
        try {
            if (getMutex) {
                connectionLock = statement.lockConnection();
            }
            statement.setColumns(columns);
            statement.setCursorResultSet(this);
            rows.clear();
            // No meta data, no timeout (we're not sending it yet), no row
            // limit, don't send yet
            statement.tdsExecute(null, "sp_cursorfetch", param, true, 0, 0,
                    getStatement().getMaxFieldSize(), false);

            // Setup fetchtype param
            PARAM_FETCHTYPE.value = FETCH_INFO;
            param[1] = PARAM_FETCHTYPE;

            // Setup rownum
            PARAM_ROWNUM_OUT.clearOutValue();
            param[2] = PARAM_ROWNUM_OUT;
            // Setup numRows parameter
            PARAM_NUMROWS_OUT.clearOutValue();
            param[3] = PARAM_NUMROWS_OUT;

            // No meta data, use the statement timeout, leave max rows as it is
            // (no limit), leave max field size as it is, send now
            statement.tdsExecute(null, "sp_cursorfetch", param, true,
                    getStatement().getQueryTimeout(), -1, -1, true);
        } finally {
            statement.freeConnection(connectionLock);
        }
        // Load rows
        processOutput(false);

        cursorPos = ((Integer) PARAM_ROWNUM_OUT.getOutValue()).intValue();
        if (fetchType != FETCH_REPEAT) {
            // Do not change ResultSet position when refreshing
            pos = cursorPos;
        }
        rowsInResult = ((Integer) PARAM_NUMROWS_OUT.getOutValue()).intValue();
        if (rowsInResult < 0) {
            // -1 = Dynamic cursor number of rows cannot be known.
            // -n = Async cursor = rows loaded so far
            rowsInResult = 0 - rowsInResult;
        }
        currentRow = getCurrentRow();
        return currentRow != null;
    }

    /**
     * Support general cursor operations such as delete, update etc.
     *
     * @param opType the type of operation to perform
     * @param row    the row number to update
     * @throws SQLException
     */
    private void cursor(final Integer opType , final ParamInfo[] row) 
        throws SQLException 
    {
        
        ParamInfo param[];

        if (opType == CURSOR_OP_DELETE) {
            // 3 parameters for delete
            param = new ParamInfo[3];
        } else {
            if (row == null) {
                throw new SQLException(Messages.get("error.resultset.update"), "24000");
            }
            // 4 parameters plus one for each column for insert/update
            param = new ParamInfo[4 + columnCount];
        }

        // Setup cursor handle param
        param[0] = PARAM_CURSOR_HANDLE;

        // Setup optype param
        PARAM_OPTYPE.value = opType;
        param[1] = PARAM_OPTYPE;

        // Setup rownum
        PARAM_ROWNUM.value = new Integer(pos - cursorPos + 1);
        param[2] = PARAM_ROWNUM;

        // If row is not null, we're dealing with an insert/update
        if (row != null) {
            // Setup table
            param[3] = PARAM_TABLE;

            int colCnt = columnCount;
            // Current column; we will only update/insert columns for which
            // values were specified
            int crtCol = 4;
            // Name of the table to insert default values into (if necessary)
            String tableName = null;

            for (int i = 0; i < colCnt; i++) {
                ParamInfo pi = row[i];
                ColInfo col = columns[i];

                if (pi != null && pi.isSet) {
                    if (!col.isWriteable) {
                        // Column is read-only but was updated
                        throw new SQLException(Messages.get("error.resultset.insert",
                                Integer.toString(i + 1), col.realName), "24000");
                    }

                    param[crtCol++] = pi;
                }
                if (tableName == null && col.tableName != null) {
                    if (col.catalog != null || col.schema != null) {
                        tableName = (col.catalog != null ? col.catalog : "")
                                + '.' + (col.schema != null ? col.schema : "")
                                + '.' + col.tableName;
                    } else {
                        tableName = col.tableName;
                    }
                }
            }

            if (crtCol == 4) {
                if (opType == CURSOR_OP_INSERT) {
                    // Insert default values for all columns.
                    // There seem to be two forms of sp_cursor: one with
                    // parameter names and values and one w/o names and with
                    // expressions (this is where 'default' comes in).
                    param[crtCol] = new ParamInfo(Types.VARCHAR,
                            "insert " + tableName + " default values",
                            ParamInfo.UNICODE);
                    crtCol++;
                } else {
                    // No column to update so bail out!
                    return;
                }
            }

            // If the count is different (i.e. there were read-only
            // columns) reallocate the parameters into a shorter array
            if (crtCol != colCnt + 4) {
                ParamInfo[] newParam = new ParamInfo[crtCol];

                System.arraycopy(param, 0, newParam, 0, crtCol);
                param = newParam;
            }
        }
        Semaphore connectionLock = null;
        try {
            connectionLock = statement.lockConnection();
            // With meta data (we're not expecting any ResultSets), no timeout
            // (because we're not sending the request yet), don't alter max
            // rows, don't alter max field size, don't send yet
            statement.tdsExecute(null, "sp_cursor", param, false, 0, -1, -1, false);

            if (param.length != 4) {
                param = new ParamInfo[4];
                param[0] = PARAM_CURSOR_HANDLE;
            }

            // Setup fetchtype param
            PARAM_FETCHTYPE.value = FETCH_INFO;
            param[1] = PARAM_FETCHTYPE;

            // Setup rownum
            PARAM_ROWNUM_OUT.clearOutValue();
            param[2] = PARAM_ROWNUM_OUT;
            // Setup numRows parameter
            PARAM_NUMROWS_OUT.clearOutValue();
            param[3] = PARAM_NUMROWS_OUT;

            // No meta data (no ResultSets expected), use statement timeout,
            // don't alter max rows, don't alter max field size, send now
            statement.tdsExecute(null, "sp_cursorfetch", param, false,
                    getStatement().getQueryTimeout(), -1, -1, true);
        } finally {
            statement.freeConnection(connectionLock);
        }

        // Consume the sp_cursor response
        statement.getMessages().checkErrors();
        Integer retVal = statement.getReturnStatus();
        if (retVal.intValue() != 0) {
            throw new SQLException(Messages.get("error.resultset.cursorfail"),
                    "24000");
        }

        //
        // Allow row values to be garbage collected
        //
        if (row != null) {
            for (int i = 0; i < row.length; i++) {
                if (row[i] != null) {
                    row[i].clearInValue();
                }
            }
        }

        // Consume the sp_cursorfetch response
        statement.getMessages().checkErrors();
        cursorPos = ((Integer) PARAM_ROWNUM_OUT.getOutValue()).intValue();
        rowsInResult = ((Integer) PARAM_NUMROWS_OUT.getOutValue()).intValue();

        // Update row status
        if (opType == CURSOR_OP_DELETE || opType == CURSOR_OP_UPDATE) {
            Object[] currRow = getCurrentRow();
            if (currRow == null) {
                throw new SQLException(
                        Messages.get("error.resultset.updatefail"), "24000");
            }
            // No need to re-fetch the row, just mark it as deleted or dirty
            currRow[columns.length - 1] =
                    (opType == CURSOR_OP_DELETE) ? SQL_ROW_DELETED : SQL_ROW_DIRTY;
        }
    }

    /**
     * Close a server side cursor.
     *
     * @throws SQLException
     */
    private void cursorClose() throws SQLException {
        Semaphore connectionLock = null;
        try {
            connectionLock = statement.lockConnection();

            ParamInfo param[] = new ParamInfo[1];

            // Setup cursor handle param
            param[0] = PARAM_CURSOR_HANDLE;

            statement.tdsExecute(null, "sp_cursorclose", param, false,
                                    getStatement().getQueryTimeout(), -1, -1, true);
            statement.getMessages().checkErrors();
        } finally {
            statement.freeConnection(connectionLock);
        }
    }

    /**
     * Processes the output of a cursor open or fetch operation. Fetches a
     * batch of rows from the <code>TdsCore</code>, loading them into the row
     * cache and optionally sets the column meta data (if called on cursor
     * open). Consumes all the response and checks for server returned errors.
     *
     * @param setMeta whether column meta data needs to be loaded (cursor open)
     * @throws SQLException if an error occurs or an error message is returned
     *                      by the server
     */
    private void processOutput(final boolean setMeta) throws SQLException {
        
        statement.processResults(true);
        if (setMeta) {
            if (columns == null) {
                // Set exception on statement as ResultSet create fails
                statement.getMessages().addException(new SQLException(
                    Messages.get("error.statement.noresult"), "24000"));
            } else {
                columnCount = getColumnCount(columns);                
            }
        }

        statement.getMessages().checkErrors();
    }

//
// -------------------- java.sql.ResultSet methods -------------------
//

    public void afterLast() throws SQLException {
        checkOpen();
        checkScrollable();

        if (pos != POS_AFTER_LAST) {
            // SAfe Just fetch a very large absolute value
            cursorFetch(FETCH_ABSOLUTE, Integer.MAX_VALUE, true);
        }
    }

    public void beforeFirst() throws SQLException {
        checkOpen();
        checkScrollable();

        if (pos != POS_BEFORE_FIRST) {
            cursorFetch(FETCH_ABSOLUTE, 0, true);
        }
    }

    public void clearWarnings() throws SQLException {
        checkOpen();

        statement.getMessages().clearWarnings();
    }

    public SQLWarning getWarnings() throws SQLException {
        checkOpen();

        return statement.getMessages().getWarnings();
    }

    public void cancelRowUpdates() throws SQLException {
        checkOpen();
        checkUpdateable();

        if (onInsertRow) {
            throw new SQLException(Messages.get("error.resultset.insrow"), "24000");
        }

        for (int i = 0; updateRow != null && i < updateRow.length; i++) {
            if (updateRow[i] != null) {
                updateRow[i].clearInValue();
            }
        }
    }

    public void close() throws SQLException {
        if (!isClosed()) {
            try {
                if (!connection.isClosed()) {
                    cursorClose();
                }
            } finally {
                setClosed();
                rows = null;
            }
            Logger.println("MSCursorResultSet.close()");
        }
    }

    public void deleteRow() throws SQLException {
        checkOpen();
        checkUpdateable();

        if (getCurrentRow() == null) {
            throw new SQLException(Messages.get("error.resultset.norow"), "24000");
        }

        if (onInsertRow) {
            throw new SQLException(Messages.get("error.resultset.insrow"), "24000");
        }

        cursor(CURSOR_OP_DELETE, null);
    }

    public void insertRow() throws SQLException {
        checkOpen();
        checkUpdateable();

        if (!onInsertRow) {
            throw new SQLException(Messages.get("error.resultset.notinsrow"), "24000");
        }

        cursor(CURSOR_OP_INSERT, insertRow);
    }

    public void moveToCurrentRow() throws SQLException {
        checkOpen();
        checkUpdateable();

        onInsertRow = false;
    }

    public void moveToInsertRow() throws SQLException {
        checkOpen();
        checkUpdateable();
        if (insertRow == null) {
            insertRow = new ParamInfo[columnCount];
        }
        onInsertRow = true;
    }

    public void refreshRow() throws SQLException {
        checkOpen();

        if (onInsertRow) {
            throw new SQLException(Messages.get("error.resultset.insrow"), "24000");
        }

        cursorFetch(FETCH_REPEAT, 0, true);
    }

    public void updateRow() throws SQLException {
        checkOpen();
        checkUpdateable();

        if (getCurrentRow() == null) {
            throw new SQLException(Messages.get("error.resultset.norow"), "24000");
        }

        if (onInsertRow) {
            throw new SQLException(Messages.get("error.resultset.insrow"), "24000");
        }

        if (updateRow != null) {
            cursor(CURSOR_OP_UPDATE, updateRow);
        }
    }

    public boolean first() throws SQLException {
        checkOpen();
        checkScrollable();

        pos = 1;
        if (getCurrentRow() == null) {
            return cursorFetch(FETCH_FIRST, 0, true);
        }
        return true;
    }

    // FIXME Make the isXXX() methods work with forward-only cursors (rowsInResult == -1)
    public boolean isLast() throws SQLException {
        checkOpen();

        return(pos == rowsInResult) && (rowsInResult != 0);
    }

    public boolean last() throws SQLException {
        checkOpen();
        checkScrollable();

        pos = rowsInResult;
        if (asyncCursor || getCurrentRow() == null) {
            if (cursorFetch(FETCH_LAST, 0, true)) {
                // Set pos to the last row, as the number of rows can change
                pos = rowsInResult;
                return true;
            }
            return false;
        }
        return true;
    }

    public boolean next() throws SQLException {
        checkOpen();

        ++pos;
        if (getCurrentRow() == null) {
            return cursorFetch(FETCH_NEXT, 0, true);
        }
        return true;
    }

    public boolean previous() throws SQLException {
        checkOpen();
        checkScrollable();

        // Don't bother if we're already before the first row
        if (pos == POS_BEFORE_FIRST) {
            return false;
        }

        // Save current ResultSet position
        int initPos = pos;
        // Decrement current position
        --pos;
        if (initPos == POS_AFTER_LAST || getCurrentRow() == null) {
            boolean res = cursorFetch(FETCH_PREVIOUS, 0, true);
            pos = (initPos == POS_AFTER_LAST) ? rowsInResult : (initPos - 1);
            return res;
        }
        return true;
    }

    public boolean rowDeleted() throws SQLException {
        checkOpen();

        Object[] currRow = getCurrentRow();

        // If there is no current row, return false (the row was not deleted)
        if (currRow == null) {
            return false;
        }

        // Reload if dirty
        if (SQL_ROW_DIRTY.equals(currRow[columns.length - 1])) {
            cursorFetch(FETCH_REPEAT, 0, true);
            currRow = getCurrentRow();
        }

        return SQL_ROW_DELETED.equals(currRow[columns.length - 1]);
    }

    public boolean rowInserted() throws SQLException {
        checkOpen();
        // No way to find out
        return false;
    }

    public boolean rowUpdated() throws SQLException {
        checkOpen();
        // No way to find out
        return false;
    }

    public boolean absolute(int row) throws SQLException {
        checkOpen();
        checkScrollable();

        pos = (row >= 0) ? row : (rowsInResult - row + 1);
        if (getCurrentRow() == null) {
            boolean result = cursorFetch(FETCH_ABSOLUTE, row, true);
            if (cursorPos == 1 && row + rowsInResult < 0) {
                pos = 0;
                result = false;
            }
            return result;
        }
        return true;
    }

    public boolean relative(int row) throws SQLException {
        checkOpen();
        checkScrollable();

        pos = (pos == POS_AFTER_LAST) ? (rowsInResult + 1 + row) : (pos + row);
        if (getCurrentRow() == null) {
            if (pos < cursorPos) {
                // If fetching backwards fetch the row and the rows before it,
                // then restore pos
                int savePos = pos;
                boolean result = cursorFetch(FETCH_RELATIVE,
                        pos - cursorPos - getFetchSize() + 1, true);
                if (result) {
                    pos = savePos;
                } else {
                    pos = POS_BEFORE_FIRST;
                }
                return result;
            }
            return cursorFetch(FETCH_RELATIVE, pos - cursorPos, true);
        }
        return true;
    }

    public String getCursorName() throws SQLException {
        checkOpen();
        if (cursorName != null) {
            return cursorName;
        }
        return super.getCursorName();
    }

    Object[] getCurrentRow() {
        if (pos < cursorPos || pos >= cursorPos + rows.size() || onInsertRow) {
            return null;
        }

        return rows.get(pos - cursorPos);
    }
}
