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
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.text.NumberFormat;
import java.io.UnsupportedEncodingException;
import java.io.InputStreamReader;

import net.sourceforge.jtds.util.Logger;

/**
 * jTDS Implementation of the java.sql.ResultSet interface supporting forward 
 * (or scroll insenstive) read only result sets.
 * <p>
 * Implementation notes:
 * <ol>
 * <li>This class is also the base for more sophisticated result sets and
 * incorporates the update methods required by them.
 * <li>The class supports the BLOB/CLOB objects added by Brian.
 * </ol>
 *
 * @author Mike Hutchinson
 * @version $Id: ResultSetImpl.java,v 1.4 2009-09-27 12:59:02 ickzon Exp $
 */
public class ResultSetImpl implements ResultSet {

    static final int POS_BEFORE_FIRST = 0;
    static final int POS_AFTER_LAST = -1;

    /*
     *  Shared Instance variables.
     */
    /** The current row number. */
    int pos = POS_BEFORE_FIRST;
    /** Actual buffer pointer. */
    int bufferPos;
    /** The number of rows in the result. */
    int rowsInResult;
    /** Number of visible columns in row. */
    int columnCount;
    /** The array of column descriptors. */
    ColInfo columns[];
    /** The current result set row. */
    Object  currentRow[];    
    /** The row buffer. **/
    ArrayList<Object[]>  rows;
    /** Indicates at eof. */
    boolean eof;

    /*
     * Private instance variables.
     */
    /** The result set type. */
    private int resultSetType = ResultSet.TYPE_FORWARD_ONLY;
    /** The result set concurrency. */
    private int concurrency = ResultSet.CONCUR_READ_ONLY;
    /** True if last column retrieved was null. */
    private boolean wasNull;
    /** The parent statement. */
    private StatementImpl statement;
    /** The parent connection. */
    private ConnectionImpl con;
    /** True if this result set is closed. */
    private boolean closed;
    /** The fetch direction. */
    private int fetchDirection = FETCH_FORWARD;
    /** The fetch size (only applies to cursor <code>ResultSet</code>s). */
    private int fetchSize;
    /** Used to format numeric values when scale is specified. */
    private static NumberFormat f = NumberFormat.getInstance();
    /** Cache to optimize findColumn(String) lookups */
    private HashMap<String,Integer> columnMap;
    /** The insert result set row. */
    private Object  insertRow[];

    /**
     * Construct a simple result set from a statement, metadata or generated keys.
     *
     * @param statement The parent statement object or null.
     * @param concurrency the result set concurrency.
     * @param type the result set type.
     * @throws SQLException
     */
    ResultSetImpl(final StatementImpl statement, 
                  final int concurrency, 
                  final int type) 
    {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, null, new Object[]{statement});
        }
        if (statement == null) {
            throw new IllegalArgumentException("Statement parameter must not be null");
        }
        this.statement = statement;
        this.concurrency   = concurrency;
        this.resultSetType = type;     
        try {
            con           = (ConnectionImpl)statement.getConnection();
            fetchSize     = statement.getFetchSize();
        } catch (SQLException e) {
            // Will not occur
        }
        rows = new ArrayList<Object[]>(fetchSize);
        currentRow = null;
        eof = true;
    }
        
    /**
     * Constructs a cached result set based on locally generated data.
     *
     * @param statement the parent statement object
     * @param colName   array of column names
     * @param colType   array of corresponding data types
     * @exception SQLException if an error occurs
     */
    ResultSetImpl(final StatementImpl statement,
                  final String[] colName, 
                  final int[] colType) throws SQLException 
    {
        if (statement == null) {
            throw new IllegalArgumentException("Statement parameter must not be null");
        }
        this.statement = statement;
        try {
            con            = (ConnectionImpl)statement.getConnection();
            fetchSize      = statement.getFetchSize();
        } catch (SQLException e) {
            // Will not occur
        }
        //
        // Construct the column descriptor array
        //
        columns = new ColInfo[colName.length];
        for (int i = 0; i < colName.length; i++) {
            ColInfo ci = new ColInfo();
            ci.name     = colName[i];
            ci.realName = colName[i];
            ci.jdbcType = colType[i];
            ci.isCaseSensitive = false;
            ci.isIdentity = false;
            ci.isWriteable = false;
            ci.nullable = 2;
            ci.scale = 0;
            fillInType(ci);
            columns[i] = ci;
        }
        columnCount     = getColumnCount(columns);
        rowsInResult    = 0;
        setResultSetType(ResultSet.TYPE_FORWARD_ONLY);
        setResultSetConcurrency(ResultSet.CONCUR_UPDATABLE);
        rows = new ArrayList<Object[]>(fetchSize);
        currentRow = null;
        eof = true;
    }

    /**
     * Fill in the TDS native type code and all other fields for a
     * <code>ColInfo</code> instance with the JDBC type set.
     *
     * @param ci the <code>ColInfo</code> instance
     */
    private void fillInType(final ColInfo ci) {
        switch (ci.jdbcType) {
            case java.sql.Types.VARCHAR:
                ci.bufferSize = 255;
                ci.displaySize = 255;
                ci.precision = 255;
                ci.sqlType = "varchar";
                break;
            case java.sql.Types.INTEGER:
                ci.bufferSize = 4;
                ci.displaySize = 11;
                ci.precision = 10;
                ci.sqlType = "int";
                break;
            case java.sql.Types.SMALLINT:
                ci.bufferSize = 2;
                ci.displaySize = 6;
                ci.precision = 5;
                ci.sqlType = "smallint";
                break;
            case java.sql.Types.BIT:
                ci.bufferSize = 1;
                ci.displaySize = 1;
                ci.precision = 1;
                ci.sqlType = "bit";
                break;
            default:
                throw new IllegalStateException("Internal error: bad jdbc type "+
                            ci.jdbcType);
        }
        ci.scale = 0;
    }

    /**
     * Set the result set type.
     * @param type the result set type.
     */
    void setResultSetType(final int type) {
        resultSetType = type;
    }
    
    /**
     * Set the result set concurrency.
     * @param concurrency the concurrency value.
     */
    void setResultSetConcurrency(final int concurrency) {
        this.concurrency = concurrency;
    }
    
    /**
     * Set the closed flag on this result set
     */
    void setClosed()
    {
        closed = true;
        statement = null;
        currentRow = null;
    }

    /**
     * Retrieve the closed status of this result set.
     * @return the closed flag as a <code>boolean</code>.
     */
    @Override
    public boolean isClosed()
    {
        return closed;
    }
    
    /**
     * Retrieve the column count excluding hidden columns
     *
     * @param columns The columns array
     * @return The new column count as an <code>int</code>.
     */
    static int getColumnCount(final ColInfo[] columns) {
        // MJH - Modified to cope with more than one hidden column
        int i;
        for (i = columns.length - 1; i >= 0 && columns[i].isHidden; i--);
        return i + 1;
    }

    /**
     * Retrieve the column descriptor array.
     *
     * @return The column descriptors as a <code>ColInfo[]</code>.
     */
    ColInfo[] getColumns() {
        return columns;
    }
    
    /**
     * Set the column descriptor array.
     * @param columns the column descriptors.
     */
    void setColumns(final ColInfo columns[]) {
        this.columns = columns;
        this.columnCount = getColumnCount(columns);
    }

    /**
     * Set the specified column's name.
     *
     * @param colIndex The index of the column in the row.
     * @param name The new name.
     */
    void setColName(final int colIndex, final String name) {
        if (colIndex < 1 || colIndex > columns.length) {
            throw new IllegalArgumentException("columnIndex "
                    + colIndex + " invalid");
        }

        columns[colIndex - 1].realName = name;
    }

    /**
     * Set the specified column's label.
     *
     * @param colIndex The index of the column in the row.
     * @param name The new label.
     */
    void setColLabel(final int colIndex, final String name) {
        if (colIndex < 1 || colIndex > columns.length) {
            throw new IllegalArgumentException("columnIndex "
                    + colIndex + " invalid");
        }

        columns[colIndex - 1].name = name;
    }

    /**
     * Set the specified column's JDBC type.
     *
     * @param colIndex The index of the column in the row.
     * @param jdbcType The new type value.
     */
    void setColType(final int colIndex, final int jdbcType) {
        if (colIndex < 1 || colIndex > columns.length) {
            throw new IllegalArgumentException("columnIndex "
                    + colIndex + " invalid");
        }

        columns[colIndex - 1].jdbcType = jdbcType;
    }

    /**
     * Set the specified column's data value.
     *
     * @param colIndex index of the column
     * @param value    new column value
     * @param length   the length of a stream parameter
     * @return the value, possibly converted to an internal type
     */
    Object setColValue(final int colIndex, 
                       final int jdbcType, 
                       final Object value, 
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
        if (insertRow == null) {
            throw new SQLException(Messages.get("error.resultset.norow"), "24000");
        }
        insertRow[colIndex-1] = value;
        return value;
    }

    /**
     * Set the current row's column count.
     *
     * @param columnCount The number of visible columns in the row.
     */
    void setColumnCount(final int columnCount) {
        if (columnCount < 1 || columnCount > columns.length) {
            throw new IllegalArgumentException("columnCount "
                    + columnCount + " is invalid");
        }

        this.columnCount = columnCount;
    }

    /**
     * Get the specified column's data item.
     *
     * @param index the column index in the row
     * @return the column value as an <code>Object</code>
     * @throws SQLException if the connection is closed;
     *         if <code>index</code> is less than <code>1</code>;
     *         if <code>index</code> is greater that the number of columns;
     *         if there is no current row
     */
    Object getColumn(final int index) throws SQLException {
        checkOpen();
        
        if (index < 1 || index > columnCount) {
            throw new SQLException(Messages.get("error.resultset.colindex",
                                                      Integer.toString(index)),
                                                       "07009");
        }
        
        if (currentRow == null) {
            throw new SQLException(Messages.get("error.resultset.norow"), "24000");
        }

        Object data = currentRow[index - 1];

        wasNull = data == null;

        return data;
    }

    /**
     * Check that this connection is still open.
     *
     * @throws SQLException if connection closed.
     */
    void checkOpen() throws SQLException {
        if (closed) {
            throw new SQLException(Messages.get("error.generic.closed", "ResultSet"),
                                        "HY010");
        }
    }

    /**
     * Check that this resultset is scrollable.
     *
     * @throws SQLException if connection closed.
     */
    void checkScrollable() throws SQLException {
        if (resultSetType == ResultSet.TYPE_FORWARD_ONLY) {
            throw new SQLException(Messages.get("error.resultset.fwdonly"), "24000");
        }
    }

    /**
     * Check that this resultset is updateable.
     *
     * @throws SQLException if connection closed.
     */
    void checkUpdateable() throws SQLException {
        if (concurrency == ResultSet.CONCUR_READ_ONLY) {
            throw new SQLException(Messages.get("error.resultset.readonly"), "24000");
        }
    }

    /**
     * Report that user tried to call a method which has not been implemented.
     *
     * @param method The method name to report in the error message.
     * @throws SQLException
     */
    static void notImplemented(final String method) throws SQLException {
        throw new SQLException(Messages.get("error.generic.notimp", method), "HYC00");
    }

    /**
     * Called by the TDS protocol to add a new row to the table buffer.
     * @param row the new row to add.
     */
    void addRow(final Object row[]) {
        rows.add(row);
        eof       = false;
        rowsInResult++;
        bufferPos = 0;
    }
    
    /**
     * Set the internal table buffer to the supplied value.
     * @param rows the new table buffer object.
     */
    void setRows(final ArrayList<Object[]> rows) {
        this.rows = rows;
        rowsInResult = rows.size();
        eof = true;
    }
    
    /**
     * Get the internal table buffer.
     * @return the table buffer as an <code>ArrayList</code>.
     */
    ArrayList<Object[]> getRows()
    {
        return rows;
    }
    
    /**
     * Append the data in another result set to this one.
     * @param rs the result set with the data to append.
     */
    void append(final ResultSetImpl rs) {
        rows.addAll(rs.getRows());
        rowsInResult = rows.size();
        eof = true;
    }
    
    /**
     * Called by the TdsCore instance to indicate that all rows have
     * been read.
     */
    void setEof() {
        eof = true;        
    }
    
    /**
     * Indicates that EOF has been set on this result set.
     * @return <code>boolean</code> true if at end of file.
     */
    boolean isEof(){
        return eof;
    }

//
// -------------------- java.sql.ResultSet methods -------------------
//
    public int getConcurrency() throws SQLException {
        checkOpen();

        return concurrency;
    }

    public int getFetchDirection() throws SQLException {
        checkOpen();

        return fetchDirection;
    }

    public int getFetchSize() throws SQLException {
        checkOpen();

        return fetchSize;
    }

    public int getRow() throws SQLException {
        checkOpen();

        return pos > 0 ? pos : 0;
    }

    public int getType() throws SQLException {
        checkOpen();

        return resultSetType;
    }

    public void afterLast() throws SQLException {
        checkOpen();
        checkScrollable();
        pos = POS_AFTER_LAST;
    }

    public void beforeFirst() throws SQLException {
        checkOpen();
        checkScrollable();
        pos = POS_BEFORE_FIRST;
    }

    public void cancelRowUpdates() throws SQLException {
        checkOpen();
        checkUpdateable();
    }

    public void clearWarnings() throws SQLException {
        checkOpen();
    }

    public void close() throws SQLException {
        if (!closed) {
            Logger.printMethod(this, "close", null);
            try {
                if (!con.isClosed()) {
                   // Skip to end of result set
                   // Could send cancel but this is safer as
                   // cancel could kill other statements in a batch.
                   while (next());
                }
            } finally {
                setClosed();
            }
        }
    }

    public void deleteRow() throws SQLException {
        checkOpen();
        checkUpdateable();
    }

    public void insertRow() throws SQLException {
        checkOpen();
        checkUpdateable();
        rows.add(insertRow);
        insertRow = new Object[columns.length];
        eof = true;
    }

    public void moveToCurrentRow() throws SQLException {
        checkOpen();
        checkUpdateable();
    }


    public void moveToInsertRow() throws SQLException {
        checkOpen();
        checkUpdateable();
        insertRow = new Object[columns.length];
    }

    public void refreshRow() throws SQLException {
        checkOpen();
        checkUpdateable();
    }

    public void updateRow() throws SQLException {
        checkOpen();
        checkUpdateable();
    }

    public boolean first() throws SQLException {
        return absolute(1);
    }

    public boolean isAfterLast() throws SQLException {
        checkOpen();

        return (pos == POS_AFTER_LAST) && (rowsInResult != 0);
    }

    public boolean isBeforeFirst() throws SQLException {
        checkOpen();

        return (pos == POS_BEFORE_FIRST) && (rowsInResult != 0);
    }

    public boolean isFirst() throws SQLException {
        checkOpen();

        return pos == 1;
    }

    public boolean isLast() throws SQLException {
        checkOpen();
        if (resultSetType == ResultSet.TYPE_FORWARD_ONLY) {
            return (pos == rowsInResult) && (rowsInResult != 0);
        } else {
            return pos == rows.size() && rows.size() != 0;
        }
    }

    public boolean last() throws SQLException {
        return absolute(-1);
    }

    public boolean next() throws SQLException {
        checkOpen();
        if (resultSetType == ResultSet.TYPE_FORWARD_ONLY) {
            if (bufferPos < rows.size()) {
                currentRow = rows.get(bufferPos++);
                if (!eof) {
                    rows.clear();
                    statement.processResults(false);
                }
                pos++;
                return true;
            }
            currentRow = null;
            pos = POS_AFTER_LAST;
            return false;
        }
        if (pos == POS_AFTER_LAST || pos >= rows.size()) {
            currentRow = null;
            pos = POS_AFTER_LAST;
            return false;
        }
        currentRow = rows.get(pos++);
        return true;
    }

    public boolean previous() throws SQLException {
        checkOpen();
        checkScrollable();

        return false;
    }

    public boolean rowDeleted() throws SQLException {
        checkOpen();
        checkUpdateable();

        return false;
    }

    public boolean rowInserted() throws SQLException {
        checkOpen();
        checkUpdateable();

        return false;
    }

    public boolean rowUpdated() throws SQLException {
        checkOpen();
        checkUpdateable();

        return false;
    }

    public boolean wasNull() throws SQLException {
        checkOpen();

        return wasNull;
    }

    public byte getByte(int columnIndex) throws SQLException {
        return ((Integer) Support.convert(con, getColumn(columnIndex), java.sql.Types.TINYINT, null)).byteValue();
    }

    public short getShort(int columnIndex) throws SQLException {
        return ((Integer) Support.convert(con, getColumn(columnIndex), java.sql.Types.SMALLINT, null)).shortValue();
    }

    public int getInt(int columnIndex) throws SQLException {
        return ((Integer) Support.convert(con, getColumn(columnIndex), java.sql.Types.INTEGER, null)).intValue();
    }

    public long getLong(int columnIndex) throws SQLException {
        return ((Long) Support.convert(con, getColumn(columnIndex), java.sql.Types.BIGINT, null)).longValue();
    }

    public float getFloat(int columnIndex) throws SQLException {
        return ((Float) Support.convert(con, getColumn(columnIndex), java.sql.Types.REAL, null)).floatValue();
    }

    public double getDouble(int columnIndex) throws SQLException {
        return ((Double) Support.convert(con, getColumn(columnIndex), java.sql.Types.DOUBLE, null)).doubleValue();
    }

    public void setFetchDirection(int direction) throws SQLException {
        checkOpen();
        switch (direction) {
        case FETCH_UNKNOWN:
        case FETCH_REVERSE:
            if (resultSetType == ResultSet.TYPE_FORWARD_ONLY) {
                throw new SQLException(Messages.get("error.resultset.fwdonly"), "24000");
            }
            // Fall through

        case FETCH_FORWARD:
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

        if (rows < 0 || (statement.getMaxRows() > 0 && rows > statement.getMaxRows())) {
            throw new SQLException(
                    Messages.get("error.generic.badparam",
                            Integer.toString(rows),
                            "rows"),
                    "HY092");
        }
        if (rows == 0) {
            rows = statement.getDefaultFetchSize();
        }
        fetchSize = rows;
    }

    public void updateNull(int columnIndex) throws SQLException {
        setColValue(columnIndex, Types.NULL, null, 0);
    }

    public boolean absolute(int row) throws SQLException {
        checkOpen();
        checkScrollable();
        if (row < 0) {
            pos = (rows.size() + row) + 1; 
        } else {
            pos = row;
        }
        if (pos < 1) {
            pos = POS_BEFORE_FIRST;
        } else 
        if (pos > rows.size()) {
            pos = POS_AFTER_LAST;
        } else {
            currentRow = rows.get(pos - 1);
            return true;
        }
        currentRow = null;
        return false;
    }

    public boolean getBoolean(int columnIndex) throws SQLException {
        return ((Boolean) Support.convert(con, getColumn(columnIndex), Types.BOOLEAN, null)).booleanValue();
    }

    public boolean relative(int row) throws SQLException {
        if (pos == POS_AFTER_LAST) {
            return absolute(rows.size() + row + 1);
        }
        return absolute(pos + row);
    }

    public byte[] getBytes(int columnIndex) throws SQLException {
        return (byte[]) Support.convert(con, getColumn(columnIndex), Types.BINARY, null);
    }

    public void updateByte(int columnIndex, byte x) throws SQLException {
        setColValue(columnIndex, Types.INTEGER, new Integer(x & 0xFF), 0);
    }

    public void updateDouble(int columnIndex, double x) throws SQLException {
        setColValue(columnIndex, Types.DOUBLE, new Double(x), 0);
    }

    public void updateFloat(int columnIndex, float x) throws SQLException {
        setColValue(columnIndex, Types.REAL, new Float(x), 0);
    }

    public void updateInt(int columnIndex, int x) throws SQLException {
        setColValue(columnIndex, Types.INTEGER, new Integer(x), 0);
    }

    public void updateLong(int columnIndex, long x) throws SQLException {
        setColValue(columnIndex, Types.BIGINT, new Long(x), 0);
    }

    public void updateShort(int columnIndex, short x) throws SQLException {
        setColValue(columnIndex, Types.INTEGER, new Integer(x), 0);
    }

    public void updateBoolean(int columnIndex, boolean x) throws SQLException {
        setColValue(columnIndex, Types.BIT, x ? Boolean.TRUE : Boolean.FALSE, 0);
    }

    public void updateBytes(int columnIndex, byte[] x) throws SQLException {
        setColValue(columnIndex, Types.VARBINARY, x, (x != null)? x.length: 0);
    }

    public InputStream getAsciiStream(int columnIndex) throws SQLException {
        Clob clob = getClob(columnIndex);

        if (clob == null) {
            return null;
        }

        return clob.getAsciiStream();
    }

    public InputStream getBinaryStream(int columnIndex) throws SQLException {
        Blob blob = getBlob(columnIndex);

        if (blob == null) {
            return null;
        }

        return blob.getBinaryStream();
    }

    public InputStream getUnicodeStream(int columnIndex) throws SQLException {
        ClobImpl clob = (ClobImpl) getClob(columnIndex);

        if (clob == null) {
            return null;
        }

        return clob.getUnicodeStream();
    }

    public void updateAsciiStream(int columnIndex, InputStream inputStream, int length)
        throws SQLException {
        if (inputStream == null || length < 0) {
             updateCharacterStream(columnIndex, null, 0);
        } else {
            try {
                updateCharacterStream(columnIndex, new InputStreamReader(inputStream, "US-ASCII"), length);
            } catch (UnsupportedEncodingException e) {
                // Should never happen!
            }
         }
    }

    public void updateBinaryStream(int columnIndex, InputStream inputStream, int length)
        throws SQLException {

        if (inputStream == null || length < 0) {
            updateBytes(columnIndex, null);
            return;
        }

        setColValue(columnIndex, java.sql.Types.VARBINARY, inputStream, length);
    }

    public Reader getCharacterStream(int columnIndex) throws SQLException {
        Clob clob = getClob(columnIndex);

        if (clob == null) {
            return null;
        }

        return clob.getCharacterStream();
    }

    public void updateCharacterStream(int columnIndex, Reader reader, int length)
        throws SQLException {

        if (reader == null || length < 0) {
            updateString(columnIndex, null);
            return;
        }

        setColValue(columnIndex, java.sql.Types.VARCHAR, reader, length);
    }

    public Object getObject(int columnIndex) throws SQLException {
        Object value = getColumn(columnIndex);

        // Don't return UniqueIdentifier objects as the user won't know how to
        // handle them
        if (value instanceof UniqueIdentifier) {
            return value.toString();
        }
        // Don't return DateTime objects as the user won't know how to
        // handle them
        if (value instanceof DateTime) {
            return ((DateTime) value).toObject();
        }
        // If the user requested String/byte[] instead of LOBs, do the conversion
        if (!con.getUseLOBs()) {
            value = Support.convertLOB(value);
        }

        return value;
    }

    public void updateObject(int columnIndex, Object x) throws SQLException {
        checkOpen();
        int length = 0;
        int jdbcType = Types.VARCHAR; // Use for NULL values

        if (x != null) {
            // Need to do some conversion and testing here
            jdbcType = Support.getJdbcType(x);
            if (x instanceof BigDecimal) {
                int prec = con.getMaxPrecision();
                x = Support.normalizeBigDecimal((BigDecimal)x, prec);
            } else if (x instanceof Blob) {
                Blob blob = (Blob) x;
                x = blob.getBinaryStream();
                length = (int) blob.length();
            } else if (x instanceof Clob) {
                Clob clob = (Clob) x;
                x = clob.getCharacterStream();
                length = (int) clob.length();
            } else if (x instanceof String) {
                length = ((String)x).length();
            } else if (x instanceof byte[]) {
                length = ((byte[])x).length;
            }
            if (jdbcType == Types.JAVA_OBJECT) {
                // Unsupported class of object
                if (columnIndex < 1 || columnIndex > columnCount) {
                    throw new SQLException(Messages.get("error.resultset.colindex",
                            Integer.toString(columnIndex)),
                            "07009");
                }
                ColInfo ci = columns[columnIndex-1];
                throw new SQLException(
                        Messages.get("error.convert.badtypes",
                                x.getClass().getName(),
                                Support.getJdbcTypeName(ci.jdbcType)), "22005");
            }
        }

        setColValue(columnIndex, jdbcType, x, length);
    }

    public void updateObject(int columnIndex, Object x, int scale) throws SQLException {
        checkOpen();
        if (scale < 0 || scale > con.getMaxPrecision()) {
            throw new SQLException(Messages.get("error.generic.badscale"), "HY092");
        }

        if (x instanceof BigDecimal) {
            updateObject(columnIndex, ((BigDecimal) x).setScale(scale, BigDecimal.ROUND_HALF_UP));
        } else if (x instanceof Number) {
            synchronized (f) {
                f.setGroupingUsed(false);
                f.setMaximumFractionDigits(scale);
                updateObject(columnIndex, f.format(x));
            }
        } else {
            updateObject(columnIndex, x);
        }
    }

    public String getCursorName() throws SQLException {
        checkOpen();
        throw new SQLException(Messages.get("error.resultset.noposupdate"), "24000");
    }

    public String getString(int columnIndex) throws SQLException {
        return (String) Support.convert(con, getColumn(columnIndex), java.sql.Types.VARCHAR, null);
    }

    public void updateString(int columnIndex, String x) throws SQLException {
        setColValue(columnIndex, Types.VARCHAR, x , (x != null)? x.length(): 0);
    }

    public byte getByte(String columnName) throws SQLException {
        return getByte(findColumn(columnName));
    }

    public double getDouble(String columnName) throws SQLException {
        return getDouble(findColumn(columnName));
    }

    public float getFloat(String columnName) throws SQLException {
        return getFloat(findColumn(columnName));
    }

    public int findColumn(String columnName) throws SQLException {
        checkOpen();
        
        if (columnMap == null) {
            columnMap = new HashMap<String,Integer>(columnCount);
        } else {
            Integer ord = columnMap.get(columnName);
            if (ord != null) {
                return ord.intValue();
            }
        }

        // Rather than use toUpperCase()/toLowerCase(), which are costly,
        // just do a sequential search. It's actually faster in most cases.
        for (int i = 0; i < columnCount; i++) {
            if (columns[i].name.equalsIgnoreCase(columnName)) {
                columnMap.put(columnName, new Integer(i + 1));

                return i + 1;
            }
        }

        throw new SQLException(Messages.get("error.resultset.colname", columnName), "07009");
    }

    public int getInt(String columnName) throws SQLException {
        return getInt(findColumn(columnName));
    }

    public long getLong(String columnName) throws SQLException {
        return getLong(findColumn(columnName));
    }

    public short getShort(String columnName) throws SQLException {
        return getShort(findColumn(columnName));
    }

    public void updateNull(String columnName) throws SQLException {
        updateNull(findColumn(columnName));
    }

    public boolean getBoolean(String columnName) throws SQLException {
        return getBoolean(findColumn(columnName));
    }

    public byte[] getBytes(String columnName) throws SQLException {
        return getBytes(findColumn(columnName));
    }

    public void updateByte(String columnName, byte x) throws SQLException {
        updateByte(findColumn(columnName), x);
    }

    public void updateDouble(String columnName, double x) throws SQLException {
        updateDouble(findColumn(columnName), x);
    }

    public void updateFloat(String columnName, float x) throws SQLException {
        updateFloat(findColumn(columnName), x);
    }

    public void updateInt(String columnName, int x) throws SQLException {
        updateInt(findColumn(columnName), x);
    }

    public void updateLong(String columnName, long x) throws SQLException {
        updateLong(findColumn(columnName), x);
    }

    public void updateShort(String columnName, short x) throws SQLException {
        updateShort(findColumn(columnName), x);
    }

    public void updateBoolean(String columnName, boolean x) throws SQLException {
        updateBoolean(findColumn(columnName), x);
    }

    public void updateBytes(String columnName, byte[] x) throws SQLException {
        updateBytes(findColumn(columnName), x);
    }

    public BigDecimal getBigDecimal(int columnIndex) throws SQLException {
        return (BigDecimal) Support.convert(con, getColumn(columnIndex), java.sql.Types.DECIMAL, null);
    }

    public BigDecimal getBigDecimal(int columnIndex, int scale) throws SQLException {
        BigDecimal result = (BigDecimal) Support.convert(con, getColumn(columnIndex), java.sql.Types.DECIMAL, null);

        if (result == null) {
            return null;
        }

        return result.setScale(scale, BigDecimal.ROUND_HALF_UP);
    }

    public void updateBigDecimal(int columnIndex, BigDecimal x)
        throws SQLException {
        if (x != null) {
            int prec = con.getMaxPrecision();
            x = Support.normalizeBigDecimal(x, prec);
        }
        setColValue(columnIndex, Types.DECIMAL, x, 0);
    }

    public URL getURL(int columnIndex) throws SQLException {
        String url = getString(columnIndex);

        try {
            return new java.net.URL(url);
        } catch (MalformedURLException e) {
            throw new SQLException(Messages.get("error.resultset.badurl", url), "22000");
        }
    }

    public Array getArray(int columnIndex) throws SQLException {
        notImplemented("ResultSet.getArray()");
        return null;
    }

    public void updateArray(int columnIndex, Array x) throws SQLException {
        notImplemented("ResultSet.updateArray()");
    }

    public Blob getBlob(int columnIndex) throws SQLException {
        return (Blob) Support.convert(con, getColumn(columnIndex), java.sql.Types.BLOB, null);
    }

    public void updateBlob(int columnIndex, Blob x) throws SQLException {
        if (x == null) {
            updateBinaryStream(columnIndex, null, 0);
        } else {
            updateBinaryStream(columnIndex, x.getBinaryStream(), (int) x.length());
        }
    }

    public Clob getClob(int columnIndex) throws SQLException {
        return (Clob) Support.convert(con, getColumn(columnIndex), java.sql.Types.CLOB, null);
    }

    public void updateClob(int columnIndex, Clob x) throws SQLException {
        if (x == null) {
            updateCharacterStream(columnIndex, null, 0);
        } else {
            updateCharacterStream(columnIndex, x.getCharacterStream(), (int) x.length());
        }
    }

    public Date getDate(int columnIndex) throws SQLException {
        return (java.sql.Date)Support.convert(con, getColumn(columnIndex), java.sql.Types.DATE, null);
    }

    public void updateDate(int columnIndex, Date x) throws SQLException {
        setColValue(columnIndex, Types.DATE, x, 0);
    }

    public Ref getRef(int columnIndex) throws SQLException {
        checkOpen();
        notImplemented("ResultSet.getRef()");

        return null;
    }

    public void updateRef(int columnIndex, Ref x) throws SQLException {
        notImplemented("ResultSet.updateRef()");
    }

    public ResultSetMetaData getMetaData() throws SQLException {
        checkOpen();

        // If this is a DatabaseMetaData built result set, avoid getting an
        // exception because the statement is closed and assume no LOBs
        boolean useLOBs = statement.isClosed()
                ? false
                : con.getUseLOBs();
        return new ResultSetMetaDataImpl(columns, columnCount,
                useLOBs);
    }

    public SQLWarning getWarnings() throws SQLException {
        checkOpen();

        return null;
    }

    public Statement getStatement() throws SQLException {
        checkOpen();

        return statement;
    }

    public Time getTime(int columnIndex) throws SQLException {
        return (java.sql.Time) Support.convert(con, getColumn(columnIndex), java.sql.Types.TIME, null);
    }

    public void updateTime(int columnIndex, Time x) throws SQLException {
        setColValue(columnIndex, Types.TIME, x, 0);
    }

    public Timestamp getTimestamp(int columnIndex) throws SQLException {
        return (Timestamp) Support.convert(con, getColumn(columnIndex), java.sql.Types.TIMESTAMP, null);
    }

    public void updateTimestamp(int columnIndex, Timestamp x) throws SQLException {
        setColValue(columnIndex, Types.TIMESTAMP, x, 0);
    }

    public InputStream getAsciiStream(String columnName) throws SQLException {
        return getAsciiStream(findColumn(columnName));
    }

    public InputStream getBinaryStream(String columnName) throws SQLException {
        return getBinaryStream(findColumn(columnName));
    }

    public InputStream getUnicodeStream(String columnName) throws SQLException {
        return getUnicodeStream(findColumn(columnName));
    }

    public void updateAsciiStream(String columnName, InputStream x, int length)
        throws SQLException {
        updateAsciiStream(findColumn(columnName), x, length);
    }

    public void updateBinaryStream(String columnName, InputStream x, int length)
        throws SQLException {
        updateBinaryStream(findColumn(columnName), x, length);
    }

    public Reader getCharacterStream(String columnName) throws SQLException {
        return getCharacterStream(findColumn(columnName));
    }

    public void updateCharacterStream(String columnName, Reader x, int length)
        throws SQLException {
        updateCharacterStream(findColumn(columnName), x, length);
    }

    public Object getObject(String columnName) throws SQLException {
        return getObject(findColumn(columnName));
    }

    public void updateObject(String columnName, Object x) throws SQLException {
        updateObject(findColumn(columnName), x);
    }

    public void updateObject(String columnName, Object x, int scale)
        throws SQLException {
        updateObject(findColumn(columnName), x, scale);
    }

    public Object getObject(int columnIndex, Map<String, Class<?>> map) throws SQLException {
        notImplemented("ResultSet.getObject(int, Map)");
        return null;
    }

    public String getString(String columnName) throws SQLException {
        return getString(findColumn(columnName));
    }

    public void updateString(String columnName, String x) throws SQLException {
        updateString(findColumn(columnName), x);
    }

    public BigDecimal getBigDecimal(String columnName) throws SQLException {
        return getBigDecimal(findColumn(columnName));
    }

    public BigDecimal getBigDecimal(String columnName, int scale)
        throws SQLException {
        return getBigDecimal(findColumn(columnName), scale);
    }

    public void updateBigDecimal(String columnName, BigDecimal x)
        throws SQLException {
        updateObject(findColumn(columnName), x);
    }

    public URL getURL(String columnName) throws SQLException {
        return getURL(findColumn(columnName));
    }

    public Array getArray(String columnName) throws SQLException {
        return getArray(findColumn(columnName));
    }

    public void updateArray(String columnName, Array x) throws SQLException {
        updateArray(findColumn(columnName), x);
    }

    public Blob getBlob(String columnName) throws SQLException {
        return getBlob(findColumn(columnName));
    }

    public void updateBlob(String columnName, Blob x) throws SQLException {
        updateBlob(findColumn(columnName), x);
    }

    public Clob getClob(String columnName) throws SQLException {
        return getClob(findColumn(columnName));
    }

    public void updateClob(String columnName, Clob x) throws SQLException {
        updateClob(findColumn(columnName), x);
    }

    public Date getDate(String columnName) throws SQLException {
        return getDate(findColumn(columnName));
    }

    public void updateDate(String columnName, Date x) throws SQLException {
        updateDate(findColumn(columnName), x);
    }

    public Date getDate(int columnIndex, Calendar cal) throws SQLException {
        java.sql.Date date = getDate(columnIndex);

        if (date != null && cal != null) {
            date = new java.sql.Date(new DateTime().timeToZone(date, cal));
        }

        return date;
    }

    public Ref getRef(String columnName) throws SQLException {
        return getRef(findColumn(columnName));
    }

    public void updateRef(String columnName, Ref x) throws SQLException {
        updateRef(findColumn(columnName), x);
    }

    public Time getTime(String columnName) throws SQLException {
        return getTime(findColumn(columnName));
    }

    public void updateTime(String columnName, Time x) throws SQLException {
        updateTime(findColumn(columnName), x);
    }

    public Time getTime(int columnIndex, Calendar cal) throws SQLException {
        java.sql.Time time = getTime(columnIndex);

        if (time != null && cal != null) {
            return new Time(new DateTime().timeToZone(time, cal));
        }

        return time;
    }

    public Timestamp getTimestamp(String columnName) throws SQLException {
        return getTimestamp(findColumn(columnName));
    }

    public void updateTimestamp(String columnName, Timestamp x)
        throws SQLException {
        updateTimestamp(findColumn(columnName), x);
    }

    public Timestamp getTimestamp(int columnIndex, Calendar cal)
        throws SQLException {
            Timestamp timestamp = getTimestamp(columnIndex);

            if (timestamp != null && cal != null) {
                timestamp = new Timestamp(new DateTime().timeToZone(timestamp, cal));
            }

            return timestamp;
    }

    public Object getObject(String columnName, Map<String, Class<?>> map) throws SQLException {
        return getObject(findColumn(columnName), map);
    }

    public Date getDate(String columnName, Calendar cal) throws SQLException {
        return getDate(findColumn(columnName), cal);
    }

    public Time getTime(String columnName, Calendar cal) throws SQLException {
        return getTime(findColumn(columnName), cal);
    }

    public Timestamp getTimestamp(String columnName, Calendar cal)
        throws SQLException {
        return getTimestamp(findColumn(columnName), cal);
    }

    @Override
    public int getHoldability() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Reader getNCharacterStream(int columnIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Reader getNCharacterStream(String columnLabel) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public NClob getNClob(int columnIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public NClob getNClob(String columnLabel) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public String getNString(int columnIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public String getNString(String columnLabel) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public RowId getRowId(int columnIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public RowId getRowId(String columnLabel) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public SQLXML getSQLXML(int columnIndex) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public SQLXML getSQLXML(String columnLabel) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateAsciiStream(int columnIndex, InputStream x)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateAsciiStream(String columnLabel, InputStream x)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateAsciiStream(int columnIndex, InputStream x, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateAsciiStream(String columnLabel, InputStream x, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateBinaryStream(int columnIndex, InputStream x)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateBinaryStream(String columnLabel, InputStream x)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateBinaryStream(int columnIndex, InputStream x, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateBinaryStream(String columnLabel, InputStream x,
            long length) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateBlob(int columnIndex, InputStream inputStream)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateBlob(String columnLabel, InputStream inputStream)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateBlob(int columnIndex, InputStream inputStream, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateBlob(String columnLabel, InputStream inputStream,
            long length) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateCharacterStream(int columnIndex, Reader x)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateCharacterStream(String columnLabel, Reader reader)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateCharacterStream(int columnIndex, Reader x, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateCharacterStream(String columnLabel, Reader reader,
            long length) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateClob(int columnIndex, Reader reader) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateClob(String columnLabel, Reader reader)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateClob(int columnIndex, Reader reader, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateClob(String columnLabel, Reader reader, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNCharacterStream(int columnIndex, Reader x)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNCharacterStream(String columnLabel, Reader reader)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNCharacterStream(int columnIndex, Reader x, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNCharacterStream(String columnLabel, Reader reader,
            long length) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNClob(int columnIndex, NClob clob) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNClob(String columnLabel, NClob clob) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNClob(int columnIndex, Reader reader) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNClob(String columnLabel, Reader reader)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNClob(int columnIndex, Reader reader, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNClob(String columnLabel, Reader reader, long length)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNString(int columnIndex, String string)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateNString(String columnLabel, String string)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateRowId(int columnIndex, RowId x) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateRowId(String columnLabel, RowId x) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateSQLXML(int columnIndex, SQLXML xmlObject)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void updateSQLXML(String columnLabel, SQLXML xmlObject)
            throws SQLException {
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

    //// JDBC4.1 demarcation, do NOT put any JDBC3/4.0 code below this line ////

    @Override
    public <T> T getObject(int columnIndex, Class<T> type) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public <T> T getObject(String columnLabel, Class<T> type) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }
}
