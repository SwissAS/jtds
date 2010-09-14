//jTDS JDBC Driver for Microsoft SQL Server and Sybase
//Copyright (C) 2004 The jTDS Project
//
//This library is free software; you can redistribute it and/or
//modify it under the terms of the GNU Lesser General Public
//License as published by the Free Software Foundation; either
//version 2.1 of the License, or (at your option) any later version.
//
//This library is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//Lesser General Public License for more details.
//
//You should have received a copy of the GNU Lesser General Public
//License along with this library; if not, write to the Free Software
//Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
package net.sourceforge.jtds.jdbc;

import java.sql.SQLException;
import java.util.ArrayList;

/**
 * This class implements a memory cached scrollable/updateable result set.
 * <p>
 * Notes:
 * <ol>
 * <li>For maximum performance use the scroll insensitive result set type.
 * <li>As the result set is cached in memory this implementation is limited
 * to small result sets.
 * <li>Updateable or scroll sensitive result sets are limited to selects which
 * reference one table only.
 * <li>Scroll sensitive result sets must have primary keys.
 * <li>Updates are optimistic. To guard against lost updates it is recommended
 * that the table includes a timestamp column.
 * <li>This class is a plug-in replacement for the MSCursorResultSet class which
 * may be advantageous in certain applications as the scroll insensitive result
 * set implemented here is much faster than the server side cursor.
 * <li>Updateable result sets cannot be built from the output of stored procedures.
 * <li>This implementation uses 'select ... for browse' to obtain the column meta
 * data needed to generate update statements etc.
 * <li>Named forward updateable cursors are also supported in which case positioned updates
 * and deletes are used referencing a server side declared cursor.
 * <li>Named forward read only declared cursors can have a larger fetch size specified
 * allowing a cursor alternative to the default direct select method.
 * <ol>
 *
 * @author Mike Hutchinson
 * @version $Id: CachedResultSet.java,v 1.15.2.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public class CachedResultSet extends JtdsResultSet {

    /** Indicates currently inserting. */
    protected boolean onInsertRow;
    /** Buffer row used for inserts. */
    protected ParamInfo[] insertRow;
    /** The "update" row. */
    protected ParamInfo[] updateRow;
    /** The row count of the initial result set. */
    protected int initialRowCnt;
    /**
     * If set, the <code>ResultSet</code> is in the init phase, i.e is
     * updateable.
     */
    protected boolean initializing;

    /**
     * Construct a cached result set based on locally generated data.
     * @param statement       The parent statement object.
     * @param colName         Array of column names.
     * @param colType         Array of corresponding data types.
     * @exception java.sql.SQLException
     */
    CachedResultSet(JtdsStatement statement,
                    String[] colName, int[] colType) throws SQLException {
        super(statement, null);
        //
        // Construct the column descriptor array
        //
        this.columns = new ColInfo[colName.length];
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
            TdsData.fillInType(ci);
            columns[i] = ci;
        }
        this.columnCount   = getColumnCount(columns);
        this.rowData       = new ArrayList(INITIAL_ROW_COUNT);
        this.rowsInResult  = 0;
        this.initialRowCnt = 0;
        this.pos           = POS_BEFORE_FIRST;
        this.initializing  = true;
    }

    /**
     * Create a cached result set with the same columns
     * (and optionally data) as an existing result set.
     *
     * @param rs The result set to copy.
     */
    CachedResultSet(JtdsResultSet rs) throws SQLException {
        super((JtdsStatement)rs.getStatement(), null);

        this.columns       = rs.getColumns();
        this.columnCount   = getColumnCount(columns);
        this.rowData       = new ArrayList(INITIAL_ROW_COUNT);
        this.rowsInResult  = 0;
        this.initialRowCnt = 0;
        this.pos           = POS_BEFORE_FIRST;
        this.initializing  = true;
    }

    /**
     * Create a cached result set containing one row.
     * @param statement The parent statement object.
     * @param columns   The column descriptor array.
     * @param data      The row data.
     * @throws SQLException
     */
    CachedResultSet(JtdsStatement statement,
            ColInfo columns[], Object data[]) throws SQLException {
        super(statement, null);
        this.columns       = columns;
        this.columnCount   = getColumnCount(columns);
        this.rowData       = new ArrayList(1);
        this.rowsInResult  = 1;
        this.initialRowCnt = 1;
        this.pos           = POS_BEFORE_FIRST;
        this.rowData.add(copyRow(data));
    }

    /**
     * End the creation phase, i.e make the <code>ResultSet</code> read only.
     */
    void initDone() {
        initializing = false;
    }

    /**
     * Fetch the next result row from the internal row array.
     *
     * @param rowNum The row number to fetch.
     * @return <code>boolean</code> true if a result set row is returned.
     */
    private boolean cursorFetch(int rowNum) {
        //
        // JDBC2 style Scrollable and/or Updateable cursor
        //
        if (rowsInResult == 0) {
            pos = POS_BEFORE_FIRST;
            currentRow = null;
            return false;
        }
        if (rowNum == pos) {
            // On current row
            //
            return true;
        }
        if (rowNum < 1) {
            currentRow = null;
            pos = POS_BEFORE_FIRST;
            return false;
        }
        if (rowNum > rowsInResult) {
            currentRow = null;
            pos = POS_AFTER_LAST;
            return false;
        }
        pos = rowNum;
        currentRow = (Object[])rowData.get(rowNum-1);

        return true;
    }

    /**
     * Set the specified column's data value.
     *
     * @param colIndex The index of the column in the row.
     * @param value The new column value.
     */
    protected void setColValue(int colIndex, int jdbcType, Object value, int length)
            throws SQLException {

        super.setColValue(colIndex, jdbcType, value, length);

        if (!onInsertRow && currentRow == null) {
            throw new SQLException(Messages.get("error.resultset.norow"), "24000");
        }
        colIndex--;
        ParamInfo pi;
        ColInfo ci = columns[colIndex];
        boolean isUnicode = TdsData.isUnicode(ci);

        if (onInsertRow) {
            pi = insertRow[colIndex];
            if (pi == null) {
                pi = new ParamInfo(-1, isUnicode);
                pi.collation = ci.collation;
                pi.charsetInfo = ci.charsetInfo;
                insertRow[colIndex] = pi;
            }
        } else {
            if (updateRow == null) {
                updateRow = new ParamInfo[columnCount];
            }
            pi = updateRow[colIndex];
            if (pi == null) {
                pi = new ParamInfo(-1, isUnicode);
                pi.collation = ci.collation;
                pi.charsetInfo = ci.charsetInfo;
                updateRow[colIndex] = pi;
            }
        }

        if (value == null) {
            pi.value    = null;
            pi.length   = 0;
            pi.jdbcType = ci.jdbcType;
            pi.isSet    = true;
        } else {
            pi.value     = value;
            pi.length    = length;
            pi.jdbcType  = jdbcType;
            pi.isSet     = true;
        }
    }

//
//  -------------------- java.sql.ResultSet methods -------------------
//

    public void cancelRowUpdates() throws SQLException {
        checkOpen();
        checkUpdateable();
        if (onInsertRow) {
            throw new SQLException(Messages.get("error.resultset.insrow"), "24000");
        }
        if (updateRow != null) {
            for (int i = 0; i < updateRow.length; i++) {
                if (updateRow[i] != null) {
                    updateRow[i].clearInValue();
                }
            }
        }
    }

    public void close() throws SQLException {
        if (!closed) {
            closed    = true;
            statement = null;
        }
    }

    public void insertRow() throws SQLException {
        checkOpen();

        checkUpdateable();

        if (!onInsertRow) {
            throw new SQLException(Messages.get("error.resultset.notinsrow"), "24000");
        }

        //
        // Now insert copy of row into result set buffer
        //
        ConnectionJDBC2 con = (ConnectionJDBC2)statement.getConnection();
        Object row[] = newRow();
        for (int i = 0; i < insertRow.length; i++) {
            if (insertRow[i] != null) {
                row[i] = Support.convert(con, insertRow[i].value,
                        columns[i].jdbcType, con.getCharset());
            }
        }
        rowData.add(row);

        rowsInResult++;
        initialRowCnt++;
        //
        // Clear row data
        //
        for (int i = 0; insertRow != null && i < insertRow.length; i++) {
            if (insertRow[i] != null) {
                insertRow[i].clearInValue();
            }
        }
    }

    public void moveToCurrentRow() throws SQLException {
        checkOpen();
        checkUpdateable();
        insertRow = null;
        onInsertRow = false;
    }


    public void moveToInsertRow() throws SQLException {
        checkOpen();
        checkUpdateable();
        insertRow   = new ParamInfo[columnCount];
        onInsertRow = true;
    }

    public boolean isLast() throws SQLException {
        checkOpen();

        return(pos == rowsInResult) && (rowsInResult != 0);
    }

    public boolean next() throws SQLException {
        checkOpen();
        if (pos != POS_AFTER_LAST) {
            return cursorFetch(pos+1);
        } else {
            return false;
        }
    }

    protected void checkUpdateable() throws SQLException {
        if (!initializing) {
            super.checkUpdateable();
        }
    }
}
