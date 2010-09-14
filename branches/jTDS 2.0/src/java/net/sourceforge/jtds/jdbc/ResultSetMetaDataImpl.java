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

import java.sql.ResultSetMetaData;
import java.sql.SQLException;

/**
 * jTDS implementation of the java.sql.ResultSetMetaData interface.
 * <p>
 * Implementation notes:
 * <ol>
 * <li>New simple implementation required by the new column info structure.
 * <li>Unlike the equivalent in the older jTDS, this version is generic and does
 *     not need to know details of the TDS protocol.
 * </ol>
 *
 * @author Mike Hutchinson
 * @version $Id: ResultSetMetaDataImpl.java,v 1.3 2009-09-27 12:59:02 ickzon Exp $
 */
public class ResultSetMetaDataImpl implements ResultSetMetaData {
    private final ColInfo[] columns;
    private final int columnCount;
    private final boolean useLOBs;

    /**
     * Construct ResultSetMetaData object over the current ColInfo array.
     *
     * @param columns The current ColInfo row descriptor array.
     * @param columnCount The number of visible columns.
     */
    ResultSetMetaDataImpl(final ColInfo[] columns, 
                          final int columnCount, 
                          final boolean useLOBs) 
    {
        this.columns = columns;
        this.columnCount = columnCount;
        this.useLOBs = useLOBs;
    }

    /**
     * Return the column descriptor given a column index.
     *
     * @param column The column index (from 1 .. n).
     * @return The column descriptor as a <code>ColInfo<code>.
     * @throws SQLException
     */
    ColInfo getColumn(final int column) throws SQLException {
        if (column < 1 || column > columnCount) {
            throw new SQLException(
                    Messages.get("error.resultset.colindex",
                            Integer.toString(column)), "07009");
        }

        return columns[column - 1];
    }

    /**
     * Retrieve the currency status of the column.
     *
     * @param ci The column meta data.
     * @return <code>boolean</code> true if the column is a currency type.
     */
    private boolean isCurrency(final ColInfo ci) {
        return (ci.sqlType.equals("money") || ci.sqlType.equals("smallmoney"));
    }

    /**
     * Retrieve the searchable status of the column.
     *
     * @param ci the column meta data
     * @return <code>true</code> if the column is not a text or image type.
     */
    private boolean isSearchable(final ColInfo ci) {
        return !ci.sqlType.equals("text") &&
               !ci.sqlType.equals("ntext") &&
               !ci.sqlType.equals("unitext") &&
               !ci.sqlType.equals("image") &&
               !ci.sqlType.equals("xml") &&
                ci.tdsType != 240; // User Defined CLR type
    }

    /**
     * Retrieve the signed status of the column.
     *
     * @param ci the column meta data
     * @return <code>true</code> if the column is a signed numeric.
     */
    private boolean isSigned(final ColInfo ci) {
        return ci.sqlType.startsWith("smallint") ||
               ci.sqlType.startsWith("int") ||
               ci.sqlType.startsWith("bigint") ||
               ci.sqlType.equals("float") ||
               ci.sqlType.equals("real") ||
               ci.sqlType.startsWith("decimal") ||
               ci.sqlType.startsWith("numeric") ||
               ci.sqlType.equals("money") ||
               ci.sqlType.equals("smallmoney");
    }

    // ------  java.sql.ResultSetMetaData methods follow -------

    public int getColumnCount() throws SQLException {
        return this.columnCount;
    }

    public int getColumnDisplaySize(int column) throws SQLException {
        return getColumn(column).displaySize;
    }

    public int getColumnType(int column) throws SQLException {
        if (useLOBs) {
            return getColumn(column).jdbcType;
        }
        return Support.convertLOBType(getColumn(column).jdbcType);
    }

    public int getPrecision(int column) throws SQLException {
        return getColumn(column).precision;
    }

    public int getScale(int column) throws SQLException {
        return getColumn(column).scale;
    }

    public int isNullable(int column) throws SQLException {
        return getColumn(column).nullable;
    }

    public boolean isAutoIncrement(int column) throws SQLException {
        return getColumn(column).isIdentity;
    }

    public boolean isCaseSensitive(int column) throws SQLException {
        return getColumn(column).isCaseSensitive;
    }

    public boolean isCurrency(int column) throws SQLException {
        return isCurrency(getColumn(column));
    }

    public boolean isDefinitelyWritable(int column) throws SQLException {
        getColumn(column);

        return false;
    }

    public boolean isReadOnly(int column) throws SQLException {
        return !getColumn(column).isWriteable;
    }

    public boolean isSearchable(int column) throws SQLException {
        return isSearchable(getColumn(column));
    }

    public boolean isSigned(int column) throws SQLException {
        return isSigned(getColumn(column));
    }

    public boolean isWritable(int column) throws SQLException {
        return getColumn(column).isWriteable;
    }

    public String getCatalogName(int column) throws SQLException {
        ColInfo col = getColumn(column);

        return (col.catalog == null) ? "" : col.catalog;
    }

    public String getColumnClassName(int column) throws SQLException {
        String c = Support.getClassName(getColumnType(column));
        if (!useLOBs) {
            if (c.equals("java.sql.Clob")) {
                return "java.lang.String";
            }
            if (c.equals("java.sql.Blob")) {
                return "[B";
            }
        }
        return c;
    }

    public String getColumnLabel(int column) throws SQLException {
        return getColumn(column).name;
    }

    public String getColumnName(int column) throws SQLException {
        return getColumn(column).name;
    }

    public String getColumnTypeName(int column) throws SQLException {
        return getColumn(column).sqlType;
    }

    public String getSchemaName(int column) throws SQLException {
        ColInfo col = getColumn(column);

        return (col.schema == null) ? "" : col.schema;
    }

    public String getTableName(int column) throws SQLException {
        ColInfo col = getColumn(column);

        return (col.tableName == null) ? "" : col.tableName;
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
