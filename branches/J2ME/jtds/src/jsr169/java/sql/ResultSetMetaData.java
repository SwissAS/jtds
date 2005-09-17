// jTDS JDBC Driver for Microsoft SQL Server and Sybase
// Copyright (C) 2005 The jTDS Project
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
package java.sql;
/**
 * An object that can be used to get information about the types and properties
 * of the columns in a <code>ResultSet</code> object. The following code
 * fragment creates the <code>ResultSet</code> object rs, creates the
 * <code>ResultSetMetaData</code> object rsmd, and uses rsmd to find out how
 * many columns rs has and whether the first column in rs can be used in a
 * WHERE clause.
 * <pre>
 *      ResultSet rs = stmt.executeQuery("SELECT a, b, c FROM TABLE2");
 *      ResultSetMetaData rsmd = rs.getMetaData();
 *      int numberOfColumns = rsmd.getColumnCount();
 *      boolean b = rsmd.isSearchable(1);</pre>
 */
public interface ResultSetMetaData {

    /**
     * The constant indicating that a column does not allow NULL values.
     */
    int columnNoNulls = 0;

    /**
     * The constant indicating that a column allows NULL values.
     */
    int columnNullable = 1;

    /**
     * The constant indicating that the nullability of a column's values is
     * unknown.
     */
    int columnNullableUnknown = 2;

    /**
     * Returns the number of columns in this <code>ResultSet</code> object.
     *
     * @return the number of columns
     * @throws SQLException if a database access error occurs
     */
    int getColumnCount()
            throws SQLException;

    /**
     * Indicates whether the designated column is automatically numbered, thus
     * read-only.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return true if so; false otherwise
     * @throws SQLException if a database access error occurs
     */
    boolean isAutoIncrement(int column)
            throws SQLException;

    /**
     * Indicates whether a column's case matters.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return true if so; false otherwise
     * @throws SQLException if a database access error occurs
     */
    boolean isCaseSensitive(int column)
            throws SQLException;

    /**
     * Indicates whether the designated column can be used in a where clause.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return true if so; false otherwise
     * @throws SQLException if a database access error occurs
     */
    boolean isSearchable(int column)
            throws SQLException;

    /**
     * Indicates whether the designated column is a cash value.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return true if so; false otherwise
     * @throws SQLException if a database access error occurs
     */
    boolean isCurrency(int column)
            throws SQLException;

    /**
     * Indicates the nullability of values in the designated column.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return the nullability status of the given column; one of
     *         <code>columnNoNulls, columnNullable or columnNullableUnknown</code>
     * @throws SQLException if a database access error occurs
     */
    int isNullable(int column)
            throws SQLException;

    /**
     * Indicates whether values in the designated column are signed numbers.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return true if so; false otherwise
     * @throws SQLException if a database access error occurs
     */
    boolean isSigned(int column)
            throws SQLException;

    /**
     * Indicates the designated column's normal maximum width in characters.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return the normal maximum number of characters allowed as the width of
     *         the designated column
     * @throws SQLException if a database access error occurs
     */
    int getColumnDisplaySize(int column)
            throws SQLException;

    /**
     * Gets the designated column's suggested title for use in printouts and
     * displays.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return the suggested column title
     * @throws SQLException if a database access error occurs
     */
    String getColumnLabel(int column)
            throws SQLException;

    /**
     * Get the designated column's name.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return column name
     * @throws SQLException if a database access error occurs
     */
    String getColumnName(int column)
            throws SQLException;

    /**
     * Get the designated column's table's schema.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return schema name or "" if not applicable
     * @throws SQLException if a database access error occurs
     */
    String getSchemaName(int column)
            throws SQLException;

    /**
     * Get the designated column's number of decimal digits.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return precision
     * @throws SQLException if a database access error occurs
     */
    int getPrecision(int column)
            throws SQLException;

    /**
     * Gets the designated column's number of digits to right of the decimal
     * point.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return scale
     * @throws SQLException if a database access error occurs
     */
    int getScale(int column)
            throws SQLException;

    /**
     * Gets the designated column's table name.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return table name or "" if not applicable
     * @throws SQLException if a database access error occurs
     */
    String getTableName(int column)
            throws SQLException;

    /**
     * Gets the designated column's table's catalog name.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return the name of the catalog for the table in which the given column
     *         appears or "" if not applicable
     * @throws SQLException if a database access error occurs
     */
    String getCatalogName(int column)
            throws SQLException;

    /**
     * Retrieves the designated column's SQL type.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return SQL type from java.sql.Types
     * @throws SQLException if a database access error occurs
     */
    int getColumnType(int column)
            throws SQLException;

    /**
     * Retrieves the designated column's database-specific type name.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return type name used by the database. If the column type is a
     *         user-defined type, then a fully-qualified type name is returned.
     * @throws SQLException if a database access error occurs
     */
    String getColumnTypeName(int column)
            throws SQLException;

    /**
     * Indicates whether the designated column is definitely not writable.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return true if so; false otherwise
     * @throws SQLException if a database access error occurs
     */
    boolean isReadOnly(int column)
            throws SQLException;

    /**
     * Indicates whether it is possible for a write on the designated column to
     * succeed.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return true if so; false otherwise
     * @throws SQLException if a database access error occurs
     */
    boolean isWritable(int column)
            throws SQLException;

    /**
     * Indicates whether a write on the designated column will definitely
     * succeed.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return true if so; false otherwise
     * @throws SQLException if a database access error occurs
     */
    boolean isDefinitelyWritable(int column)
            throws SQLException;

    /**
     * Returns the fully-qualified name of the Java class whose instances are
     * manufactured if the method <code>ResultSet.getObject</code> is called to
     * retrieve a value from the column. <code>ResultSet.getObject</code> may
     * return a subclass of the class returned by this method.
     *
     * @param column the first column is 1, the second is 2, ...
     * @return the fully-qualified name of the class in the Java programming
     *         language that would be used by the method
     *         <code>ResultSet.getObject</code> to retrieve the value in the
     *         specified column. This is the class name used for custom mapping. 
     * @throws SQLException if a database access error occurs
     */
    String getColumnClassName(int column)
            throws SQLException;
}
