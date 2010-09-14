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
package javax.sql;

import java.io.InputStream;
import java.io.Reader;
import java.sql.*;
import java.util.Calendar;
import java.util.Map;

/**
 * The interface that adds support to the JDBC API for the JavaBeansTM component
 * model. A rowset, which can be used as a <code>JavaBeans</code> component in
 * a visual <code>Bean</code> development environment, can be created and
 * configured at design time and executed at run time.
 * <p/>
 * The <code>RowSet</code> interface provides a set of JavaBeans properties that
 * allow a <code>RowSet</code> instance to be configured to connect to a JDBC
 * data source and read some data from the data source. A group of setter methods
 * (<code>setInt, setBytes, setString</code>, and so on) provide a way to pass
 * input parameters to a rowset's command property. This command is the SQL
 * query the rowset uses when it gets its data from a relational database, which
 * is generally the case.
 * <p/>
 * The <code>RowSet</code> interface supports JavaBeans events, allowing other
 * components in an application to be notified when an event occurs on a rowset,
 * such as a change in its value.
 * <p/>
 * The <code>RowSet</code> interface is unique in that it is intended to be
 * implemented using the rest of the JDBC API. In other words, a
 * <code>RowSet</code> implementation is a layer of software that executes
 * "on top" of a JDBC driver. Implementations of the <code>RowSet</code>
 * interface can be provided by anyone, including JDBC driver vendors who want
 * to provide a <code>RowSet</code> implementation as part of their JDBC
 * products.
 * <p/>
 * A <code>RowSet</code> object may make a connection with a data source and
 * maintain that connection throughout its life cycle, in which case it is
 * called a connected rowset. A rowset may also make a connection with a data
 * source, get data from it, and then close the connection. Such a rowset is
 * called a <i>disconnected</i> rowset. A <i>disconnected</i> rowset may make
 * changes to its data while it is disconnected and then send the changes back
 * to the original source of the data, but it must reestablish a connection to
 * do so.
 * <p/>
 * A <i>disconnected</i> rowset may have a <code>reader</code> (a
 * <code>RowSetReader</code> object) and a <code>writer</code> (a
 * <code>RowSetWriter</code> object) associated with it. The reader may be
 * implemented in many different ways to populate a rowset with data, including
 * getting data from a non-relational data source. The writer can also be
 * implemented in many different ways to propagate changes made to the rowset's
 * data back to the underlying data source.
 * <p/>
 * Rowsets are easy to use. The <code>RowSet</code> interface extends the
 * standard <code>java.sql.ResultSet</code> interface. The
 * <code>RowSetMetaData</code> interface extends the
 * <code>java.sql.ResultSetMetaData</code> interface. Thus, developers familiar
 * with the JDBC API will have to learn a minimal number of new APIs to use
 * rowsets. In addition, third-party software tools that work with JDBC
 * <code>ResultSet</code> objects will also easily be made to work with rowsets.
 */
public interface RowSet
        extends ResultSet {

    /**
     * Retrieves the logical name that identifies the data source for this
     * <code>RowSet</code> object. Users should set either the url property or
     * the data source name property. The rowset will use the property that was
     * set more recently to get a connection.
     *
     * @return a data source name
     * @see #setDataSourceName(java.lang.String)
     */
    String getDataSourceName();

    /**
     * Sets the data source name property for this <code>RowSet</code> object to
     * the given <code>String</code>.
     * <p/>
     * The value of the data source name property can be used to do a lookup of
     * a <code>DataSource</code> object that has been registered with a naming
     * service. After being retrieved, the DataSource object can be used to
     * create a connection to the data source that it represents.
     *
     * @param name the logical name of the data source for this
     *             <code>RowSet</code> object
     * @throws SQLException if a database access error occurs
     * @see #getDataSourceName()
     */
    void setDataSourceName(String name)
            throws SQLException;

    /**
     * Retrieves the username used to create a database connection for this
     * <code>RowSet</code> object. The username property is set at run time
     * before calling the method <code>execute</code>. It is not usually part of
     * the serialized state of a <code>RowSet</code> object.
     *
     * @return the username property
     * @see #setUsername(java.lang.String)
     */
    String getUsername();

    /**
     * Sets the username property for this <code>RowSet</code> object to the
     * given <code>String</code>.
     *
     * @param name a user name
     * @throws SQLException if a database access error occurs
     * @see #getUsername()
     */
    void setUsername(String name)
            throws SQLException;

    /**
     * Retrieves the password used to create a database connection. The password
     * property is set at run time before calling the method
     * <code>execute</code>. It is not usually part of the serialized state of a
     * <code>RowSet</code> object.
     *
     * @return the password for making a database connection
     * @see #setPassword(java.lang.String)
     */
    String getPassword();

    /**
     * Sets the database password for this <code>RowSet</code> object to the
     * given String.
     *
     * @param password  the password string
     * @throws SQLException if a database access error occurs
     * @see #getPassword()
     */
    void setPassword(String password)
            throws SQLException;

    /**
     * Retrieves the transaction isolation level set for this
     * <code>RowSet</code> object.
     *
     * @return the transaction isolation level; one of
     *         Connection.TRANSACTION_READ_UNCOMMITTED,
     *         Connection.TRANSACTION_READ_COMMITTED,
     *         Connection.TRANSACTION_REPEATABLE_READ, or
     *         Connection.TRANSACTION_SERIALIZABLE
     * @see #setTransactionIsolation(int)
     */
    int getTransactionIsolation();

    /**
     * Sets the transaction isolation level for this <code>RowSet</code> object.
     *
     * @param level the transaction isolation level; one of
     *              Connection.TRANSACTION_READ_UNCOMMITTED,
     *              Connection.TRANSACTION_READ_COMMITTED,
     *              Connection.TRANSACTION_REPEATABLE_READ, or
     *              Connection.TRANSACTION_SERIALIZABLE
     * @throws SQLException if a database access error occurs
     * @see #getTransactionIsolation()
     */
    void setTransactionIsolation(int level)
            throws SQLException;

    /**
     * Retrieves the <code>Map</code> object associated with this
     * <code>RowSet</code> object, which specifies the custom mapping of SQL
     * user-defined types, if any. The default is for the type map to be empty.
     *
     * @return a <code>java.util.Map</code> object containing the names of SQL
     *                                      user-defined types and the Java
     *                                      classes to which they are to be
     *                                      mapped
     * @throws SQLException if a database access error occurs
     * @see #setTypeMap(java.util.Map)
     */
    Map getTypeMap()
            throws SQLException;

    /**
     * Installs the given <code>java.util.Map</code> object as the default type
     * map for this RowSet object. This type map will be used unless another
     * type map is supplied as a method parameter.
     *
     * @param map a <code>java.util.Map</code> object containing the names of
     *            SQL user-defined types and the Java classes to which they are
     *            to be mapped
     * @throws SQLException if a database access error occurs
     * @see #getTypeMap()
     */
    void setTypeMap(Map map)
            throws SQLException;

    /**
     * Retrieves this <code>RowSet</code> object's command property. The command
     * property contains a command string, which must be an SQL query, that can
     * be executed to fill the rowset with data. The default value is null.
     *
     * @return the command string; may be null
     * @see #setCommand(java.lang.String)
     */
    String getCommand();

    /**
     * Sets this <code>RowSet</code> object's command property to the given SQL
     * query. This property is optional when a rowset gets its data from a data
     * source that does not support commands, such as a spreadsheet.
     *
     * @param cmd the SQL query that will be used to get the data for this
     *            <code>RowSet</code> object; may be null
     * @throws SQLException if a database access error occurs
     * @see #getCommand()
     */
    void setCommand(String cmd)
            throws SQLException;

    /**
     * Retrieves whether this <code>RowSet</code> object is read-only. If
     * updates are possible, the default is for a rowset to be updatable.
     * <p/>
     * Attempts to update a read-only rowset will result in an SQLException
     * being thrown.
     *
     * @return true if this <code>RowSet</code> object is read-only; false if
     *         it is updatable
     * @see #setReadOnly(boolean)
     */
    boolean isReadOnly();

    /**
     * Sets whether this <code>RowSet</code> object is read-only to the given
     * boolean.
     *
     * @param value true if read-only; false if updatable
     * @throws SQLException if a database access error occurs
     * @see #isReadOnly()
     */
    void setReadOnly(boolean value)
            throws SQLException;

    /**
     * Retrieves the maximum number of bytes that may be returned for certain
     * column values. This limit applies only to BINARY, VARBINARY,
     * LONGVARBINARYBINARY, CHAR, VARCHAR, and LONGVARCHAR columns. If the limit
     * is exceeded, the excess data is silently discarded.
     *
     * @return the current maximum column size limit; zero means that there is
     *         no limit
     * @throws SQLException if a database access error occurs
     * @see #setMaxFieldSize(int)
     */
    int getMaxFieldSize()
            throws SQLException;

    /**
     * Sets the maximum number of bytes that can be returned for a column value
     * to the given number of bytes. This limit applies only to BINARY,
     * VARBINARY, LONGVARBINARYBINARY, CHAR, VARCHAR, and LONGVARCHAR columns.
     * If the limit is exceeded, the excess data is silently discarded.
     * For maximum portability, use values greater than 256.
     *
     * @param max the new max column size limit in bytes; zero means unlimited
     * @throws SQLException if a database access error occurs
     * @see #getMaxFieldSize()
     */
    void setMaxFieldSize(int max)
            throws SQLException;

    /**
     * Retrieves the maximum number of rows that this <code>RowSet</code> object
     * can contain. If the limit is exceeded, the excess rows are silently
     * dropped.
     *
     * @return the current maximum number of rows that this <code>RowSet</code>
     *         object can contain; zero means unlimited
     * @throws SQLException if a database access error occurs
     * @see #setMaxRows(int)
     */
    int getMaxRows()
            throws SQLException;

    /**
     * Sets the maximum number of rows that this <code>RowSet</code> object can
     * contain to the specified number. If the limit is exceeded, the excess
     * rows are silently dropped.
     *
     * @param max the new maximum number of rows; zero means unlimited
     * @throws SQLException if a database access error occurs
     * @see #getMaxRows()
     */
    void setMaxRows(int max)
            throws SQLException;

    /**
     * Retrieves whether escape processing is enabled for this
     * <code>RowSet</code> object. If escape scanning is enabled, which is the
     * default, the driver will do escape substitution before sending an SQL
     * statement to the database.
     *
     * @return true if escape processing is enabled; false if it is disabled
     * @throws SQLException if a database access error occurs
     * @see #setEscapeProcessing(boolean)
     */
    boolean getEscapeProcessing()
            throws SQLException;

    /**
     * Sets escape processing for this <code>RowSet</code> object on or off. If
     * escape scanning is on (the default), the driver will do escape
     * substitution before sending an SQL statement to the database.
     *
     * @param enable true to enable escape processing; false to disable it
     * @throws SQLException if a database access error occurs
     * @see #getEscapeProcessing()
     */
    void setEscapeProcessing(boolean enable)
            throws SQLException;

    /**
     * Retrieves the maximum number of seconds the driver will wait for a
     * statement to execute. If this limit is exceeded, an SQLException is
     * thrown.
     *
     * @return the current query timeout limit in seconds; zero means unlimited
     * @throws SQLException if a database access error occurs
     * @see #setQueryTimeout(int)
     */
    int getQueryTimeout()
            throws SQLException;

    /**
     * Sets the maximum time the driver will wait for a statement to execute to
     * the given number of seconds. If this limit is exceeded, an SQLException
     * is thrown.
     *
     * @param seconds the new query timeout limit in seconds; zero means that
     *                there is no limit
     * @throws SQLException if a database access error occurs
     * @see #getQueryTimeout()
     */
    void setQueryTimeout(int seconds)
            throws SQLException;

    /**
     * Sets the type of this <code>RowSet</code> object to the given type. This
     * method is used to change the type of a rowset, which is by default
     * read-only and non-scrollable.
     *
     * @param type one of the <code>ResultSet</code> constants specifying a type:
     * ResultSet.TYPE_FORWARD_ONLY, ResultSet.TYPE_SCROLL_INSENSITIVE, or
     * ResultSet.TYPE_SCROLL_SENSITIVE
     * @throws SQLException if a database access error occurs
     * @see ResultSet#getType()
     */
    void setType(int type)
            throws SQLException;

    /**
     * Sets the concurrency of this <code>RowSet</code> object to the given
     * concurrency level. This method is used to change the concurrency level of
     * a rowset, which is by default ResultSet.CONCUR_READ_ONLY
     *
     * @param concurrency one of the <code>ResultSet</code> constants specifying
     *                    a concurrency level: ResultSet.CONCUR_READ_ONLY or
     *                    ResultSet.CONCUR_UPDATABLE
     * @throws SQLException if a database access error occurs
     * @see ResultSet#getConcurrency()
     */
    void setConcurrency(int concurrency)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's SQL
     * command to SQL NULL.
     * <p/>
     * <b>Note:</b> You must specify the parameter's SQL type.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param sqlType a SQL type code defined by <code>java.sql.Types</code>
     * @throws SQLException if a database access error occurs
     */
    void setNull(int parameterIndex, int sqlType)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's SQL
     * command to SQL NULL. This version of the method setNull should be used
     * for SQL user-defined types (UDTs) and REF type parameters. Examples of
     * UDTs include: STRUCT, DISTINCT, JAVA_OBJECT, and named array types.
     * <p/>
     * <b>Note:</b> To be portable, applications must give the SQL type code and
     * the fully qualified SQL type name when specifying a NULL UDT or REF
     * parameter. In the case of a UDT, the name is the type name of the
     * parameter itself. For a REF parameter, the name is the type name of the
     * referenced type. If a JDBC driver does not need the type code or type
     * name information, it may ignore it. Although it is intended for UDT and
     * REF parameters, this method may be used to set a null parameter of any
     * JDBC type. If the parameter does not have a user-defined or REF type,
     * the typeName parameter is ignored.
     *
     * @param paramIndex the first parameter is 1, the second is 2, ...
     * @param sqlType a value from <code>java.sql.Types</code>
     * @param typeName the fully qualified name of an SQL UDT or the type name
     *                 of the SQL structured type being referenced by a REF type;
     *                 ignored if the parameter is not a UDT or REF type
     * @throws SQLException if a database access error occurs
     */
    void setNull(int paramIndex, int sqlType, String typeName)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given Java boolean value. The driver converts this to an
     * SQL BIT value before sending it to the database.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setBoolean(int parameterIndex, boolean x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given Java byte value. The driver converts this to an SQL
     * TINYINT value before sending it to the database.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setByte(int parameterIndex, byte x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given Java short value. The driver converts this to an
     * SQL SMALLINT value before sending it to the database.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setShort(int parameterIndex, short x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given Java <code>int</code> value. The driver converts
     * this to an SQL INTEGER value before sending it to the database.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setInt(int parameterIndex, int x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given Java <code>long</code> value. The driver converts
     * this to an SQL BIGINT value before sending it to the database.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setLong(int parameterIndex, long x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given Java <code>float</code> value. The driver converts
     * this to an SQL REAL value before sending it to the database.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setFloat(int parameterIndex, float x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given Java <code>double</code> value. The driver converts
     * this to an SQL DOUBLE value before sending it to the database.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setDouble(int parameterIndex, double x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given Java <code>string</code> value. Before sending it to
     * the database, the driver converts this to an SQL VARCHAR or LONGVARCHAR
     * value, depending on the argument's size relative to the driver's limits
     * on VARCHAR values.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setString(int parameterIndex, String x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given Java <code>array of byte</code> values. Before
     * sending it to the database, the driver converts this to an SQL VARBINARY
     * or LONGVARBINARY value, depending on the argument's size relative to the
     * driver's limits on VARBINARY values.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setBytes(int parameterIndex, byte[] x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given <code>java.sql.Date</code> value. The driver
     * converts this to an SQL DATE value before sending it to the database,
     * using the default <code>java.util.Calendar</code> to calculate the date.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setDate(int parameterIndex, Date x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given <code>java.sql.Time</code> value. The driver
     * converts this to an SQL TIME value before sending it to the database,
     * using the default <code>java.util.Calendar</code> to calculate it.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setTime(int parameterIndex, Time x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given <code>java.sql.Timestamp</code> value. The driver
     * converts this to an SQL TIMESTAMP value before sending it to the database,
     * using the default <code>java.util.Calendar</code> to calculate it.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @throws SQLException if a database access error occurs
     */
    void setTimestamp(int parameterIndex, Timestamp x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given <code>java.io.InputStream</code> value. It may be
     * more practical to send a very large ASCII value via a
     * <code>java.io.InputStream</code> rather than as a LONGVARCHAR parameter.
     * The driver will read the data from the stream as needed until it reaches
     * end-of-file.
     * <p/>
     * <b>Note:</b> This stream object can either be a standard Java stream
     * object or your own subclass that implements the standard interface.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the Java input stream that contains the ASCII parameter value
     * @param length the number of bytes in the stream
     * @throws SQLException if a database access error occurs
     */
    void setAsciiStream(int parameterIndex, InputStream x, int length)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given <code>java.io.InputStream</code> value. It may be
     * more practical to send a very large binary value via a
     * <code>java.io.InputStream</code> rather than as a LONGVARBINARY parameter.
     * The driver will read the data from the stream as needed until it reaches
     * end-of-file.
     * <p/>
     * <b>Note:</b> This stream object can either be a standard Java stream
     * object or your own subclass that implements the standard interface.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the Java input stream that contains the binary parameter value
     * @param length the number of bytes in the stream
     * @throws SQLException if a database access error occurs
     */
    void setBinaryStream(int parameterIndex, InputStream x, int length)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command to the given <code>java.io.InputStream</code> value. It may be
     * more practical to send a very large UNICODE value via a
     * <code>java.io.Reader</code> rather than as a LONGVARCHAR parameter.
     * The driver will read the data from the stream as needed until it reaches
     * end-of-file.
     * <p/>
     * <b>Note:</b> This stream object can either be a standard Java stream
     * object or your own subclass that implements the standard interface.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param reader the Reader object that contains the UNICODE data to be set
     * @param length the number of bytes in the stream
     * @throws SQLException if a database access error occurs
     */
    void setCharacterStream(int parameterIndex, Reader reader, int length)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command with the given Java Object. For integral values, the
     * <code>java.lang</code> equivalent objects should be used (for example, an
     * instance of the class <code>Integer</code> for an <code>int</code>).
     * <p/>
     * The given Java object will be converted to the <code>targetSqlType</code>
     * before being sent to the database.
     * <p/>
     * If the object is of a class implementing SQLData, the rowset should call
     * the method <code>SQLData.writeSQL</code> to write the object to an
     * SQLOutput data stream. If the object is an instance of a class
     * implementing the <code>Ref, Struct, Array, Blob, or Clob</code>
     * interfaces, the driver uses the default mapping to the corresponding SQL
     * type.
     * <p/>
     * Note that this method may be used to pass datatabase-specific abstract
     * data types.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the object containing the input parameter value
     * @param targetSqlType the SQL type (as defined in java.sql.Types) to be
     *                      sent to the database. The scale argument may further
     *                      qualify this type.
     * @param scale for <code>java.sql.Types.DECIMAL</code> or
     *              <code>java.sql.Types.NUMERIC</code> types, this is the
     *              number of digits after the decimal point. For all other
     *              types, this value will be ignored.
     * @throws SQLException if a database access error occurs
     * @see Types
     */
    void setObject(int parameterIndex, Object x, int targetSqlType, int scale)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command with a Java <code>Object</code>. For integral values, the
     * <code>java.lang</code> equivalent objects should be used. This method is
     * like <code>setObject</code> above, but the scale used is the scale of the
     * second parameter. Scalar values have a scale of zero. Literal values have
     * the scale present in the literal.
     * <p/>
     * Even though it is supported, it is not recommended that this method be
     * called with floating point input values.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the object containing the input parameter value
     * @param targetSqlType the SQL type (as defined in java.sql.Types) to be
     *                      sent to the database.
     * @throws SQLException if a database access error occurs
     */
    void setObject(int parameterIndex, Object x, int targetSqlType)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command with a Java Object. For integral values, the
     * <code>java.lang</code> equivalent objects should be used.
     * <p/>
     * The JDBC specification provides a standard mapping from Java Object types
     * to SQL types. The driver will convert the given Java object to its
     * standard SQL mapping before sending it to the database.
     * <p/>
     * Note that this method may be used to pass datatabase-specific abstract
     * data types by using a driver-specific Java type. If the object is of a
     * class implementing SQLData, the rowset should call the method
     * <code>SQLData.writeSQL</code> to write the object to an SQLOutput data
     * stream. If the object is an instance of a class implementing the
     * <code>Ref, Struct, Array, Blob, or Clob</code> interfaces, the driver
     * uses the default mapping to the corresponding SQL type.
     * <p/>
     * An exception is thrown if there is an ambiguity, for example, if the
     * object is of a class implementing more than one of these interfaces.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the object containing the input parameter value
     * @throws SQLException if a database access error occurs
     */
    void setObject(int parameterIndex, Object x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command with the given <code>Blob</code> value. The driver will convert
     * this to the BLOB value that the Blob object represents before sending it
     * to the database.
     *
     * @param i the first parameter is 1, the second is 2, ...
     * @param x an object representing a BLOB
     * @throws SQLException if a database access error occurs
     */
    void setBlob(int i, Blob x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command with the given <code>Clob</code> value. The driver will convert
     * this to the BLOB value that the Clob object represents before sending it
     * to the database.
     *
     * @param i the first parameter is 1, the second is 2, ...
     * @param x an object representing a CLOB
     * @throws SQLException if a database access error occurs
     */
    void setClob(int i, Clob x)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command with the given java.sql.Date value. The driver will convert this
     * to an SQL DATE value, using the given <code>java.util.Calendar</code>
     * object to calculate the date.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @param cal the <code>java.util.Calendar</code> object to use for
     *            calculating the date
     * @throws SQLException if a database access error occurs
     */
    void setDate(int parameterIndex, Date x, Calendar cal)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command with the given java.sql.Time value. The driver will convert this
     * to an SQL TIME value, using the given <code>java.util.Calendar</code>
     * object to calculate the date, before sending it to the database.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @param cal the <code>java.util.Calendar</code> object to use for
     *            calculating the time
     * @throws SQLException if a database access error occurs
     */
    void setTime(int parameterIndex, Time x, Calendar cal)
            throws SQLException;

    /**
     * Sets the designated parameter in this <code>RowSet</code> object's
     * command with the given java.sql.Timestamp value. The driver will convert
     * this to an SQL TIMESTAMP value, using the given
     * <code>java.util.Calendar</code> object to calculate the date, before
     * sending it to the database.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, ...
     * @param x the parameter value
     * @param cal the <code>java.util.Calendar</code> object to use for
     *            calculating the timestamp
     * @throws SQLException if a database access error occurs
     */
    void setTimestamp(int parameterIndex, Timestamp x, Calendar cal)
            throws SQLException;

    /**
     * Clears the parameters set for this <code>RowSet</code> object's command.
     * <p/>
     * In general, parameter values remain in force for repeated use of a
     * <code>RowSet</code> object. Setting a parameter value automatically
     * clears its previous value. However, in some cases it is useful to
     * immediately release the resources used by the current parameter values,
     * which can be done by calling the method <code>clearParameters</code>.
     *
     * @throws SQLException if a database access error occurs
     */
    void clearParameters()
            throws SQLException;

    /**
     * Fills this <code>RowSet</code> object with data.
     * <p/>
     * The <code>execute</code> method may use the following properties to
     * create a connection for reading data: url, data source name, user name,
     * password, transaction isolation, and type map. The execute method may
     * use the following properties to create a statement to execute a command:
     * command, read only, maximum field size, maximum rows, escape processing,
     * and query timeout.
     * <p/>
     * If the required properties have not been set, an exception is thrown. If
     * this method is successful, the current contents of the rowset are
     * discarded and the rowset's metadata is also (re)set. If there are
     * outstanding updates, they are ignored.
     * <p/>
     * If this <code>RowSet</code> object does not maintain a continuous
     * connection with its source of data, it may use a <code>reader</code> (a
     * <code>RowSetReader</code> object) to fill itself with data. In this case,
     * a reader will have been registered with this <code>RowSet</code> object,
     * and the method <code>execute</code> will call on the reader's
     * <code>readData</code> method as part of its implementation.
     *
     * @throws SQLException if a database access error occurs or any of the
     *                      properties necessary for making a connection and
     *                      creating a statement have not been set
     */
    void execute()
            throws SQLException;

    /**
     * Registers the given listener so that it will be notified of events that
     * occur on this <code>RowSet</code> object.
     *
     * @param listener a component that has implemented the
     *                 <code>RowSetListener</code> interface and wants to be
     *                 notified when events occur on this <code>RowSet</code>
     *                 object
     * @see #removeRowSetListener(javax.sql.RowSetListener)
     */
    void addRowSetListener(RowSetListener listener);

    /**
     * Removes the specified listener from the list of components that will be
     * notified when an event occurs on this <code>RowSet</code> object.
     *
     * @param listener a component that has been registered as a listener for
     *                 this <code>RowSet</code> object
     * @see #addRowSetListener(javax.sql.RowSetListener)
     */
    void removeRowSetListener(RowSetListener listener);
}
