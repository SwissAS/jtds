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

import java.net.URL;
import java.util.Calendar;

/**
 * The interface used to execute SQL stored procedures. The JDBC API provides a
 * stored procedure SQL escape syntax that allows stored procedures to be
 * called in a standard way for all RDBMSs. This escape syntax has one form
 * that includes a result parameter and one that does not. If used, the result
 * parameter must be registered as an OUT parameter. The other parameters can
 * be used for input, output or both. Parameters are referred to sequentially,
 * by number, with the first parameter being 1.
 * <pre>
 *   {?= call &lt;procedure-name&gt;[&lt;arg1&gt;,&lt;arg2&gt;, ...]}
 *   {call &lt;procedure-name&gt;[&lt;arg1&gt;,&lt;arg2&gt;, ...]}
 * </pre>
 * <p/>
 * IN parameter values are set using the <code>set</code> methods inherited
 * from {@link PreparedStatement}.  The type of all OUT parameters must be
 * registered prior to executing the stored procedure; their values are
 * retrieved after execution via the <code>get</code> methods provided here.
 * <p/>
 * A <code>CallableStatement</code> can return one {@link ResultSet} object or
 * multiple <code>ResultSet</code> objects. Multiple <code>ResultSet</code>
 * objects are handled using operations inherited from {@link Statement}.
 * <p/>
 * For maximum portability, a call's <code>ResultSet</code> objects and update
 * counts should be processed prior to getting the values of output parameters.
 *
 * @see Connection#prepareCall(java.lang.String)
 * @see ResultSet
 */
public interface CallableStatement extends PreparedStatement {
    /**
     * Registers the OUT parameter in ordinal position
     * <code>parameterIndex</code> to the JDBC type <code>sqlType</code>.
     * All OUT parameters must be registered before a stored procedure is
     * executed.
     * <p/>
     * The JDBC type specified by <code>sqlType</code> for an OUT parameter
     * determines the Java type that must be used in the <code>get</code>
     * method to read the value of that parameter.
     * <p/>
     * If the JDBC type expected to be returned to this output parameter is
     * specific to this particular database, <code>sqlType</code> should be
     * <code>java.sql.Types.OTHER</code>. The method {@link #getObject(int)}
     * retrieves the value.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @param sqlType        the JDBC type code defined by
     *                       <code>java.sql.Types</code>. If the parameter is
     *                       of JDBC type <code>NUMERIC</code> or
     *                       <code>DECIMAL</code>, the version of
     *                       <code>registerOutParameter</code> that accepts a
     *                       scale value should be used.
     * @throws SQLException if a database access error occurs
     * @see Types
     */
    void registerOutParameter(int parameterIndex, int sqlType)
            throws SQLException;

    /**
     * Registers the parameter in ordinal position <code>parameterIndex</code>
     * to be of JDBC type <code>sqlType</code>. This method must be called
     * before a stored procedure is executed.
     * <p/>
     * The JDBC type specified by <code>sqlType</code> for an OUT parameter
     * determines the Java type that must be used in the <code>get</code>
     * method to read the value of that parameter.
     * <p/>
     * This version of <code>registerOutParameter</code> should be used when
     * the parameter is of JDBC type <code>NUMERIC</code> or
     * <code>DECIMAL</code>.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @param sqlType        the SQL type code defined by
     *                       <code>java.sql.Types</code>
     * @param scale          the desired number of digits to the right of the
     *                       decimal point. It must be greater than or equal to
     *                       zero
     * @throws SQLException if a database access error occurs
     * @see Types
     */
    void registerOutParameter(int parameterIndex, int sqlType, int scale)
            throws SQLException;

    /**
     * Retrieves whether the last OUT parameter read had the value of SQL
     * <code>NULL</code>. Note that this method should be called only after
     * calling a getter method; otherwise, there is no value to use in
     * determining whether it is <code>null</code> or not.
     *
     * @return <code>true</code> if the last parameter read was SQL
     *         <code>NULL</code>; <code>false</code> otherwise
     * @throws SQLException if a database access error occurs
     */
    boolean wasNull() throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>CHAR</code>,
     * <code>VARCHAR</code>, or <code>LONGVARCHAR</code> parameter as a
     * <code>String</code> in the Java programming language.
     * <p/>
     * For the fixed-length type JDBC <code>CHAR</code>, the
     * <code>String</code> object returned has exactly the same value the JDBC
     * <code>CHAR</code> value had in the database, including any padding added
     * by the database.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>null</code>
     * @throws SQLException if a database access error occurs
     * @see #setString(int, String)
     */
    String getString(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>BIT</code> parameter as
     * a <code>boolean</code> in the Java programming language.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>false</code>
     * @throws SQLException if a database access error occurs
     * @see #setBoolean(int, boolean)
     */
    boolean getBoolean(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>TINYINT</code>
     * parameter as a <code>byte</code> in the Java programming language.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>0</code>
     * @throws SQLException if a database access error occurs
     * @see #setByte(int, byte)
     */
    byte getByte(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>SMALLINT</code>
     * parameter as a <code>short</code> in the Java programming language.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>0</code>
     * @throws SQLException if a database access error occurs
     * @see #setShort(int, short)
     */
    short getShort(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>INTEGER</code>
     * parameter as an <code>int</code> in the Java programming language.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>0</code>
     * @throws SQLException if a database access error occurs
     * @see #setInt(int, int)
     */
    int getInt(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>BIGINT</code> parameter
     * as a <code>long</code> in the Java programming language.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>0</code>
     * @throws SQLException if a database access error occurs
     * @see #setLong(int, long)
     */
    long getLong(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>FLOAT</code> parameter
     * as a <code>float</code> in the Java programming language.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>0</code>
     * @throws SQLException if a database access error occurs
     * @see #setFloat(int, float)
     */
    float getFloat(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>DOUBLE</code> parameter
     * as a <code>double</code> in the Java programming language.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>0</code>
     * @throws SQLException if a database access error occurs
     * @see #setDouble(int, double)
     */
    double getDouble(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>BINARY</code> or
     * <code>VARBINARY</code> parameter as an array of <code>byte</code> values
     * in the Java programming language.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>null</code>
     * @throws SQLException if a database access error occurs
     * @see #setBytes(int, byte[])
     */
    byte[] getBytes(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>DATE</code> parameter
     * as a <code>java.sql.Date</code> object.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>null</code>
     * @throws SQLException if a database access error occurs
     * @see #setDate(int, Date)
     */
    Date getDate(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>TIME</code> parameter
     * as a <code>java.sql.Time</code> object.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>null</code>
     * @throws SQLException if a database access error occurs
     * @see #setTime(int, Time)
     */
    Time getTime(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>TIMESTAMP</code>
     * parameter as a <code>java.sql.Timestamp</code> object.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>null</code>
     * @throws SQLException if a database access error occurs
     * @see #setTimestamp(int, Timestamp)
     */
    Timestamp getTimestamp(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated parameter as an
     * <code>Object</code> in the Java programming language. If the value is an
     * SQL <code>NULL</code>, the driver returns a Java <code>null</code>.
     * <p/>
     * This method returns a Java object whose type corresponds to the JDBC
     * type that was registered for this parameter using the method
     * <code>registerOutParameter</code>.  By registering the target JDBC type
     * as <code>java.sql.Types.OTHER</code>, this method can be used to read
     * database-specific abstract data types.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value. If the value is SQL <code>NULL</code>, the
     *         result is <code>null</code>
     * @throws SQLException if a database access error occurs
     * @see Types
     * @see #setObject(int, Object, int, int)
     */
    Object getObject(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>BLOB</code> parameter
     * as a {@link Blob} object in the Java programming language.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value as a <code>Blob</code> object in the Java
     *         programming language. If the value was SQL <code>NULL</code>,
     *         the value <code>null</code> is returned
     * @throws SQLException if a database access error occurs
     */
    Blob getBlob(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>CLOB</code> parameter
     * as a {@link Clob} object in the Java programming language.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @return the parameter value as a <code>Clob</code> object in the Java
     *         programming language. If the value was SQL <code>NULL</code>,
     *         the value <code>null</code> is returned
     * @throws SQLException if a database access error occurs
     */
    Clob getClob(int parameterIndex) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>DATE</code> parameter
     * as a <code>java.sql.Date</code> object, using the given
     * <code>Calendar</code> object to construct the date. With a
     * <code>Calendar</code> object, the driver can calculate the date taking
     * into account a custom timezone and locale. If no <code>Calendar</code>
     * object is specified, the driver uses the default timezone and locale.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @param cal            the <code>Calendar</code> object the driver will
     *                       use to construct the date
     * @return the parameter value.  If the value is SQL <code>NULL</code>, the
     *         result is <code>null</code>
     * @throws SQLException if a database access error occurs
     * @see #setDate(int, Date, java.util.Calendar)
     */
    Date getDate(int parameterIndex, Calendar cal) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>TIME</code> parameter
     * as a <code>java.sql.Time</code> object, using the given
     * <code>Calendar</code> object to construct the time. With a
     * <code>Calendar</code> object, the driver can calculate the time taking
     * into account a custom timezone and locale. If no <code>Calendar</code>
     * object is specified, the driver uses the default timezone and locale.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @param cal            the <code>Calendar</code> object the driver will
     *                       use to construct the time
     * @return the parameter value.  If the value is SQL <code>NULL</code>, the
     *         result is <code>null</code>
     * @throws SQLException if a database access error occurs
     * @see #setTime(int, Time, java.util.Calendar)
     */
    Time getTime(int parameterIndex, Calendar cal) throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>TIMESTAMP</code>
     * parameter as a <code>java.sql.Timestamp</code> object, using the given
     * <code>Calendar</code> object to construct the <code>Timestamp</code>
     * object. With a <code>Calendar</code> object, the driver can calculate
     * the timestamp taking into account a custom timezone and locale. If no
     * <code>Calendar</code> object is specified, the driver uses the default
     * timezone and locale.
     *
     * @param parameterIndex the first parameter is 1, the second is 2, and so
     *                       on
     * @param cal            the <code>Calendar</code> object the driver will
     *                       use to construct the timestamp
     * @return the parameter value.  If the value is SQL <code>NULL</code>, the
     *         result is <code>null</code>
     * @throws SQLException if a database access error occurs
     * @see #setTimestamp(int, Timestamp, java.util.Calendar)
     */
    Timestamp getTimestamp(int parameterIndex, Calendar cal)
            throws SQLException;

    /**
     * Registers the OUT parameter in ordinal position
     * <code>parameterIndex</code> to the JDBC type <code>sqlType</code>. All
     * OUT parameters must be registered before a stored procedure is executed.
     * The JDBC type specified by <code>sqlType</code> for an OUT parameter
     * determines the Java type that must be used in the method getXXX to read
     * the value of that parameter. If the JDBC type expected to be returned to
     * this output parameters is specified to this particular database,
     * <code>sqlType</code> should be <code>java.sql.Types.OTHER</code>. The
     * method <code>CallableStatement.getObject</code> will retrieve the value.
     * <p/>
     * <b>Notes:</b> When reading the value of an out parameter, you must use
     * the getter method whose Java type corresponds to the parameter's
     * registered SQL type.
     *
     * @param parameterIndex the first parameter is 1, the second 2,...
     * @param sqlType        a value from {@link Types}
     * @param typeName       the fully-qualified name of a SQL structured type
     * @throws SQLException  if a database access error occurs
     * @see Types
     */
    void registerOutParameter(int parameterIndex, int sqlType, String typeName)
            throws SQLException;

    /**
     * Retrieves the value of the designated JDBC <code>DATALINK</code>
     * parameter as a <code>java.net.URL</code> object.
     *
     * @param parameterIndex the first parameter is 1, the second is 2,...
     * @return a <code>java.net.URL</code> object that represents the JDBC
     *         <code>DATALINK</code> value used as the designated parameter
     * @throws SQLException if a database access error occurs, or if the URL
     *                      being returned is not a valid URL on the Java
     *                      platform
     * @see #setURL(int, java.net.URL)
     */
    URL getURL(int parameterIndex) throws SQLException;
}
