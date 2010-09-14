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

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
/**
 * A factory for connections to the physical data source that this
 * <code>DataSource</code> object represents. A replacement for the
 * <code>DriverManager</code> facility, a <code>DataSource</code> object is the
 * preferred means of getting a connection.
 * <p/>
 * The <code>DataSource</code> interface is implemented by a driver vendor.
 * <p/>
 * A <code>DataSource</code> object has properties that can be modified when
 * necessary. For example, if the data source is moved to a different server,
 * the property for the server can be changed. The benefit is that because the
 * data source's properties can be changed, any code accessing that data source
 * does not need to be changed.
 * <p/>
 * An instance of a <code>DataSource</code> object can be used in a stand alone
 * program to create <code>Connection</code> objects. In the following example
 * an instance of <code>DataSource</code>, in this case,
 * <code>VendorDataSource</code> is used to create a <code>Connection</code> to
 * a database on the machine bookserver which is listening at port 12345:
 * <pre> VendorDataSource vds = new VendorDataSource();
 *       vds.setServerName("bookserver");
 *       vds.setPortNumber(12345);
 *       Connection conn = vds.getConnection("Bob", "passwd");</pre>
 * A list of standard properties is provided in seciton 9.3.1 of the JDBC 3.0
 * specification. Consult your vendors documentation for a list the supported
 * properties for you <code>DataSource</code>.
 *
 * @see Connection
 */
public interface DataSource {

    /**
     * Attempts to establish a connection with the data source that this
     * <code>DataSource</code> object represents.
     *
     * @return a connection to the data source
     * @throws SQLException if a database access error occurs
     */
    Connection getConnection()
            throws SQLException;

    /**
     * Attempts to establish a connection with the data source that this
     * <code>DataSource</code> object represents.
     *
     * @param username the database user on whose behalf the connection is
     *                 being made
     * @param password the user's password
     * @return a connection to the data source
     * @throws SQLException if a database access error occurs
     */
    Connection getConnection(String username, String password)
            throws SQLException;

    /**
     * Retrieves the log writer for this <code>DataSource</code> object.
     * <p/>
     * The log writer is a character output stream to which all logging and
     * tracing messages for this data source will be printed. This includes
     * messages printed by the methods of this object, messages printed by
     * methods of other objects manufactured by this object, and so on. Messages
     * printed to a data source specific log writer are not printed to the log
     * writer associated with the <code>java.sql.Drivermanager</code> class.
     * When a <code>DataSource</code> object is created, the log writer is
     * initially null; in other words, the default is for logging to be disabled.
     *
     * @return the log writer for this data source or null if logging is
     *         disabled
     * @throws SQLException if a database access error occurs
     * @see #setLogWriter(java.io.PrintWriter)
     */
    PrintWriter getLogWriter()
            throws SQLException;

    /**
     * Sets the log writer for this <code>DataSource</code> object to the given
     * <code>java.io.PrintWriter</code> object.
     * <p/>
     * The log writer is a character output stream to which all logging and
     * tracing messages for this data source will be printed. This includes
     * messages printed by the methods of this object, messages printed by
     * methods of other objects manufactured by this object, and so on. Messages
     * printed to a data source- specific log writer are not printed to the log
     * writer associated with the <code>java.sql.Drivermanager</code> class.
     * When a <code>DataSource</code> object is created the log writer is
     * initially null; in other words, the default is for logging to be disabled.
     *
     * @param out the new log writer; to disable logging, set to null
     * @throws SQLException if a database access error occurs
     * @see #getLogWriter()
     */
    void setLogWriter(PrintWriter out)
            throws SQLException;

    /**
     * Sets the maximum time in seconds that this data source will wait while
     * attempting to connect to a database. A value of zero specifies that the
     * timeout is the default system timeout if there is one; otherwise, it
     * specifies that there is no timeout. When a <code>DataSource</code> object
     * is created, the login timeout is initially zero.
     *
     * @param seconds the data source login time limit
     * @throws SQLException if a database access error occurs.
     * @see #getLoginTimeout()
     */
    void setLoginTimeout(int seconds)
            throws SQLException;

    /**
     * Gets the maximum time in seconds that this data source can wait while
     * attempting to connect to a database. A value of zero means that the
     * timeout is the default system timeout if there is one; otherwise, it
     * means that there is no timeout. When a <code>DataSource</code> object is
     * created, the login timeout is initially zero.
     *
     * @return the data source login time limit
     * @throws SQLException if a database access error occurs.
     * @see #setLoginTimeout(int)
     */
    int getLoginTimeout()
            throws SQLException;
}
