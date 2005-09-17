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
 * An exception that provides information on database access warnings. Warnings
 * are silently chained to the object whose method caused it to be reported.
 * <p/>
 * Warnings may be retrieved from <code>Connection, Statement</code>, and
 * <code>ResultSet</code> objects. Trying to retrieve a warning on a connection
 * after it has been closed will cause an exception to be thrown. Similarly,
 * trying to retrieve a warning on a statement after it has been closed or on a
 * result set after it has been closed will cause an exception to be thrown.
 * Note that closing a statement also closes a result set that it might have
 * produced.
 *
 * @see Connection#getWarnings()
 * @see Statement#getWarnings()
 * @see ResultSet#getWarnings()
 */
public class SQLWarning extends SQLException {

    /**
     * Constructs a fully-specified <code>SQLWarning</code> object initialized
     * with the given values.
     *
     * @param reason a description of the warning
     * @param SQLstate an XOPEN code identifying the warning
     * @param vendorCode a database vendor-specific warning code
     */
    public SQLWarning(String reason, String SQLstate, int vendorCode) {
        super(reason, SQLstate, vendorCode);
    }

    /**
     * Constructs an <code>SQLWarning</code> object with the given reason and
     * SQLState; the vendorCode defaults to 0.
     *
     * @param reason a description of the warning
     * @param SQLstate an XOPEN code identifying the warning
     */
    public SQLWarning(String reason, String SQLstate) {
        this(reason, SQLstate, 0);
    }

    /**
     * Constructs an <code>SQLWarning</code> object with the given value for a
     * reason; SQLstate defaults to <code>null</code>, and vendorCode defaults
     * to 0.
     *
     * @param reason a description of the warning
     */
    public SQLWarning(String reason) {
        this(reason, null, 0);
    }

    /**
     * Constructs a default <code>SQLWarning</code> object. The reason defaults
     * to <code>null</code>, SQLState defaults to <code>null</code>, and
     * vendorCode defaults to 0.
     */
    public SQLWarning() {
        this(null, null, 0);
    }

    /**
     * Retrieves the warning chained to this <code>SQLWarning</code> object.
     *
     * @return the next SQLException in the chain; null if none
     * @see #setNextWarning(java.sql.SQLWarning)
     */
    public SQLWarning getNextWarning() {
        Object obj = getNextException();
        if (obj == null) {
            return null;
        }
        if (obj instanceof SQLWarning) {
            return (SQLWarning) obj;
        } else {
            throw new Error("Not a SQLWarning instance");
        }
    }

    /**
     * Adds an <code>SQLWarning</code> object to the end of the chain. 
     *
     * @param w the new end of the SQLException chain
     * @see #getNextWarning()
     */
    public void setNextWarning(SQLWarning w) {
        setNextException(w);
    }
}
