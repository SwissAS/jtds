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
 * An exception that provides information on a database access error or other
 * errors.
 * <p/>
 * Each SQLException provides several kinds of information:
 * <ul><li>a string describing the error. This is used as the Java Exception
 *         message, available via the method <code>getMesage</code>.</li>
 * <li>a "SQLstate" string, which follows either the XOPEN SQLstate conventions
 *     or the SQL 99 conventions. The values of the SQLState string are
 *     described in the appropriate spec. The <code>DatabaseMetaData</code>
 *     method <code>getSQLStateType</code> can be used to discover whether the
 *     driver returns the XOPEN type or the SQL 99 type.</li>
 * <li>an integer error code that is specific to each vendor. Normally this will
 *     be the actual error code returned by the underlying database.</li>
 * <li>a chain to a <code>next Exception</code>. This can be used to provide
 *     additional error information.</li>
 * </ul>
 */
public class SQLException extends Exception {

    private String SQLState;
    private int vendorCode;
    private SQLException next;

    /**
     * Constructs an SQLException object; the reason field defaults to
     * <code>null</code>, the SQLState field defaults to null, and the
     * vendorCode field defaults to 0.
     */
    public SQLException() {
        this(null, null, 0);
    }

    /**
     * Constructs an SQLException object with a reason; the SQLState field
     * defaults to <code>null</code>, and the vendorCode field defaults to 0.
     *
     * @param reason a description of the exception
     */
    public SQLException(String reason) {
        this(reason, null, 0);
    }

    /**
     * Constructs an SQLException object with the given reason and SQLState;
     * the vendorCode field defaults to 0.
     *
     * @param reason a description of the exception
     * @param SQLState an XOPEN or SQL 99 code identifying the exception
     */
    public SQLException(String reason, String SQLState) {
        this(reason, SQLState, 0);
    }

    /**
     * Constructs a fully-specified SQLException object.
     *
     * @param reason a description of the exception
     * @param SQLState an XOPEN or SQL 99 code identifying the exception
     * @param vendorCode a database vendor-specific exception code
     */
    public SQLException(String reason, String SQLState, int vendorCode) {
        super(reason);
        this.SQLState = SQLState;
        this.vendorCode = vendorCode;
        next = null;
    }

    /**
     * Retrieves the SQLState for this <code>SQLException</code> object.
     *
     * @return the SQLState value
     */
    public String getSQLState() {
        return SQLState;
    }

    /**
     * Retrieves the vendor-specific exception code for this
     * <code>SQLException</code> object.
     *
     * @return the vendor's error code
     */
    public int getErrorCode() {
        return vendorCode;
    }

    /**
     * Retrieves the exception chained to this <code>SQLException</code> object.
     *
     * @return the next <code>SQLException</code> object in the chain; null if
     *         there are none
     * @see #setNextException(java.sql.SQLException)
     */
    public SQLException getNextException() {
        return next;
    }

    /**
     * Adds an <code>SQLException</code> object to the end of the chain.
     *
     * @param ex the new exception that will be added to the end of the
     *        SQLException chain
     * @see #getNextException()
     */
    public synchronized void setNextException(SQLException ex) {
        SQLException tail = null;
        for (tail = this; tail.next != null; tail = tail.next) {
            ;
        }
        tail.next = ex;
    }
}
