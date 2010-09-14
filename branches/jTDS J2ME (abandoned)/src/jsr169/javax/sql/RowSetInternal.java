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

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * The interface that a <code>RowSet</code> object implements in order to
 * present itself to a <code>RowSetReader</code> or <code>RowSetWriter</code>
 * object. The <code>RowSetInternal</code> interface contains methods that let
 * the reader or writer access and modify the internal state of the rowset.
 */
public interface RowSetInternal {

    /**
     * Retrieves the parameters that have been set for this <code>RowSet</code>
     * object's command.
     *
     * @return an array of the current parameter values for this
     *         <code>RowSet</code> object's command
     * @throws SQLException if a database access error occurs
     */
    Object[] getParams()
            throws SQLException;

    /**
     * Retrieves the <code>Connection</code> object that was passed to this
     * <code>RowSet</code> object.
     *
     * @return the <code>Connection</code> object passed to the rowset or
     *         null if none was passed
     * @throws SQLException if a database access error occurs
     */
    Connection getConnection()
            throws SQLException;

    /**
     * Sets the given <code>RowSetMetaData</code> object as the
     * <code>RowSetMetaData</code> object for this <code>RowSet</code> object.
     * The <code>RowSetReader</code> object associated with the rowset will use
     * <code>RowSetMetaData</code> methods to set the values giving information
     * about the rowset's columns.
     *
     * @param md the <code>RowSetMetaData</code> object that will be set with
     *           information about the rowset's columns
     * @throws SQLException if a database access error occurs
     */
    void setMetaData(RowSetMetaData md)
            throws SQLException;

    /**
     * Retrieves a <code>ResultSet</code> object containing the original value
     * of this <code>RowSet</code> object.
     * <p/>
     * The cursor is positioned before the first row in the result set. Only
     * rows contained in the result set returned by the method getOriginal are
     * said to have an original value.
     *
     * @return the original value of the rowset
     * @throws SQLException if a database access error occurs
     */
    ResultSet getOriginal()
            throws SQLException;

    /**
     * Retrieves a <code>ResultSet</code> object containing the original value
     * of the current row only. If the current row has no original value, an
     * empty result set is returned. If there is no current row, an exception is
     * thrown.
     *
     * @return the original value of the current row as a <code>ResultSet</code>
     *         object
     * @throws SQLException if a database access error occurs or this method is
     *                      called while the cursor is on the insert row, before
     *                      the first row, or after the last row
     */
    ResultSet getOriginalRow()
            throws SQLException;
}
