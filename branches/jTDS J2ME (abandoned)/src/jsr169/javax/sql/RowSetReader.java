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

import java.sql.SQLException;

/**
 * The facility that a disconnected <code>RowSet</code> object calls on to
 * populate itself with rows of data. A <code>reader</code> (an object
 * implementing the <code>RowSetReader</code> interface) may be registered with
 * a <code>RowSet</code> object that supports the reader/writer paradigm. When
 * the <code>RowSet</code> object's execute method is called, it in turn calls
 * the reader's <code>readData</code> method.
 */
public interface RowSetReader {

    /**
     * Reads the new contents of the calling <code>RowSet</code> object. In
     * order to call this method, a <code>RowSet</code> object must have
     * implemented the <code>RowSetInternal</code> interface and registered this
     * <code>RowSetReader</code> object as its reader. The <code>readData</code>
     * method is invoked internally by the <code>RowSet.execute</code> method
     * for rowsets that support the reader/writer paradigm.
     * <p/>
     * The <code>readData</code> method adds rows to the caller. It can be
     * implemented in a wide variety of ways and can even populate the caller
     * with rows from a nonrelational data source. In general, a reader may
     * invoke any of the rowset's methods, with one exception. Calling the
     * method <code>execute</code> will cause an SQLException to be thrown
     * because execute may not be called recursively. Also, when a reader
     * invokes <code>RowSet</code> methods, no listeners are notified; that is,
     * no <code>RowSetEvent</code> objects are generated and no
     * <code>RowSetListener</code> methods are invoked. This is true because
     * listeners are already being notified by the method <code>execute</code>.
     *
     * @param caller the <code>RowSet</code> object (1) that has implemented the
     *               <code>RowSetInternal</code> interface, (2) with which this
     *               <code>reader</code> is registered, and (3) whose
     *               <code>execute</code> method called this <code>reader</code>
     * @throws SQLException if a database access error occurs or this method
     *                      invokes the <code>RowSet.execute</code> method
     */
    void readData(RowSetInternal caller)
            throws SQLException;
}
