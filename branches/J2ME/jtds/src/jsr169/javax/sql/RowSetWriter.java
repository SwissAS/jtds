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
 * An object that implements the <code>RowSetWriter</code> interface, called a
 * <i>writer</i>. A writer may be registered with a <code>RowSet</code> object
 * that supports the reader/writer paradigm.
 * <p/>
 * If a disconnected <code>RowSet</code> object modifies some of its data, and
 * it has a writer associated with it, it may be implemented so that it calls on
 * the writer's <code>writeData</code> method internally to write the updates
 * back to the data source. In order to do this, the writer must first establish
 * a connection with the rowset's data source.
 * <p/>
 * If the data to be updated has already been changed in the data source, there
 * is a conflict, in which case the writer will not write the changes to the
 * data source. The algorithm the writer uses for preventing or limiting
 * conflicts depends entirely on its implementation.
 */
public interface RowSetWriter {

    /**
     * Writes the changes in this <code>RowSetWriter</code> object's rowset back
     * to the data source from which it got its data.
     *
     * @param caller the <code>RowSet</code> object (1) that has implemented the
     *               <code>RowSetInternal</code> interface, (2) with which this
     *               writer is registered, and (3) that called this method
     *               internally
     * @return true if the modified data was written; false if not, which will
     *         be the case if there is a conflict
     * @throws SQLException if a database access error occurs
     */
    boolean writeData(RowSetInternal caller)
            throws SQLException;
}
