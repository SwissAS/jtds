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

import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.XAConnection;
import javax.transaction.xa.XAResource;

/**
 * jTDS implementation of the <code>XAConnection</code> interface.
 *
 * @version $Id: XAConnectionImpl.java,v 1.1 2007-09-10 19:19:31 bheineman Exp $
 */
public class XAConnectionImpl extends PooledConnectionImpl implements XAConnection {
    /** The XAResource used by the transaction manager to control this connection.*/
    private XAResourceImpl resource = null;

    /**
     * Construct a new <code>XAConnection</code> object.
     *
     * @param connection the real database connection
     */
    XAConnectionImpl(final Connection connection)
    throws SQLException {
        super(connection);
    }

    //
    // --------------- javax.sql.XAConnection interface methods -------------
    //
    public XAResource getXAResource() throws SQLException {
        if (resource == null) {
            resource = new XAResourceImpl(connection);
        }
        return resource;
    }

    public synchronized void close() throws SQLException {
        if (resource != null) {
            resource.close();
            resource = null;
        }
        super.close();
    }
}
