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

import javax.transaction.xa.XAException;
import javax.transaction.xa.XAResource;
import javax.transaction.xa.Xid;

/**
 * jTDS implementation of the XAResource interface.
 *
 * @version $Id: XAResourceImpl.java,v 1.1 2007-09-10 19:19:31 bheineman Exp $
 */
public class XAResourceImpl implements XAResource {
    /** The connection to be enlisted in an XA transaction. */
    private final ConnectionImpl connection;
    /** The XA transaction timeout. */
    private int   timeout = ConnectionImpl.DEFAULT_XA_TIMEOUT;
    
    /**
     * Construct a XAResource object.
     * @param connection the underlying database connection.
     * @throws SQLException
     */
    public XAResourceImpl(final Connection connection)throws SQLException {
        this.connection = (ConnectionImpl)connection;
        this.connection.xa_open();
    }

    ConnectionImpl getConnection()
    {
        return connection;
    }

    public void close()
    {
        try {
            connection.xa_close();
        } catch (SQLException e) {
            // Ignore close errors
        }
        
    }
    
    //
    // ------------------- javax.transaction.xa.XAResource interface methods -------------------
    //
    public int getTransactionTimeout() throws XAException {
        return this.timeout;
    }

    public boolean setTransactionTimeout(int timeout) throws XAException {
        this.timeout = (timeout < 1)? ConnectionImpl.DEFAULT_XA_TIMEOUT: timeout;
        return true;
    }

    public boolean isSameRM(XAResource xares) throws XAException {
        return connection.isSameRM(xares);
    }

    public Xid[] recover(int flags) throws XAException {
        return connection.xa_recover(flags);
    }

    public int prepare(Xid xid) throws XAException {
        return connection.xa_prepare(xid);
    }

    public void forget(Xid xid) throws XAException {
        connection.xa_forget(xid);
    }

    public void rollback(Xid xid) throws XAException {
        connection.xa_rollback(xid);
    }

    public void end(Xid xid, int flags) throws XAException {
        connection.xa_end(xid, flags);
    }

    public void start(Xid xid, int flags) throws XAException {
        connection.xa_start(xid, flags, timeout);
    }

    public void commit(Xid xid, boolean commit) throws XAException {
        connection.xa_commit(xid, commit);
    }
}
