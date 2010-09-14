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
package net.sourceforge.jtds.jca;

import java.sql.Connection;
import java.sql.SQLException;

import javax.resource.ResourceException;
import javax.resource.spi.LocalTransaction;
import javax.resource.spi.LocalTransactionException;
import javax.resource.spi.ResourceAdapterInternalException;
import javax.resource.spi.ConnectionEvent;

import net.sourceforge.jtds.jdbc.Messages;
import net.sourceforge.jtds.util.Logger;

/**
 * jTDS implementation of the LocalTransaction interface.
 */
public class LocalTransactionImpl implements LocalTransaction {

    /** The managed connection. */
    ManagedConnectionImpl mc;
    /** The physical database connection. */
    Connection con;
    /** Flag to indicate in local transaction. */
    boolean[] inLocalTx = new boolean[1];
    
    /**
     * Construct a new LocalTransaction instance.
     * @param connection the physical database connection.
     */
    public LocalTransactionImpl(ManagedConnectionImpl mc, Connection connection) {
        Logger.printMethod(this, null, null);
        this.mc = mc;
        this.con = connection;
        this.inLocalTx[0] = false;        
    }
    
    /**
     * Begin a local transaction.
     * @throws ResourceException
     */
    public void begin() throws ResourceException {
        Logger.printMethod(this, "begin", null);
        try {
            synchronized (inLocalTx) {
                if (inLocalTx[0]) {
                    throw new LocalTransactionException(
                            Messages.get("error.jca.nolocaltx"));
                }
                inLocalTx[0] = true;
            }
            con.setAutoCommit(false);
        } catch (SQLException e) {
            throw new ResourceAdapterInternalException(e.getMessage());
        }
        mc.fireConnectionEvent(null, ConnectionEvent.LOCAL_TRANSACTION_STARTED, null);
    }

    /**
     * Commit a local transaction.
     * @throws ResourceException
     */
    public void commit() throws ResourceException {
        Logger.printMethod(this,"commit", null);
       try {
            synchronized (inLocalTx) {
                if (!inLocalTx[0]) {
                    throw new LocalTransactionException(
                            Messages.get("error.jca.notintx"));
                }
                inLocalTx[0] = false;
            }
            // jTDS setAutoCommit() will commit open transaction as
            // required by the JDBC spec.
            con.setAutoCommit(true);
        } catch (SQLException e) {
            throw new ResourceAdapterInternalException(e.getMessage());
        }
        mc.fireConnectionEvent(null, ConnectionEvent.LOCAL_TRANSACTION_COMMITTED, null);
    }

    /**
     * Rollback a local transaction.
     * @throws ResourceException
     */
    public void rollback() throws ResourceException {
        Logger.printMethod(this, "rollback", null);
        try {
            synchronized (inLocalTx) {
                if (!inLocalTx[0]) {
                    throw new LocalTransactionException(
                            Messages.get("error.jca.notintx"));
                }
                inLocalTx[0] = false;
            }
            con.rollback();
            con.setAutoCommit(true);
        } catch (SQLException e) {
            throw new ResourceAdapterInternalException(e.getMessage());
        }
        mc.fireConnectionEvent(null, ConnectionEvent.LOCAL_TRANSACTION_ROLLEDBACK, null);
    }

}
