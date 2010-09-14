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

import java.sql.SQLException;

import javax.resource.ResourceException;
import javax.resource.spi.ConnectionEvent;
import javax.resource.spi.ManagedConnection;
import javax.resource.spi.ManagedConnectionFactory;
import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.ConnectionManager;
import javax.resource.spi.LazyAssociatableConnectionManager;


import net.sourceforge.jtds.jdbc.ConnectionWrapper;
import net.sourceforge.jtds.jdbc.Messages;
import net.sourceforge.jtds.util.Logger;

/**
 * This class implements a wrapper for the java.sql.Connection instance.
 * The jTDS ConnectionWrapper super class provides the bulk of the logic.
 */
public class ConnectionHandle extends ConnectionWrapper {
    /** The current ManagedConnection associated with this handle. */
    private ManagedConnectionImpl    mc;
    /** The current ManagedConnectionFactory associated with this handle. */
    private ManagedConnectionFactory mcf;
    /** The credentials used to create this connection. */
    private ConnectionRequestInfo    cri;
    /** The Connection manager used to create this connection. */
    private ConnectionManager        cxm;

    /**
     * Construct a connection handle.
     * @param mcf the ManagedConnectionFactory used to create this connection.
     * @param cri the ConnectionRequestInfo used to authenticate this connection.
     */
    ConnectionHandle(ManagedConnectionFactory mcf, ConnectionRequestInfo cri) {
        super(null, null);
        this.mcf = mcf;
        this.cri = cri;
    }
    
    /**
     * Validates the connection state and may also lazily associate with
     * a <code>ManagedConnection</code> if a 
     * <code>LazyAssociatableConnectionManager</code> is available.
     */
    protected void checkOpen() throws SQLException {
        if (this.closed) {
            throw new SQLException(Messages.get("error.conproxy.noconn"), "HY010");
        }
        if (this.mc == null) {
            SQLException sqle = null;
            // Not currently associated with a managed connection see if we have
            // an instance of a LazyAssociatableConnectionManager to hand and 
            // try and reassociate connection with a managed connection.
            if (cxm instanceof LazyAssociatableConnectionManager) {
                Logger.printTrace("Lazy association with MC being attempted");
                try {
                    ((LazyAssociatableConnectionManager)cxm).associateConnection(this, this.mcf, this.cri);
                } catch (ResourceException e) {
                    if (e.getCause() instanceof SQLException) {
                        sqle = (SQLException)e.getCause();
                    } else {
                        sqle = new SQLException(Messages.get("error.jca.lazyfail"), "HY010");
                        sqle.initCause(e);
                    }
                }
                if (this.mc == null) {
                    sqle = new SQLException(Messages.get("error.jca.lazyfail"), "HY010");
                }
            }
            if (sqle != null) {
                throw sqle;
            }
        }
    }

    /**
     * Processes SQLExceptions.
     * </p>Only serious exceptions that threaten the viability of the underlying
     * database connection are forwarded to the connection listeners. 
     * All exceptions are rethrown for the application to handle.
     * @param sqlException the exception to be reported.
     * @throws the original exception rethrown. 
     */
    protected void processSQLException(SQLException sqlException) throws SQLException {
        if (this.con.isClosed()) {
            // Serious error the connection is now unusable
            this.mc.fireConnectionEvent(this, ConnectionEvent.CONNECTION_ERROR_OCCURRED, sqlException);
        }
        throw sqlException;
    }    

    /**
     * Retrieve the ManagedConnection associated with this handle.
     * @return the <code>ManagedConnection</code>.
     */
    ManagedConnection getManagedConnection()
    {
        return this.mc;
    }

    /**
     * Set the ManagedConnection for this handle.
     * @param mc the ManagedConnection to associate with this handle.
     */
    void setManagedConnection(ManagedConnection mc) {
        this.mc  = (ManagedConnectionImpl)mc;
        this.con = (mc == null)? null: ((ManagedConnectionImpl)mc).getPhysicalConnection();
    }

    /**
     * Retrieve the ConnectionManager used to create this connection.
     * @return the <code>javax.resource.spi.ConnectionManager<code> used to create 
     * this connection. 
     */
    ConnectionManager getConnectionManager() {
        return this.cxm;
    }
    
    /**
     * Set the ConnectionManager used to create this connection.
     * @param cxm the ConnectionManager used to create the connection.
     */
    void setConnectionManager(ConnectionManager cxm) {
        this.cxm = cxm;
    }
    
    /**
     * Delgates calls to the connection; SQLExceptions thrown from the connection
     * will cause an event to be fired on the connection pool listeners.
     */
    public void close() {
        Logger.printMethod(this, "close", null);
        if (this.closed) {
            return;
        }
        if (this.mc != null) {
            this.mc.fireConnectionEvent(this, ConnectionEvent.CONNECTION_CLOSED, null);
        }
        this.closed = true;
    }

}
