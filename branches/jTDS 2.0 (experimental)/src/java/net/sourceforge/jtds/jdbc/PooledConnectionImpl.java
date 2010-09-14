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

import java.sql.*;
import java.util.*;
import javax.sql.*;

import net.sourceforge.jtds.util.Logger;

/**
 * jTDS implementation of the <code>PooledConnection</code> interface.
 *
 * @version $Id: PooledConnectionImpl.java,v 1.3 2009-09-27 12:59:02 ickzon Exp $
 */
public class PooledConnectionImpl implements javax.sql.PooledConnection {
    /** The list of ConnectionEventListeners registered with this connection. */
    private ArrayList<ConnectionEventListener> listeners = new ArrayList<ConnectionEventListener>();
    /** The underlying JDBC connection object. */
    protected Connection connection;
    /** The InvocationHandler for the Connection interface. */
    protected ConnectionWrapper connectionWrapper;
    /**
     * Construct a new pooled connection.
     * @param connection the JDBC connection instance.
     */
    PooledConnectionImpl(final Connection connection) {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, null, new Object[]{connection});
        }
        this.connection = connection;
    }

    Connection getRealConnection()
    {
        return this.connection;
    }
    
    /**
     * Fires a new connection event on all listeners.
     *
     * @param closed true if the connection is closed.
     * @param sqlException the SQLException to pass to the listeners
     */
    void fireConnectionEvent(boolean closed, SQLException sqlException) {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "fireConnectionEvent", new Object[]{new Boolean(closed), sqlException});
        }
        ConnectionEventListener list[] = null;
        synchronized (listeners) {
            if (listeners.size() > 0) {
                list = listeners.toArray(new ConnectionEventListener[listeners.size()]);
            }
        }
        if (list != null) {
            ConnectionEvent connectionEvent = new ConnectionEvent(this, sqlException);
            for (int i = 0; i < list.length; i++) {
                if (closed) {
                    list[i].connectionClosed(connectionEvent);
                } else {
                    try {
                        if (connection == null || connection.isClosed()) {
                            list[i].connectionErrorOccurred(connectionEvent);
                        }
                    } catch (SQLException ex) {
                        // Will never occur
                    }
                }
            }
        }
    }

    //
    // ------ methods from javax.sql.PooledConnection -----
    //
    
    /**
     * Adds the specified listener to the list.
     * @param listener the event listener to add.
     * @see #fireConnectionEvent
     * @see #removeConnectionEventListener
     */
    public void addConnectionEventListener(ConnectionEventListener listener) {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "addConnectionEventListener", new Object[]{listener});
        }
        synchronized (listener) {
            listeners.add(listener);
        }
    }

    /**
     * Closes the database connection.
     *
     * @throws SQLException if an error occurs
     */
    public void close() throws SQLException {
        Logger.printMethod(this, "close", null);
        if (connectionWrapper != null) {
            //
            // Client still has a connection handle in use
            //
            try {
                if (!((ConnectionImpl)connection).isXaTransaction() && 
                    !connection.getAutoCommit()) 
                {
                    connection.rollback();
                }
            } catch (SQLException e) {
                // Ignore
            }
        }
        if (connection != null) {
            try {
                connection.close();
            } finally {
                connection = null; // Garbage collect the connection
            }
        }
    }


    /**
     * Get a proxy connection wrapping the real JDBC Connection.
     * @return the wrapped connection as a <code>java.lang.reflect.Proxy</code>.
     * @throws SQLException if an error occurs
     */
    public Connection getConnection() throws SQLException {
        Logger.printMethod(this, "getConnection", null);
        //
        // Trap attempt to obtain a connection after it has been closed.
        //
        if (connection == null) {
            SQLException ex = 
                new SQLException(Messages.get("error.jdbcx.conclosed"), "08003");
            fireConnectionEvent(false, ex);
            throw ex;
        }
        if (connectionWrapper != null) {
            // JDBC standard states that any existing connection will
            // be closed even if the application has not already done so.
            // This allows the pooling software to reclaim a connection.
            try {
                if (!((ConnectionImpl)connection).isXaTransaction() && 
                    !connection.getAutoCommit()) 
                {
                    connection.rollback();
                }
            } catch (SQLException e) {
                // Ignore any Exceptions on underlying connection;
            }
        }
        try {
            //
            // JDBC standard says that the connection should be initialised to
            // a known state.
            //
            connection.setAutoCommit(true);
            if (connection.getTransactionIsolation() != Connection.TRANSACTION_READ_COMMITTED) {
                connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            }
            connection.clearWarnings();
            return new ConnectionWrapper(this, connection);
            
        } catch (SQLException ex) {
            fireConnectionEvent(false, ex);
            throw ex;
        }
    }

    /**
     * Removes the specified listener from the list.
     * @param listener the event listener to remove.
     * @see #addConnectionEventListener
     * @see #fireConnectionEvent
     */
    public void removeConnectionEventListener(ConnectionEventListener listener) {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "removeConnectionEventListener", new Object[]{listener});
        }
        synchronized (listener) {
            listeners.remove(listener);
        }
    }

    @Override
    public void addStatementEventListener(StatementEventListener listener) {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void removeStatementEventListener(StatementEventListener listener) {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }
}
