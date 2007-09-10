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

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Properties;

import javax.resource.ResourceException;
import javax.resource.spi.ConnectionEventListener;
import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.LocalTransaction;
import javax.resource.spi.ManagedConnection;
import javax.resource.spi.ManagedConnectionFactory;
import javax.resource.spi.ManagedConnectionMetaData;
import javax.resource.spi.ResourceAdapterInternalException;
import javax.resource.spi.ResourceAllocationException;
import javax.resource.spi.SecurityException;
import javax.resource.spi.security.PasswordCredential;
import javax.resource.spi.DissociatableManagedConnection;
import javax.security.auth.Subject;
import javax.resource.spi.ConnectionEvent;
import javax.transaction.xa.XAResource;

import net.sourceforge.jtds.jdbc.DataSourceImpl;
import net.sourceforge.jtds.jdbc.Messages;
import net.sourceforge.jtds.jdbc.XAResourceImpl;
import net.sourceforge.jtds.util.Logger;

/**
 * jTDS implementation of the JCA ManagedConnection.
 * </p>This class encapsulates a physical database connection.
 */
public class ManagedConnectionImpl implements ManagedConnection, DissociatableManagedConnection
 {
    
    /** List of connection event listeners subscribing to this connection. */
    private ArrayList<ConnectionEventListener> listeners = new ArrayList<ConnectionEventListener>();
    /** Connection handles currently linked to this managed connection. */
    ArrayList<ConnectionHandle> handles = new ArrayList<ConnectionHandle>();
    /** The parent ManagedConnectionFactory object. */
    ManagedConnectionFactoryImpl mcf;
    /** The credentials specific to this managed connection. */
    PasswordCredential pc;
    /** Cached meta data for this managed connection. */
    ManagedConnectionMetaData metaData;
    /** The physical database connection. */
    Connection con;
    /** The XA connection ID allocated to this connection by the server. */
    int xaConnectionId;
    /** The transaction timeout. */
    int txTimeout;
    /** Flag to indicate that connection remains valid. */
    boolean connectionDestroyed;
    /** XAResource instance for this connection. */
    XAResource xaResource = null;
    /** LocalTransaction instance for this connection. */
    LocalTransaction localTransaction = null;
    /** Log writer instance. */
    private PrintWriter log;
    
    /**
     * Construct a new ManagedConnection.
     * @param mcf the parent ManagedConnectionFactory.
     * @param pc the authentication credentials.
     * @throws ResourceException
     */
    public ManagedConnectionImpl(ManagedConnectionFactoryImpl mcf, 
                                     PasswordCredential pc)
    throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, null, new Object[]{mcf, pc});
        }
        this.mcf = mcf;
        this.pc  = pc;
        this.log = mcf.getLogWriter();
        //
        // Obtain an underlying database connection
        //
        Properties props = new Properties();
        if (pc.getUserName().length() > 0) {
            props.setProperty("USER", pc.getUserName());
        }
        if (pc.getPassword().length > 0) {
            props.setProperty("PASSWORD", new String(this.pc.getPassword()));
        }
        if (mcf.getServerName() != null && mcf.getServerName().length() > 0) {
            props.setProperty("SERVERNAME", mcf.getServerName());
        }
        if (mcf.getPortNumber() != null && mcf.getPortNumber().length() > 0) {
            props.setProperty("PORTNUMBER", mcf.getPortNumber());
        }
        try {
            DataSourceImpl ds = new DataSourceImpl(mcf.getConnectionURL(), props);
            con = ds.getConnection();
        } catch (SQLException e) {
            throw new ResourceAdapterInternalException(e.getMessage());
        }
    }
    
    public Connection getPhysicalConnection()
    {
        return this.con;
    }
    
    /**
     * Check that the connection has not been destroyed.
     * @throws ResourceException
     */
    void checkNotDestroyed() throws ResourceException
    {
        if (connectionDestroyed) {
            throw new javax.resource.spi.IllegalStateException(
                    Messages.get("error.jca.condestroyed"));
        }
    }
    
    /**
     * Adds a connection event listener to the ManagedConnection instance. 
     * </p>The registered ConnectionEventListener instances are notified 
     * of connection close and error events, also of local transaction 
     * related events on the Managed Connection.
     * @param listener the ConnectionEventListener to be registered. 
     */
    public void addConnectionEventListener(ConnectionEventListener listener) {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "addConnectionEventListener", new Object[]{listener});
        }
        if (listener == null) {
            throw new NullPointerException(
                    Messages.get("error.generic.nullparam", 
                                    "addConnectionEventListener"));
        }
        synchronized (listeners) {
            listeners.add(listener);
        }
    }

    /**
     * Removes an already registered connection event listener from the 
     * ManagedConnection instance. 
     * @param listener the ConnectionEventListener to be removed. 
     */
    public void removeConnectionEventListener(ConnectionEventListener listener) {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "removeConnectionEventListener", new Object[]{listener});
        }
        if (listener == null) {
            throw new NullPointerException(
                    Messages.get("error.generic.nullparam", 
                                    "removeConnectionEventListener"));
        }
        synchronized (listeners) {
            listeners.remove(listener);
        }
    }

    /**
     * Fires a new connection event on all listeners.
     *
     * @param handle the originating ConnectionHandle object.
     * @param event the ConnectionEvent constant.
     * @param sqlException the SQLException to pass to the listeners
     */
    public void fireConnectionEvent(Object handle, int event, SQLException sqlException) {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "fireConnectionEvent", 
                    new Object[]{handle, new Integer(event), sqlException});
        }
        //
        // Clone handle array to protect against concurrent modification errors
        //
        ArrayList<ConnectionEventListener> copyList = null;
        synchronized (listeners) {
            if (listeners.size() == 0) {
                return;
            }
            copyList = new ArrayList<ConnectionEventListener>(listeners);
        }
        ConnectionEvent connectionEvent;
        if (event == ConnectionEvent.CONNECTION_CLOSED) {
            connectionEvent = new ConnectionEvent(this, event);
            connectionEvent.setConnectionHandle(handle);
        } else {    
            connectionEvent = new ConnectionEvent(this, event, sqlException);
        }

        Iterator<ConnectionEventListener> iterator = copyList.iterator();

        while (iterator.hasNext()) {
            ConnectionEventListener listener = iterator.next();

            switch (event) {
                case ConnectionEvent.CONNECTION_CLOSED:
                    listener.connectionClosed(connectionEvent);
                    break;
                case ConnectionEvent.CONNECTION_ERROR_OCCURRED:
                    listener.connectionErrorOccurred(connectionEvent);
                    break;
                case ConnectionEvent.LOCAL_TRANSACTION_STARTED:
                    listener.localTransactionStarted(connectionEvent);
                    break;
                case ConnectionEvent.LOCAL_TRANSACTION_COMMITTED:
                    listener.localTransactionCommitted(connectionEvent);
                    break;
                case ConnectionEvent.LOCAL_TRANSACTION_ROLLEDBACK:
                    listener.localTransactionRolledback(connectionEvent);
                    break;
            }
        }
    }
    
    /**
     * Check that this connection is still valid by executing an SQL statement.
     * @return <boolean>true</boolean> if the connection is still valid.
     */
    boolean isValid()
    {
        Statement stmt = null;
        ResultSet rs = null;
        try {
            if (!this.con.isClosed()) {
                stmt = con.createStatement();
                rs = stmt.executeQuery("SELECT 1");
            }
            return true;
        } catch (SQLException e) {
            return false;
        } finally {
            if (rs != null) try {rs.close();} catch (SQLException e) {/* ignore */}
            if (stmt != null) try {stmt.close();} catch (SQLException e) {/* ignore */}
        }
    }

    /**
     * Used by the container to change the association of an application-level 
     * connection handle with a ManagedConneciton instance.
     * </p>The resource adapter is required to implement the associateConnection 
     * method. The method implementation for a ManagedConnection should 
     * dissociate the connection handle (passed as a parameter) from its 
     * currently associated ManagedConnection and associate the new connection 
     * handle with itself. 
     * @param connection the connection handle to associate.
     * @throws ResourceException
     */
    public void associateConnection(Object connection) throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "associateConnection", new Object[]{connection});
        }
        checkNotDestroyed();
        if (connection == null) {
            throw new NullPointerException(
                    Messages.get("error.generic.nullparam", "associateConnection"));
        }
        if (!(connection instanceof ConnectionHandle)) {
            throw new IllegalArgumentException("Foreign ConnectionHandle object supplied");
        }
        ConnectionHandle ch = (ConnectionHandle)connection;
        ManagedConnectionImpl mc = (ManagedConnectionImpl)ch.getManagedConnection();
        if (mc == this) {
            throw new javax.resource.spi.IllegalStateException(
                    Messages.get("error.jca.badassoc"));
        }
        mc.dissociateConnection(ch);
        synchronized (handles) {
            handles.add(ch);
        }
        ch.setManagedConnection(this);
    }
    
    /**
     * This method is called by an application server (that is capable of
     * lazy connection association optimization) in order to dissociate a 
     * ManagedConnection instance from all of its connection handles. 
     * @throws ResourceException
     */
    public void dissociateConnections() throws ResourceException {
        Logger.printMethod(this, "dissociateConnections", null);
        synchronized (handles) {
            for (int i = handles.size() - 1; i >= 0; i--) {
                ConnectionHandle ch = handles.get(i);
                ch.setManagedConnection(null);
            }
            handles.clear();
        }
    }
    
    /**
     * Remove the associatation between a ConnectionHandle and this 
     * ManagedConnection instance.
     * @param ch the connection handle to remove.
     */
    void dissociateConnection(ConnectionHandle ch) {
        synchronized (handles) {
            handles.remove(ch);
        }
        ch.setManagedConnection(null);
    }
    
    /**
     * Application server calls this method to force any cleanup on the 
     * ManagedConnection instance.
     * </p>All connection handles are dissociated from this managed connection.
     * @throws ResourceException
     */
    public void cleanup() throws ResourceException {
        Logger.printMethod(this, "cleanup", null);
        dissociateConnections();
    }

    /**
     * Destroys the physical connection to the underlying resource manager.
     * </p>This causes the underlying database connection to be closed.
     * @throws ResourceException
     */
    public void destroy() throws ResourceException {
        Logger.printMethod(this, "destroy", null);
        checkNotDestroyed();
        cleanup();
        try {
            if (this.xaResource != null) {
                ((XAResourceImpl)this.xaResource).close();
            }
            this.con.close();
        } catch (SQLException e) {
            throw new ResourceException(e.getMessage());
        }
        this.connectionDestroyed = true;
        //
        // Ensure listeners can never be called
        //
        synchronized (listeners) {
            listeners.clear();
        }
    }
    
    /**
     * Creates a new connection handle for the underlying physical connection
     * represented by the ManagedConnection instance.
     * @param subject - security context as JAAS subject
     * @param cxRequestInfo - ConnectionRequestInfo instance
     * @return generic Object instance representing the connection handle. 
     * For jTDS, the connection handle created by a ManagedConnection instance 
     * implements java.sql.Connection and is of type 
     * <code>net.sourceforge.jtds.jca.ConnectionHandle</code>.
     * @throws ResourceException 
     */
    public Object getConnection(Subject subject, ConnectionRequestInfo cxRequestInfo)
            throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "getConnection", new Object[]{subject, cxRequestInfo});
        }
        checkNotDestroyed();
        PasswordCredential pc = this.mcf.getCredentials(this.mcf, subject, cxRequestInfo);
        //
        // Resin does not implement the equals method in their version of 
        // PasswordCredential. Sigh! We will check the username and password individually
        // as this will work with all containers.
        //
        //if (pc != null && !this.pc.equals(pc)) {
        if (pc != null && !(this.pc.getUserName().equals(pc.getUserName()) 
            && Arrays.equals(this.pc.getPassword(),pc.getPassword()))) {
            // This implementation does not support reauthentication as this would involve 
            // closing the underlying connection and then reconnecting with the new
            // credentials.
            throw new SecurityException(
                    Messages.get("error.jca.noreauth"));
        }
        ConnectionHandle ch = new ConnectionHandle(this.mcf, cxRequestInfo);
        ch.setManagedConnection(this);
        synchronized (handles) {
            handles.add(ch);
        }
        return ch;
    }
    
    /**
     * Returns an javax.resource.spi.LocalTransaction instance.
     * @return the <code>LocalTransaction</code> instance.
     * @throws ResourceException
     */
    public LocalTransaction getLocalTransaction() throws ResourceException {
        Logger.printMethod(this, "getLocalTransaction", null);
        if (this.localTransaction == null) {
            this.localTransaction = new LocalTransactionImpl(this, con);
        }
        return this.localTransaction;
    }

    /**
     * Gets the metadata information for this connection's underlying EIS 
     * resource manager instance (ie SQL Server).
     * @return the meta data as a <code>ManagedConnectionMetaData</code> instance.
     * @throws ResourceException 
     */
    public ManagedConnectionMetaData getMetaData() throws ResourceException {
        Logger.printMethod(this, "getMetaData", null);
        try {
            if (this.metaData == null) {
                DatabaseMetaData dbmd = con.getMetaData();
                this.metaData = new ManagedConnectionMetaDataImpl(
                                            dbmd.getDatabaseProductName(),
                                            dbmd.getDatabaseProductVersion(),
                                            this.pc.getUserName());
            }
            return this.metaData;
        } catch (SQLException e) {
            throw new ResourceAdapterInternalException(e.getMessage());
        }
    }
    
    /**
     * Returns an javax.transaction.xa.XAresource instance. 
     * </p>An application server enlists this XAResource instance with the 
     * Transaction Manager if the ManagedConnection instance is being used 
     * in a JTA transaction that is being coordinated by the Transaction Manager. 
     * @return the <code>XAResource</code> Object.
     */
    public XAResource getXAResource() throws ResourceException {
        Logger.printMethod(this, "getXAResource", null);
        try {
            if (this.xaResource == null) {
                this.xaResource = new XAResourceImpl(con);
            }
            return this.xaResource;
        } catch (SQLException e) {
            throw new ResourceAllocationException(
                    Messages.get("error.jca.noxares", e.getMessage()));
        }
    }

    /**
     * Retrieve the log writer.
     * @return the log writer as a <code>PrintWriter</code> or null. 
     */
    public PrintWriter getLogWriter() throws ResourceException {
        return this.log;
    }

    /**
     * Set the log writer.
     * @param out the log writer or null to disable logging.
     */
    public void setLogWriter(PrintWriter out) throws ResourceException {
        this.log = out;
    }
    
    /**
     * Compare the parent ManagedConnectionFactory objects and security
     * credentials to see if they match.
     * @param mcf
     * @param pc the security credentials.
     * @return <boolean>true</code> if the ManagedConnection matches.
     */
    public boolean compare(ManagedConnectionFactory mcf, PasswordCredential pc) {
        if (!this.mcf.equals(mcf)) {
            return false;
        }
        //
        // Code around the fact that Resin does not implement the equals 
        // method in their version of PasswordCredential (once more). 
        //
        return (pc == null || (this.pc.getUserName().equals(pc.getUserName()) 
                && Arrays.equals(this.pc.getPassword(),pc.getPassword())));
    }
}
