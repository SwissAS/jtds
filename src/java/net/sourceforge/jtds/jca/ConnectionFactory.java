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
import java.io.Serializable;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;

import javax.naming.NamingException;
import javax.naming.Reference;
import javax.resource.Referenceable;
import javax.resource.ResourceException;
import javax.resource.spi.ConnectionManager;
import javax.resource.spi.ManagedConnectionFactory;
import javax.sql.DataSource;

import net.sourceforge.jtds.util.Logger;


/** 
 * Implementation of the JCA connection factory. As this is a JDBC connector
 * this class implements the javax.sql.DataSource interface.
 */
public class ConnectionFactory implements DataSource, Referenceable,
        Serializable {
    static final long serialVersionUID = 1297799L;
    
    /** The login timeout. */
    private int loginTimeout;
    /** The managed connection factory for this type of connection. */
    private ManagedConnectionFactoryImpl mcf;
    /** The connection manager used to allocate these connections. */
    private ConnectionManager cxManager;
    /** The JNDI reference allocated by the container. */
    private Reference jndiRef;

    /**
     * Default contructor required by the java beans contract.
     */
    public ConnectionFactory()
    {
        // Default constructor
    }

    /**
     * Construct ConnectionFactory that will return connection handles
     * that implement java.sql.Connection.
     * @param mcf the ManagedConnectionFactory for this type of connection.
     * @param cxManager the connection manager used to allocate connections.
     * @throws ResourceException
     */
    public ConnectionFactory(ManagedConnectionFactory mcf, 
                             ConnectionManager cxManager) throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, null, new Object[]{mcf, cxManager});
        }
        this.mcf = (ManagedConnectionFactoryImpl)mcf;
        this.cxManager  = cxManager; 
    }
    
    /**
     * Obtain a database connection using the default (container) credentials.
     * </p>Calls the connection manager to allocate a connection which
     * will actually be a ConnectionHandle wrapper around a ManagedConnection.
     * @return the allocated connection as a <code>ConnectionHandle</code>.
     * @throws SQLException
     */
    public Connection getConnection() throws SQLException {
        Logger.printMethod(this, "getConnection", null);
        try {
            ConnectionHandle ch = (ConnectionHandle)cxManager.allocateConnection(mcf, null);
            ch.setConnectionManager(this.cxManager);
            return ch;
        } catch (ResourceException e) {
            throw new SQLException(e.getMessage());
        }
    }

    /**
     * Obtain a database connection using the supplied credentials.
     * </p>Calls the connection manager to allocate a connection which
     * will actually be a ConnectionHandle wrapper around a ManagedConnection.
     * @param userName the user name to authenticate with.
     * @param password the password to authenticate with.
     * @return the allocated connection as a <code>ConnectionHandle</code>.
     * @throws SQLException
     */
    public Connection getConnection(String userName, String password)
            throws SQLException {
        if (Logger.isTraceActive()) {
            String ptmp = (password != null)? "****": null;
            Logger.printMethod(this, "getConnection", new Object[]{userName, ptmp}); 
        }
        try {
            ConnectionRequestInfoImpl cri = new ConnectionRequestInfoImpl(userName, password);
            ConnectionHandle ch = (ConnectionHandle)cxManager.allocateConnection(mcf, cri);
            ch.setConnectionManager(this.cxManager);
            return ch;
        } catch (ResourceException e) {
            throw new SQLException(e.getMessage());
        }
    }

    /**
     * Retrieve the log writer.
     * @return the log writer as a <code>PrintWriter</code> or null. 
     * @throws SQLException
     */
    public PrintWriter getLogWriter() throws SQLException {
        try {
            return this.mcf.getLogWriter();
        } catch (ResourceException e) {
            throw new SQLException(e.getMessage());
        }
    }

    /**
     * Set the log writer.
     * @param out the log writer or null to disable logging.
     * @throws SQLException
     */
    public void setLogWriter(PrintWriter out) throws SQLException {
        try {
            this.mcf.setLogWriter(out);
        } catch (ResourceException e) {
            throw new SQLException(e.getMessage());
        }
    }

    /**
     * Set the login timeout for this connection.
     * <p/>This method has no effect as the physical connection has 
     * already been established. Just needed to comply with the
     * contract for javax.sql.DataSource.
     * @param timeout the login timeout value.
     */
    public void setLoginTimeout(int timeout) throws SQLException {
        this.loginTimeout = timeout;
    }

    /**
     * Retreive the login timeout value for this connection.
     * @return the timeout value as an <code>int</code>.
     */
    public int getLoginTimeout() throws SQLException {
        return this.loginTimeout;
    }

    /** 
     * Set the JNDI reference for this ConnectionFactory.
     * @param reference the JNDI reference.
     */
    public void setReference(Reference reference) {
        this.jndiRef = reference;
    }
    
    /**
     * Retrieve the JNDI reference for this ConnectionFactory.
     * @return the JNDI <code>Reference</code>.
     */
    public Reference getReference() throws NamingException {
        return this.jndiRef;
    }

    //// JDBC4.1 demarcation, do NOT put any JDBC3/4.0 code below this line ////

    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public java.util.logging.Logger getParentLogger()
        throws SQLFeatureNotSupportedException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }
}