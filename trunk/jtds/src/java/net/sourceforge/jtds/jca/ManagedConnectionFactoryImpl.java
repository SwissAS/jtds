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
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.Properties;
import java.sql.SQLException;

import javax.resource.ResourceException;
import javax.resource.spi.ConnectionManager;
import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.ManagedConnection;
import javax.resource.spi.ManagedConnectionFactory;
import javax.resource.spi.ResourceAdapter;
import javax.resource.spi.ResourceAdapterAssociation;
import javax.resource.spi.ValidatingManagedConnectionFactory;
import javax.resource.spi.security.PasswordCredential;
import javax.security.auth.Subject;

import net.sourceforge.jtds.jdbc.DataSourceImpl;
import net.sourceforge.jtds.jdbc.Messages;
import net.sourceforge.jtds.util.Logger;

/**
 * A ManagedConnectionFactory instance is a factory of 
 * ManagedConnection objects which, in the context of jTDS,
 * will be physical database connections.
 */
public class ManagedConnectionFactoryImpl implements 
                ManagedConnectionFactory,
                ResourceAdapterAssociation, 
                ValidatingManagedConnectionFactory                                                
    {
    static final long serialVersionUID = 78997987L;
    // Standard connector properties used to configure the driver
    /** The EIS server name. */
    String serverName;
    /** The EIS port number. */
    String portNumber;
    /** The user name to authenticate with. */
    String userName;
    /** The password to authenticate with. */
    String password;
    /** The JDBC connection URL. */
    String connectionURL;
    /** Log writer instance.*/
    private PrintWriter log;
    /** Resource adapter instance. */
    ResourceAdapter ra;
    
    /**
     * Default no argument constructor to satisfy java bean 
     * requirements.
     */
    public ManagedConnectionFactoryImpl()
    {
        Logger.printMethod(this, null, null);
    }
    
    /**
     * Creates a Connection Factory instance using a default ConnectionManager
     * provided by this resource adapter.
     * @return the <code>DataSourceConnectionFactory</code> object. 
     * @throws ResourceException
     */
    public Object createConnectionFactory() throws ResourceException {
        Logger.printMethod(this, "createConnectionFactory", null);
        return createConnectionFactory(new ConnectionManagerImpl());
    }

    /**
     * Creates a Connection Factory instance using a ConnectionManager
     * provided by the application server.
     * @param cxManager the connection manager.
     * @return the <code>DataSourceConnectionFactory</code> object. 
     * @throws ResourceException
     */
    public Object createConnectionFactory(ConnectionManager cxManager)
            throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "createConnectionFactory", new Object[]{toString()});
        }
        ConnectionFactory cf = new ConnectionFactory(this, cxManager);
        return cf;
    }
    
    /**
     * Creates a new physical database connection.
     * @param subject the security information provided by the application server.
     * @param cxRequestInfo the resource adapter specific connection info.
     * @return the managed connection instance as a <code>ManagedConnectionImpl</code>.
     * @throws ResourceException
     */
    public ManagedConnection createManagedConnection(Subject subject,
            ConnectionRequestInfo cxRequestInfo) throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "createManagedConnection", new Object[]{subject, cxRequestInfo});
        }
        if (cxRequestInfo != null && !(cxRequestInfo instanceof ConnectionRequestInfoImpl)) {
            // Called with a foreign request info object
            throw new IllegalArgumentException(Messages.get("error.jca.badcxreqinfo"));
        }
        PasswordCredential pc = getCredentials(this, subject, cxRequestInfo);
        return new ManagedConnectionImpl(this, pc);
    }
  
    /**
     * Returns a matched connection from the candidate set of connections. 
     * </p>This method is used by application servers to manage connection pools.
     * @param connectionSet the set of connections to scan for a matching connection.
     * @param subject the credentials.
     * @param cxRequestInfo the alternative credential set in the request info object.
     * @return the <code>ManagedConnection</code> that matches the credentials or null.
     * @throws ResourceException
     */
    public ManagedConnection matchManagedConnections(Set connectionSet, Subject subject,
            ConnectionRequestInfo cxRequestInfo) throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "matchManagedConnections", 
                    new Object[]{connectionSet, subject, cxRequestInfo});
        }
        if (cxRequestInfo != null 
            && !(cxRequestInfo instanceof ConnectionRequestInfoImpl)) {
            // We are not being called with our own request info 
            // by definition nothing matches.
            return null;
        }
        PasswordCredential pc = getCredentials(this, subject, cxRequestInfo);
        //
        // Scan set of connections provided by AS looking for a match.
        //
        Iterator i = connectionSet.iterator();
        while (i.hasNext()) {
            ManagedConnection mc = (ManagedConnection) i.next();
            if (mc instanceof ManagedConnectionImpl) {
                // OK we have one of our managed connection to test
                if (((ManagedConnectionImpl)mc).compare(this, pc)) {
                    Logger.printTrace("matchManagedConnections found a match");
                    return mc;
                }
            }
        }
        Logger.printTrace("matchManagedConnections did not find a match");
        return null;
    }

    /**
     * Helper class required to extract the PasswordCredentials from a Subject.
     * </p>The getPrivateCredentials() method is privileged so in most
     * environments a SecurityException will occur unless the method is 
     * wrapped in a PrivilegedAction.
     */
    static class ExtractCredentials implements PrivilegedAction {
        Subject subject;
        ManagedConnectionFactory mcf;
        
        ExtractCredentials(ManagedConnectionFactory mcf, Subject subject)
        {
            this.mcf = mcf;
            this.subject = subject;
        }
        
        public Object run()
        {
           Set creds = subject.getPrivateCredentials(PasswordCredential.class);
           for (Iterator i = creds.iterator(); i.hasNext(); ) {
              PasswordCredential cred = (PasswordCredential)i.next();
              // Subject may contain more than one set of credentials and we
              // only want the PasswordCredential for our ManagedConnectionFactory.
              if (mcf.equals(cred.getManagedConnectionFactory())) {
                 return cred;
              }
           }
           return null;
        }
    }
    
    /**
     * Extract the PasswordCredential object from a Subject.
     * @param mcf the ManagedConnectionFactoryInstance
     * @param subject the optional principal's security credentials.
     * @param cxRequestInfo the optional ConnectionRequestInfo instance
     * @return the <code>PasswordCredential</code> or null.
     */
    PasswordCredential getCredentials(ManagedConnectionFactory mcf, 
                                                    Subject subject, 
                                                    ConnectionRequestInfo cxRequestInfo) {
        PasswordCredential pc = null;
        if (cxRequestInfo != null) {
            //
            // ConnectionRequestInfo supplied and takes precedence
            // This is for application managed security i.e. getConnection(user,password)
            //
            pc = ((ConnectionRequestInfoImpl)cxRequestInfo).getPasswordCredential();
            pc.setManagedConnectionFactory(mcf);
        } else
        if (subject != null) {
            //
            // Container has supplied a Subject containing the credentials
            //
            pc = (PasswordCredential)AccessController.doPrivileged(
                    new ExtractCredentials(mcf, subject));
        }
        if (pc == null) {
            //
            // Credentials must have been supplied via the RAR configuration
            //
            pc = new PasswordCredential(
                    ((ManagedConnectionFactoryImpl)mcf).getUserName(), 
                    ((ManagedConnectionFactoryImpl)mcf).getPassword().toCharArray());
            pc.setManagedConnectionFactory(mcf);
        }
        return pc;
    }
    
    /**
     * Establish equality of this ManagedConnectionFactory object to another
     * object.
     * </p>The JCA specification requires us to override equals.
     * @param other the other object to compare.
     * @return <code>boolean</code> true if the two objects are equal.
     */
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ManagedConnectionFactoryImpl)) {
            return false;
        }
        ManagedConnectionFactoryImpl o = (ManagedConnectionFactoryImpl)other;
        return   (this.serverName == null? 
                  o.serverName == null: this.serverName.equals(o.serverName))
              && (this.portNumber == null? 
                  o.portNumber == null: this.portNumber.equals(o.portNumber))    
              && (this.userName == null? 
                  o.userName == null: this.userName.equals(o.userName)) 
              && (this.password == null? 
                  o.password == null: this.password.equals(o.password)) 
              && (this.connectionURL == null? 
                  o.connectionURL == null: this.connectionURL.equals(o.connectionURL)); 
    }
    
    /**
     * Get the hashcode value for this object.
     * </p>The JCA specification requires us to override hashcode as well.
     * See Effective java by Joshua Bloch for example using these primes.
     * @return the hashcode value as an <code>int</code>.
     */
    public int hashCode() {
        int result = 17;
        result = 37 * result + ((this.serverName != null)? this.serverName.hashCode(): 1);
        result = 37 * result + ((this.portNumber != null)? this.portNumber.hashCode(): 1); 
        result = 37 * result + ((this.userName != null)? this.userName.hashCode(): 1);
        result = 37 * result + ((this.password != null)? this.password.hashCode(): 1);
        result = 37 * result + ((this.connectionURL != null)? this.connectionURL.hashCode(): 1);
        return result;
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
     * <p/>Jboss always sets a log writer. The LogFile connection
     * property always overrides.
     * @param out the log writer or null to disable logging.
     */
    public void setLogWriter(PrintWriter out) throws ResourceException {
        if (out != null) {
            try {
                DataSourceImpl ds = new DataSourceImpl(getConnectionURL(), new Properties());
                if (ds.getLogFile() == null || ds.getLogFile().length() == 0) {
                    ds.setLogWriter(out);
                }
                Logger.initialize(ds);
            } catch (SQLException e) {
                // Ignore 
            }
        }
        this.log = out;
    }

    /**
     * Set the serverName connection property.
     * @param serverName The serverName to set.
     */
    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    /**
     * Retrieve the serverName connection property.
     * @return Returns the serverName.
     */
    public String getServerName() {
        return serverName;
    }

    /**
     * Set the portNumber connection property.
     * @param portNumber The portNumber to set.
     */
    public void setPortNumber(String portNumber) {
        this.portNumber = portNumber;
    }

    /**
     * Retrieve the portNumber connection property.
     * @return Returns the portNumber.
     */
    public String getPortNumber() {
        return portNumber;
    }

    /**
     * Set the userName connection property.
     * @param userName The userName to set.
     */
    public void setUserName(String userName) {
        this.userName = userName;
    }

    /**
     * Retrieve the userName connection property.
     * @return Returns the userName.
     */
    public String getUserName() {
        return (userName == null)? "": userName;
    }

    /**
     * Set the password connection property.
     * @param password The password to set.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Retrieve the password connection property.
     * @return Returns the password.
     */
    public String getPassword() {
        return password = (password == null)? "": password;
    }
    
    /**
     * Set the connection url property.
     * @param url the connection url 'jdbc:jtds:sqlserver://etc'.
     */
    public void setConnectionURL(String url) {
        this.connectionURL = url;
    }

    /**
     * Retrieve the connection url property.
     * @return Returns the connection url.
     */
    public String getConnectionURL() {
        return this.connectionURL;
    }
    // -- Implement ResourceAdapterAssociation methods for JCA 1.5
    
    /**
     * Retrieve the resource adapter instance.
     * @return the <code>ResourceAdapter</code> object.
     */
    public ResourceAdapter getResourceAdapter() {
        Logger.printMethod(this, "getResourceAdapter", null);
        return this.ra;
    }

    /**
     * Set the ResourceAdapter instance.
     * @param ra the resource adapter object.
     * @throws ResourceException
     */
    public void setResourceAdapter(ResourceAdapter ra)
            throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "setResourceAdapter", new Object[]{ra});
        }
        if (ra == null) {
            throw new NullPointerException(
                    Messages.get("error.generic.nullparam", "setResourceAdapter"));
        }
        if (this.ra != null) {
            throw new javax.resource.spi.IllegalStateException(
                    Messages.get("error.jca.rasetagain"));
        }
        this.ra = ra;
    }

    // --- Implement ValidatingManagedConnectionFactory methods
    
    /**
     * This method returns a set of invalid ManagedConnection objects chosen 
     * from a specified set of ManagedConnection objects.
     * @param connectionSet the set of connections to validate.
     * @return a <code>set</code> of invalid ManagedConnection objects. 
     */
    public Set getInvalidConnections(Set connectionSet) 
    throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this,"getInvalidConnections", new Object[]{connectionSet});
        }
        if (connectionSet == null) {
            throw new NullPointerException(
                 Messages.get("error.generic.nullparam", "getInvalidConnections"));
        }
        HashSet<ManagedConnection> bad = new HashSet<ManagedConnection>();
         for (Iterator<ManagedConnection> i = connectionSet.iterator(); i.hasNext(); ) {
             ManagedConnection mc = i.next();
             if (!((ManagedConnectionImpl)mc).isValid()) {
                 bad.add(mc);
             }
         }
         return bad;
    }
}
