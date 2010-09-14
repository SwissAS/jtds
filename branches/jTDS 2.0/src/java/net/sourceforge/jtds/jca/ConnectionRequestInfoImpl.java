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

import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.security.PasswordCredential;
import net.sourceforge.jtds.util.Logger;

/**
 * Class to encapsulate connection request information private to this 
 * resource adapter.
 * </p>Objects of this class are used to pass user/password credentials
 * between a managed connection and the connection manager.
 */
public class ConnectionRequestInfoImpl implements ConnectionRequestInfo {
    /** Encapsulation of the user name and password. */
    PasswordCredential pc;
    
    /**
     * Construct an imutable ConnectionRequestInfo object encapsulating
     * a PasswordCredential object.
     * @param userName the user name.
     * @param password the password.
     */
    public ConnectionRequestInfoImpl(String userName, String password) {
        if (Logger.isTraceActive()) {
            String ptmp = (password == null)? null: "****";
            Logger.printMethod(this, null, new Object[]{userName, ptmp}); 
        }
        if (userName == null) {
            userName = "";
        }
        if (password == null) {
            password = "";
        }
        this.pc = new PasswordCredential(userName, password.toCharArray());
    }
    
    /**
     * Establish equality of this ConnectionRequestInfo object to another
     * object.
     * @param other the other object to compare.
     * @return <code>boolean</code> true if the two objects are equal.
     */
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ConnectionRequestInfoImpl)) {
            return false;
        }
        ConnectionRequestInfoImpl o = (ConnectionRequestInfoImpl)other;
        return this.pc.equals(o.getPasswordCredential()); 
    }
    
    /**
     * Get the hashcode value for this object.
     * @return the hashcode value as an <code>int</code>.
     */
    public int hashCode() {
        return pc.hashCode();
    }

    /**
     * Get a copy of the encapsulated credentials.
     * @return the user name and password as a <code>PasswordCredential</code>.
     */
    public PasswordCredential getPasswordCredential() {
        return new PasswordCredential(pc.getUserName(), pc.getPassword());
    }
        
    /**
     * Retrieve the user name from the credentials.
     * @return Returns the userName as a <code>String</code>.
     */
    public String getUserName() {
        return pc.getUserName();
    }
        
    /**
     * Retrieve the password from the credentials.
     * @return Returns the password as a <code>String</code>.
     */
    public String getPassword() {
        return new String(pc.getPassword());
    }
    
}
