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

import javax.resource.ResourceException;
import javax.resource.spi.ManagedConnectionMetaData;

/**
 * The ManagedConnectionMetaData interface provides information about the
 * underlying EIS (JDBC) instance associated with a ManagedConnection instance. 
 * An application server uses this information to get runtime information about 
 * a connected EIS instance.
 */
public class ManagedConnectionMetaDataImpl implements
        ManagedConnectionMetaData {
    // Cached MetaData information
    String product;
    String version;
    String userName;
    
    /**
     * Construct an imutable meta data object.
     * @param product the SQL server name.
     * @param version the SQL server version.
     * @param userName the user name used to authenticate.
     */
    public ManagedConnectionMetaDataImpl(String product, String version, String userName) {
        this.product  = product;
        this.version  = version;
        this.userName = userName;
    }
    
    /**
     * Retrieve the EIS product name.
     * @return Returns the product name as a <code>String</code>.
     */
    public String getEISProductName() throws ResourceException {
        return this.product;
    }

    /**
     * Retrieve the EIS product version.
     * @return Returns the product version as a <code>String</code>.
     */
    public String getEISProductVersion() throws ResourceException {
        return this.version;
    }

    /**
     * Retrieve the maximum connections value
     * @return Returns the maximum connections value as an 
     * <code>int</code> or 0 if unknown.
     */
    public int getMaxConnections() throws ResourceException {
        return 0;
    }

    /**
     * Retrieve the authenticating user name.
     * @return Returns the user name as a <code>String</code>.
     */
    public String getUserName() throws ResourceException {
        return this.userName;
    }

}
