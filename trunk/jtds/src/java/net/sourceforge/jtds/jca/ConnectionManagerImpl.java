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
import javax.resource.spi.ConnectionManager;
import javax.resource.spi.ConnectionRequestInfo;
import javax.resource.spi.ManagedConnectionFactory;

/**
 * Default connection manager provided for use in non managed environments.
 */
public class ConnectionManagerImpl implements ConnectionManager {
    static final long serialVersionUID = 12212313L;
    
    /**
     * The method allocateConnection gets called by the resource adapter's
     * connection factory instance. This lets a connection factory instance 
     * (provided by the resource adapter) pass a connection request to the 
     * ConnectionManager instance.
     * 
     * The connectionRequestInfo parameter represents information specific
     * to the resource adapter for handling of the connection request.
     * @param mcf - used by application server to delegate connection 
     * matching/creation
     * @param cxRequestInfo - connection request Information 
     * @return connection handle with an EIS specific connection interface.
     * @throws ResourceException - Generic exception 
     */
    public Object allocateConnection(ManagedConnectionFactory mcf,
            ConnectionRequestInfo cxRequestInfo) throws ResourceException {
        return mcf.createManagedConnection(null, cxRequestInfo).getConnection(null, cxRequestInfo);
    }

}
