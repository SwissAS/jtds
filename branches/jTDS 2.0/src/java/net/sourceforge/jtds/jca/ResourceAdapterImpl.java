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

import java.io.Serializable;
import javax.resource.ResourceException;
import javax.resource.spi.ActivationSpec;
import javax.resource.spi.BootstrapContext;
import javax.resource.spi.ResourceAdapter;
import javax.resource.spi.ResourceAdapterInternalException;
import javax.resource.spi.endpoint.MessageEndpointFactory;
import javax.transaction.xa.XAResource;
import javax.resource.NotSupportedException;

import net.sourceforge.jtds.util.Logger;

/**
 * Simple ResourceAdapter as required by the JCA 1.5 specification.
 * </p>This is a 'do nothing' class at present. This would be the 
 * ideal place to manage the global XID table (see XASupport) but
 * for now the driver needs to support JCA 1.0 and non JCA usage.
 */
public class ResourceAdapterImpl implements ResourceAdapter, Serializable {
    static final long serialVersionUID = 789979847L;

    public ResourceAdapterImpl() {
        Logger.printMethod(this, null, null);
    }
    
    public void start(BootstrapContext ctx)
            throws ResourceAdapterInternalException {
        Logger.printMethod(this, "start", null);
    }

    public void stop() {
        Logger.printMethod(this, "stop", null);
    }

    public void endpointActivation(MessageEndpointFactory endPoint,
            ActivationSpec spec) throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "endpointActivation", new Object[]{endPoint});
        }
        throw new NotSupportedException("endPointActivation method not supported");
    }

    public void endpointDeactivation(MessageEndpointFactory endPoint,
            ActivationSpec spec) {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "endpointDeactivation", new Object[]{endPoint});
        }
    }

    public XAResource[] getXAResources(ActivationSpec[] arg0)
            throws ResourceException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "getXAResources", new Object[]{arg0});
        }
        // Only required for inbound adapters
        return new XAResource[0];
    }

}
