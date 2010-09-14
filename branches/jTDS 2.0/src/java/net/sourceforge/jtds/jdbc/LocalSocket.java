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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.io.IOException;

/**
 * Local named pipe socket implementation.
 */
class LocalSocket extends TdsSocket {
    /**
     * The named pipe as a file.
     */
    RandomAccessFile pipe;
    
    /**
     * Construct a local named pipe socket.
     * @param ds    connection properties.
     * @param host  remote host name.
     * @param port  remote port number.
     * @throws IOException
     */
    LocalSocket(final CommonDataSource ds, 
                final String host, 
                final int port) throws IOException 
    {
        super(ds, host, port);
        final String serverName = ds.getServerName();
        final String instanceName = ds.getInstance();

        final StringBuffer pipeName = new StringBuffer(64);
        pipeName.append("\\\\");
        if (serverName == null || 
            serverName.length() == 0 || 
            serverName.equalsIgnoreCase("localhost")) 
        {
            pipeName.append( '.' );
        } else {
            pipeName.append(serverName);
        }
        pipeName.append("\\pipe");
        if (instanceName != null && instanceName.length() != 0) {
            pipeName.append("\\MSSQL$").append(instanceName);
        }
        String namedPipePath = ds.getNamedPipePath();
        pipeName.append(namedPipePath.replace('/', '\\'));

        this.pipe = new RandomAccessFile(pipeName.toString(), "rw");

        final int bufferSize = calculateNamedPipeBufferSize(
                ds.getTds(), ds.getPacketSize());
        setOutputStream(new DataOutputStream(
                new BufferedOutputStream(
                        new FileOutputStream(this.pipe.getFD()), bufferSize)));
        setInputStream(new DataInputStream(
                new BufferedInputStream(
                        new FileInputStream(this.pipe.getFD()), bufferSize)));
    }
    
    /**
     * Close the socket (noop if in shared mode).
     */
    void close() throws IOException {
        if (this.pipe != null) {
            try {
                getOutputStream().close();
                getInputStream().close();
                this.pipe.close();
            } finally {
                this.pipe = null;
            }
        }
    }

}
