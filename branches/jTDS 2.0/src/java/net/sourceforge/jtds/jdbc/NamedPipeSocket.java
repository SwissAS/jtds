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
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import jcifs.Config;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbNamedPipe;

/**
 * Remote named pipes socket implemenation.
 */
class NamedPipeSocket extends TdsSocket {

    /**
     * The shared named pipe.
     */
    private SmbNamedPipe pipe;

    /**
     * Construct a remote named pipe socket.
     * @param ds    connection properties.
     * @param host  remote host name.
     * @param port  remote port number.
     * @throws IOException
     */
    NamedPipeSocket(final CommonDataSource ds, 
                    final String host, 
                    final int port) throws IOException 
    {
        super(ds, host, port);

        // apply socketTimeout as responseTimeout
        int timeout = ds.getSocketTimeout() * 1000;
        String val = String.valueOf(timeout > 0 ? timeout : Integer.MAX_VALUE);
        Config.setProperty("jcifs.smb.client.responseTimeout", val);
        Config.setProperty("jcifs.smb.client.soTimeout", val);

        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(
                ds.getDomain(), ds.getUser(), ds.getPassword());

        StringBuffer url = new StringBuffer(32);

        url.append("smb://");
        url.append(ds.getServerName());
        url.append("/IPC$");

        final String instanceName = ds.getInstance();
        if (instanceName != null && instanceName.length() != 0) {
            url.append("/MSSQL$");
            url.append(instanceName);
        }

        String namedPipePath = ds.getNamedPipePath();
        url.append(namedPipePath);

        pipe = new SmbNamedPipe(url.toString(), SmbNamedPipe.PIPE_TYPE_RDWR, auth);

        setOutputStream(new DataOutputStream(pipe.getNamedPipeOutputStream()));

        final int bufferSize = calculateNamedPipeBufferSize(
                ds.getTds(), ds.getPacketSize());
        setInputStream(new DataInputStream(
                new BufferedInputStream(
                        pipe.getNamedPipeInputStream(), bufferSize)));
    }

    /**
     * Close the socket (noop if in shared mode).
     */
    void close() throws IOException {
        if (pipe != null) {
            try {
                getOutputStream().close();
                getInputStream().close();
            } finally {
                pipe = null;
            }
        }
    }

}
