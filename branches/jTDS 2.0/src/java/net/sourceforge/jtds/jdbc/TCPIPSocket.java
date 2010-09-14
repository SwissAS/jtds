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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.sql.SQLException;
import java.net.InetSocketAddress;
import net.sourceforge.jtds.util.Logger;

/**
 * TDS Socket implementation for the TCP/IP protocol.
 */
class TCPIPSocket extends TdsSocket {
    /**
     * The shared network socket.
     */
    private Socket socket;
    /**
     * The shared SSL network socket;
     */
    private Socket sslSocket;

    /**
     * Construct a TCP/IP socket.
     * @param ds    connection properties.
     * @param host  remote host name.
     * @param port  remote port number.
     * @throws IOException
     */
    TCPIPSocket(final CommonDataSource ds, 
                final String host, 
                final int port) throws IOException
    {
        super(ds, host, port);
        final String bindAddress = ds.getBindAddress();
        int loginTimeout = 0;
        try {
            loginTimeout = ds.getLoginTimeout();
        } catch (SQLException e) {
            // Will not occur
        }
        this.socket = new Socket();
        if (bindAddress != null && bindAddress.length() > 0) {
            this.socket.bind(new InetSocketAddress(bindAddress, 0));
        }
        this.socket.connect(new InetSocketAddress(getHost(), getPort()), loginTimeout * 1000);
        setOutputStream(new DataOutputStream(socket.getOutputStream()));
        setInputStream(new DataInputStream(socket.getInputStream()));
        this.socket.setTcpNoDelay(ds.getTcpNoDelay());
        this.socket.setSoTimeout(ds.getSocketTimeout() * 1000);
    }
    
    /**
     * Enable SSL encryption.
     * @param ssl the encyrption required (off,request,require,authenticate).
     * @throws IOException
     */
    void enableEncryption(final String ssl) throws IOException {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "enableEncryption", new Object[]{ssl});
        }
        sslSocket = SecureSocket.getSocketFactory(ssl, this.socket)
                .createSocket(getHost(), getPort());
        setOutputStream(new DataOutputStream(sslSocket.getOutputStream()));
        setInputStream(new DataInputStream(sslSocket.getInputStream()));
    }
    
    /**
     * Disable SSL encryption.
     * @throws IOException
     */
    void disableEncryption() throws IOException {
        Logger.printMethod(this, "disableEncryption", null);
        sslSocket.close();
        sslSocket = null;
        setOutputStream(new DataOutputStream(socket.getOutputStream()));
        setInputStream(new DataInputStream(socket.getInputStream()));
    }
    
    /**
     * Get the connected status of this socket.
     *
     * @return <code>true</code> if the underlying socket is connected
     */
    boolean isConnected() {
        return this.socket != null && this.socket.isConnected();
    }
    
    /**
     * Close the TDS socket.
     * @throws IOException
     */
    void close() throws IOException {
        try {
            if (sslSocket != null) {
                sslSocket.close();
                sslSocket = null;
            }
        } finally {
            // Close physical socket
            if (socket != null) {
                socket.close();
                socket = null;
            }
        }
    }

    /**
     * Set the socket timeout.
     *
     * @param timeout the timeout value in milliseconds
     */
    void setTimeout(int timeout) throws SocketException {
        socket.setSoTimeout(timeout);
    }
}
