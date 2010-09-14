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
import java.io.EOFException;
import java.io.IOException;
import java.net.SocketException;
import java.sql.SQLException;
import java.util.Random;

import net.sourceforge.jtds.util.Logger;

/**
 * Base class to interface specific low level protcol sockets.
 */
abstract class TdsSocket {
    /**
     * Output stream for network socket.
     */
    private DataOutputStream out;
    /**
     * Input stream for network socket.
     */
    private DataInputStream in;

    /**
     * Current maxium input buffer size.
     */
    private int maxBufSize = TdsCore.MIN_PKT_SIZE;
    /**
     * Buffer for packet header.
     */
    private final byte hdrBuf[] = new byte[TdsCore.PKT_HDR_LEN];
    /**
     * The server host name.
     */
    private String host;
    /**
     * The server port number.
     */
    private int port;

    /**
     * Create a TDS Socket instance.
     * @param ds the DataSource with the connection properties.
     * @param host the remote host name.
     * @param port the remote port.
     * @return the created <code>TdsSocket</code>.
     * @throws IOException
     * @throws SQLException
     */
    static TdsSocket getInstance(final CommonDataSource ds, 
                                 final String host, 
                                 final int port) 
        throws IOException, SQLException 
    {
        TdsSocket socket = null;
        
        if (ds.getNetworkProtocol().equalsIgnoreCase("namedpipes")) {
            final long retryTimeout = (ds.getLoginTimeout() > 0 ? ds.getLoginTimeout() : 20) * 1000;
            final long startLoginTimeout = System.currentTimeMillis();
            final Random random = new Random(startLoginTimeout);
            final boolean isWindowsOS = System.getProperty("os.name").toLowerCase().startsWith("windows");

            IOException lastIOException = null;
            int exceptionCount = 0;

            do {
                try {
                    if (isWindowsOS && !ds.getUseJCIFS()) {
                        socket = new LocalSocket(ds, host, port);
                    }
                    else {
                        socket = new NamedPipeSocket(ds, host, port);
                    }
                }
                catch (IOException ioe) {
                    exceptionCount++;
                    lastIOException = ioe;
                    if (ioe.getMessage().toLowerCase().indexOf("all pipe instances are busy") >= 0) {
                        // Per a Microsoft knowledgebase article, wait 200 ms to 1 second each time
                        // we get an "All pipe instances are busy" error.
                        // http://support.microsoft.com/default.aspx?scid=KB;EN-US;165189
                        final int randomWait = random.nextInt(800) + 200;
                        if (Logger.isActive()) {
                            Logger.println("Retry #" + exceptionCount + " Wait " + randomWait + " ms: " +
                                        ioe.getMessage());
                        }
                        try {
                            Thread.sleep(randomWait);
                        }
                        catch (InterruptedException ie) {
                            // Do nothing; retry again
                        }
                    }
                    else {
                        throw ioe;
                    }
                }
            } while (socket == null && (System.currentTimeMillis() - startLoginTimeout) < retryTimeout);

            if (socket == null) {
                final IOException ioException = new IOException("Connection timed out to named pipe");
                ioException.initCause(lastIOException);
                throw ioException;
            }
        } else {
           // Use plain TCP/IP socket
           socket = new TCPIPSocket(ds, host, port);
        }
        return socket;
    }
    
    /**
     * Construct a new TDS socket.
     * @param ds the DataSource with the connection properties.
     * @param host the remote host name.
     * @param port the port number.
     * @throws IOException
     */
    TdsSocket(final CommonDataSource ds, 
              final String host, 
              final int port) throws IOException
    {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, null, new Object[]{host, Integer.toString(port)});
        }
        this.host = host;
        this.port = port;
    }

    /**
     * Set the output stream for this socket.
     * @param out the output byte stream.
     */
    protected void setOutputStream(final DataOutputStream out) {
        this.out = out;
    }
    
    /**
     * Set the input stream for this socket.
     * @param in the input byte stream.
     */
    protected void setInputStream(final DataInputStream in) {
        this.in = in;
    }
    
    /**
     * Retrive the output stream for this socket.
     * @return the stream as a <code>DataOutputStream</code>.
     */
    protected DataOutputStream getOutputStream() {
        return this.out;
    }
    
    /**
     * Retrive the input stream for this socket.
     * @return the stream as a <code>DataInputStream</code>.
     */
    protected DataInputStream getInputStream() {
        return this.in;
    }

    /**
     * Enable SSL encryption.
     * @param ssl the encyrption required (off,request,require,authenticate).
     * @throws IOException
     */
    void enableEncryption(final String ssl) throws IOException {
        // Override
    }

    /**
     * Disable SSL encryption.
     * @throws IOException
     */
    void disableEncryption() throws IOException {
        // Override
    }
    
    /**
     * Get the connection status of this socket.
     * @return <code>boolean<code> true if socket connected.
     */
    boolean isConnected() {
        return false;
    }
    
    /**
     * Close the TDS socket.
     * @throws IOException
     */
    void close() throws IOException {
        // Override
    }

    /**
     * Send a packet to the server.
     * @param buffer the packet data.
     * @throws IOException
     */
    void sendBytes(final byte buffer[]) throws IOException { 
        if (Logger.isActive()) {
            Logger.logPacket(false, buffer);
        }

        getOutputStream().write(buffer, 0, getPktLen(buffer));

        if (buffer[1] != 0) {
            getOutputStream().flush();
        }
    }
    
    /**
     * Get a packet from the server.
     * @param buffer the buffer to accept the packet.
     * @return <code>byte[]</code> containing the server packet.
     * @throws IOException
     */
    byte[] getNetPacket(byte buffer[]) throws IOException {
        //
        // Read TDS header
        //
        try {
            getInputStream().readFully(hdrBuf);
        } catch (EOFException e) {
            throw new IOException(Messages.get("error.io.serverclose"));
        }

        byte packetType = hdrBuf[0];

        if (packetType != TdsCore.LOGIN_PKT
                && packetType != TdsCore.QUERY_PKT
                && packetType != TdsCore.SYBQUERY_PKT // required to connect IBM/Netcool Omnibus, see patch [1844846]
                && packetType != TdsCore.REPLY_PKT) {
            throw new IOException("Unknown TDS packet type" + (packetType & 0xFF));
        }

        // figure out how many bytes are remaining in this packet.
        int len = getPktLen(hdrBuf);

        if (len < TdsCore.PKT_HDR_LEN || len > 65536) {
            throw new IOException(Messages.get("error.io.badpktsize", Integer.toString(len)));
        }

        if (buffer == null || len > buffer.length) {
            // Create or expand the buffer as required
            buffer = new byte[len];

            if (len > maxBufSize) {
                maxBufSize = len;
            }
        }

        // Preserve the packet header in the buffer
        System.arraycopy(hdrBuf, 0, buffer, 0, TdsCore.PKT_HDR_LEN);

        try {
            getInputStream().readFully(buffer, TdsCore.PKT_HDR_LEN, len - TdsCore.PKT_HDR_LEN);
        } catch (EOFException e) {
            throw new IOException(Messages.get("error.io.serverclose"));
        }

        if (Logger.isActive()) {
            Logger.logPacket(true, buffer);
        }

        return buffer;
    }

    /**
     * Set the socket timeout.
     * @param timeout the timeout value in milliseconds.
     * @throws SocketException
     */
    void setTimeout(final int timeout) throws SocketException {
        // Override
    }

    /**
     * Get the server host name.
     *
     * @return the host name as a <code>String</code>
     */
    String getHost() {
        return this.host;
    }

    /**
     * Get the server port number.
     *
     * @return the host port as an <code>int</code>
     */
    int getPort() {
        return this.port;
    }

    /**
     * Convert two bytes (in network byte order) in a byte array into a Java
     * short integer.
     *
     * @param buf    array of data
     * @return the 16 bit unsigned value as an <code>int</code>
     */
    int getPktLen(final byte buf[]) {
        int lo = (buf[3] & 0xff);
        int hi = ((buf[2] & 0xff) << 8);

        return hi | lo;
    }

    /**
     * Calculate the buffer size to use when buffering the <code>InputStream</code>
     * for named pipes.
     * <p/>
     * The buffer size is tied directly to the packet size because each request
     * to the <code>SmbNamedPipe</code> will send a request for a particular
     * size of packet.  In other words, if you only request 1 byte, the
     * <code>SmbNamedPipe</code> will send a request out and only ask for 1 byte
     * back.  Buffering the expected packet size ensures that all of the data
     * will be returned in the buffer without wasting any space.
     *
     * @param tds the TDS version for the connection
     * @param packetSize requested packet size for the connection
     * @return minimum default packet size if <code>packetSize == 0</code>,
     *         else <code>packetSize</code>
     */
    protected int calculateNamedPipeBufferSize(final String tds, final int packetSize) {

        if (packetSize == 0) {
            if (tds.equals("7.0") || tds.equals("8.0")) {
                return TdsCore.DEFAULT_MIN_PKT_SIZE_TDS70;
            }

            return TdsCore.MIN_PKT_SIZE;
        }

        return packetSize;
    }

}
