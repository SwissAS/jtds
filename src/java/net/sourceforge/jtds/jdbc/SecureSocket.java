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

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


/**
 * A socket that mediates between JSSE and the DB server.
 *
 * @author Rob Worsnop
 * @author Mike Hutchinson
 * @version $Id: SecureSocket.java,v 1.1 2007-09-10 19:19:32 bheineman Exp $
 */
class SecureSocket extends Socket {
    /**
     * SSL is not used.
     */
    static final String SSL_OFF = "off";
    /**
     * SSL is requested; a plain socket is used if SSL is not available.
     */
    static final String SSL_REQUEST = "request";
    /**
     * SSL is required; an exception if thrown if SSL is not available.
     */
    static final String SSL_REQUIRE = "require";
    /**
     * SSL is required and the server must return a certificate signed by a
     * client-trusted authority.
     */
    static final String SSL_AUTHENTICATE = "authenticate";
    /** Size of TLS record header. */
    static final int  TLS_HEADER_SIZE = 5;
    /** TLS Change Cipher Spec record type. */
    static final byte TYPE_CHANGECIPHERSPEC = 20;
    /** TLS Alert record type. */
    static final byte TYPE_ALERT = 21;
    /** TLS Handshake record. */
    static final byte TYPE_HANDSHAKE = 22;
    /** TLS Application data record. */
    static final byte TYPE_APPLICATIONDATA = 23;
    /** TLS Hand shake Header Size. */
    static final int HS_HEADER_SIZE = 4;
    /** TLS Hand shake client key exchange sub type. */
    static final int TYPE_CLIENTKEYEXCHANGE = 16;
    /** TLS Hand shake client hello sub type. */
    static final int TYPE_CLIENTHELLO = 1;
    //
    // Instance variables
    //
    private final Socket delegate;
    private final InputStream istm;
    private final OutputStream ostm;

    /**
     * Returns a socket factory, the behavior of which will depend on the SSL
     * setting and whether or not the DB server supports 
     *
     * @param ssl    the SSL setting
     * @param socket plain TCP/IP socket to wrap
     */
    static SocketFactory getSocketFactory(final String ssl, final Socket socket) {
        return new TdsTlsSocketFactory(ssl, socket);
    }

    /**
     * Constructs a TdsTlsSocket around an underlying socket.
     *
     * @param delegate the underlying socket
     */
    SecureSocket(final Socket delegate) throws IOException {
        this.delegate = delegate;
        istm = new SecureInputStream(delegate.getInputStream());
        ostm = new SecureOutputStream(delegate.getOutputStream());
    }

    /*
     * (non-Javadoc)
     *
     * @see java.net.Socket#close()
     */
    public synchronized void close() throws IOException {
        // Do nothing. Underlying socket closed elsewhere
    }

    /*
     * (non-Javadoc)
     *
     * @see java.net.Socket#getInputStream()
     */
    public InputStream getInputStream() throws IOException {
        return istm;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.net.Socket#getOutputStream()
     */
    public OutputStream getOutputStream() throws IOException {
        return ostm;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.net.Socket#isConnected()
     */
    public boolean isConnected() {
        return true;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.net.Socket#setSoTimeout(int)
     */
    public synchronized void setSoTimeout(int timeout) throws SocketException {
        delegate.setSoTimeout(timeout);
    }

    /*
     * (non-Javadoc)
     *
     * @see java.net.Socket#setTcpNoDelay(boolean)
     */
    public void setTcpNoDelay(boolean on) throws SocketException {
        delegate.setTcpNoDelay(on);
    }
    /**
     * An input stream that filters out TDS headers so they are not returned to
     * JSSE (which will not recognize them).
     *
     * @author Rob Worsnop
     * @author Mike Hutchinson
     * @version $Id: SecureSocket.java,v 1.1 2007-09-10 19:19:32 bheineman Exp $
     */
    private static class SecureInputStream extends FilterInputStream {

        int bytesOutstanding;

        /**
         * Temporary buffer used to de-encapsulate inital TLS packets.
         * Initial size should be enough for login phase after which no
         * buffering is required.
         */
        final byte[] readBuffer = new byte[6144];

        InputStream bufferStream;

        /** False if TLS packets are encapsulated in TDS packets. */
        boolean pureSSL;

        /**
         * Constructs a TdsTlsInputStream and bases it on an underlying stream.
         *
         * @param in the underlying stream
         */
        public SecureInputStream(final InputStream in) {
            super(in);
        }

        /*
         * (non-Javadoc)
         *
         * @see java.io.InputStream#read(byte[], int, int)
         */
        public int read(byte[] b, int off, int len) throws IOException {

            //
            // If we have read past the TDS encapsulated TLS records
            // Just read directly from the input stream.
            //
            if (pureSSL && bufferStream == null) {
                return in.read(b, off, len);
            }

            // If this is the start of a new TLS record or
            // TDS packet we need to read in entire record/packet.
            if (!pureSSL && bufferStream == null) {
                primeBuffer();
            }

            // Feed the client code bytes from the buffer
            int ret = bufferStream.read(b, off, len);
            bytesOutstanding -= ret < 0 ? 0 : ret;
            if (bytesOutstanding == 0) {
                // All bytes in the buffer have been read.
                // The next read will prime it again.
                bufferStream = null;
            }

            return ret;
        }

        /**
         * Read in entire TLS record or TDS packet and store the TLS record in the
         * buffer. (TDS packets will always contain a TLS record.)
         */
        private void primeBuffer() throws IOException {
            // first read the type (first byte for TDS and TLS).
            // TLS packet hdr size = 5 TDS = 8
            readFully(readBuffer, 0, TLS_HEADER_SIZE);
            int len;
            if (readBuffer[0] == TdsCore.REPLY_PKT
                    || readBuffer[0] == TdsCore.PRELOGIN_PKT) {
                len = ((readBuffer[2] & 0xFF) << 8) | (readBuffer[3] & 0xFF);
                // Read rest of header to skip
                readFully(readBuffer, TLS_HEADER_SIZE, TdsCore.PKT_HDR_LEN - TLS_HEADER_SIZE );
                len -= TdsCore.PKT_HDR_LEN;
                readFully(readBuffer, 0, len); // Now get inner packet
            } else {
                len = ((readBuffer[3] & 0xFF) << 8) | (readBuffer[4] & 0xFF);
                readFully(readBuffer, TLS_HEADER_SIZE, len - TLS_HEADER_SIZE);
                pureSSL = true;
            }

            bufferStream = new ByteArrayInputStream(readBuffer, 0, len);
            bytesOutstanding = len;
        }

        /**
         * Reads <code>len</code> bytes or throws an <code>IOException</code> if
         * there aren't that many bytes available.
         *
         * @param b   buffer to read into
         * @param off offset in the buffer where to start storing
         * @param len amount of data to read
         * @throws IOException if an I/O error occurs or not enough data is
         *                     available
         */
        private void readFully(byte[] b, int off, int len) throws IOException {
            int res = 0;
            while (len > 0 && (res = in.read(b, off, len)) >= 0) {
                off += res;
                len -= res;
            }

            if (res < 0) {
                throw new IOException();
            }
        }
    }
    /**
     * An output stream that mediates between JSSE and the DB server.
     * <p/>
     * SQL Server 2000 has the following requirements:
     * <ul>
     *   <li>All handshake records are delivered in TDS packets.
     *   <li>The "Client Key Exchange" (CKE), "Change Cipher Spec" (CCS) and
     *     "Finished" (FIN) messages are to be submitted in the delivered in both
     *     the same TDS packet and the same TCP packet.
     *   <li>From then on TLS/SSL records should be transmitted as normal -- the
     *     TDS packet is part of the encrypted application data.
     *
     * @author Rob Worsnop
     * @author Mike Hutchinson
     * @version $Id: SecureSocket.java,v 1.1 2007-09-10 19:19:32 bheineman Exp $
     */
    private static class SecureOutputStream extends FilterOutputStream {
        /**
         * Used for holding back CKE, CCS and FIN records.
         */
        final private List<byte[]> bufferedRecords = new ArrayList<byte[]>();
        private int totalSize;

        /**
         * Constructs a TdsTlsOutputStream based on an underlying output stream.
         *
         * @param out the underlying output stream
         */
        SecureOutputStream(final OutputStream out) {
            super(out);
        }

        /**
         * Holds back a record for batched transmission.
         *
         * @param record the TLS record to buffer
         * @param len    the length of the TLS record to buffer
         */
        private void deferRecord(final byte record[], final int len) {
            byte tmp[] = new byte[len];
            System.arraycopy(record, 0, tmp, 0, len);
            bufferedRecords.add(tmp);
            totalSize += len;
        }

        /**
         * Transmits the buffered batch of records.
         */
        private void flushBufferedRecords() throws IOException {
            byte tmp[] = new byte[totalSize];
            int off = 0;
            for (int i = 0; i < bufferedRecords.size(); i++) {
                byte x[] = bufferedRecords.get(i);
                System.arraycopy(x, 0, tmp, off, x.length);
                off += x.length;
            }
            putTdsPacket(tmp, off);
            bufferedRecords.clear();
            totalSize = 0;
        }

        public void write(byte[] b, int off, int len) throws IOException {

            if (len < TLS_HEADER_SIZE || off > 0) {
                // Too short for a TLS packet just write it
                out.write(b, off, len);
                return;
            }
            //
            // Extract relevant TLS header fields
            //
            int contentType = b[0] & 0xFF;
            int length  = ((b[3] & 0xFF) << 8) | (b[4] & 0xFF);
            //
            // Check to see if probably a SSL client hello
            //
            if (contentType < TYPE_CHANGECIPHERSPEC ||
                contentType > TYPE_APPLICATIONDATA ||
                length != len - TLS_HEADER_SIZE) {
                // Assume SSLV2 Client Hello
                putTdsPacket(b, len);
                return;
            }
            //
            // Process TLS records
            //
            switch (contentType) {

                case TYPE_APPLICATIONDATA:
                    // Application data, just copy to output
                    out.write(b, off, len);
                    break;

                case TYPE_CHANGECIPHERSPEC:
                    // Cipher spec change has to be buffered
                    deferRecord(b, len);
                    break;

                case TYPE_ALERT:
                    // Alert record ignore!
                    break;

                case TYPE_HANDSHAKE:
                    // TLS Handshake records
                    if (len >= (TLS_HEADER_SIZE + HS_HEADER_SIZE)) {
                        // Long enough for a handshake subheader
                        int hsType = b[5];
                        int hsLen  = (b[6] & 0xFF) << 16 |
                                     (b[7] & 0xFF) << 8  |
                                     (b[8] & 0xFF);

                        if (hsLen == len - (TLS_HEADER_SIZE + HS_HEADER_SIZE) &&
                            // Client hello has to go in its own TDS packet
                            hsType == TYPE_CLIENTHELLO) {
                            putTdsPacket(b, len);
                            break;
                        }
                        // All others have to be deferred and sent as a block
                        deferRecord(b, len);
                        //
                        // Now see if we have a finish record which will flush the
                        // buffered records.
                        //
                        if (hsLen != len - (TLS_HEADER_SIZE + HS_HEADER_SIZE) ||
                            hsType != TYPE_CLIENTKEYEXCHANGE) {
                            // This is probably a finish record
                            flushBufferedRecords();
                        }
                        break;
                    }
                default:
                    // Short or unknown record output it anyway
                    out.write(b, off, len);
                    break;
            }
        }

        /**
         * Write a TDS packet containing the TLS record(s).
         *
         * @param b   the TLS record
         * @param len the length of the TLS record
         */
        void putTdsPacket(final byte[] b, final int len) throws IOException {
            byte tdsHdr[] = new byte[TdsCore.PKT_HDR_LEN];
            tdsHdr[0] = TdsCore.PRELOGIN_PKT;
            tdsHdr[1] = 0x01;
            tdsHdr[2] = (byte)((len + TdsCore.PKT_HDR_LEN) >> 8);
            tdsHdr[3] = (byte)(len + TdsCore.PKT_HDR_LEN);
            out.write(tdsHdr, 0, tdsHdr.length);
            out.write(b, 0, len);
        }

        /*
         * (non-Javadoc)
         *
         * @see java.io.OutputStream#flush()
         */
        public void flush() throws IOException {
            super.flush();
        }

    }
    /**
     * The socket factory for creating sockets based on the SSL setting.
     */
    private static class TdsTlsSocketFactory extends SocketFactory {
        private static SSLSocketFactory factorySingleton;

        private final String ssl;
        private final Socket socket;

        /**
         * Constructs a TdsTlsSocketFactory.
         *
         * @param ssl      the SSL setting
         * @param socket   the TCP/IP socket to wrap
         */
        public TdsTlsSocketFactory(final String ssl, final Socket socket) {
            this.ssl = ssl;
            this.socket = socket;
        }

        /**
         * Create the SSL socket.
         * <p/>
         * NB. This method will actually create a connected socket over the
         * TCP/IP network socket supplied via the constructor of this factory
         * class.
         */
        public Socket createSocket(String host, int port)
                throws IOException, UnknownHostException {
            SSLSocket sslSocket = (SSLSocket) getFactory()
                    .createSocket(new SecureSocket(socket), host, port, true);
            //
            // See if connecting to local server.
            // getLocalHost() will normally return the address of a real
            // local network interface so we check that one and the loopback
            // address localhost/127.0.0.1
            //
            // XXX: Disable TLS resume altogether, because the cause of local
            // server failures is unknown and it also seems to sometimes occur
            // with remote servers.
            //
//            if (socket.getInetAddress().equals(InetAddress.getLocalHost()) ||
//                host.equalsIgnoreCase("localhost") || host.startsWith("127.")) {
                // Resume session causes failures with a local server
                // Invalidate the session to prevent resumes.
                sslSocket.startHandshake(); // Any IOException thrown here
                sslSocket.getSession().invalidate();
//                Logger.println("TLS Resume disabled");
//            }

            return sslSocket;
        }

        /*
         * (non-Javadoc)
         *
         * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int)
         */
        public Socket createSocket(InetAddress host, int port)
                throws IOException {
            return null;
        }

        /*
         * (non-Javadoc)
         *
         * @see javax.net.SocketFactory#createSocket(java.lang.String, int,
         *      java.net.InetAddress, int)
         */
        public Socket createSocket(String host, int port,
                                   InetAddress localHost, int localPort) throws IOException,
                UnknownHostException {
            return null;
        }

        /*
         * (non-Javadoc)
         *
         * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int,
         *      java.net.InetAddress, int)
         */
        public Socket createSocket(InetAddress host, int port,
                                   InetAddress localHost, int localPort) throws IOException {
            return null;
        }

        /**
         * Returns an SSLSocketFactory whose behavior will depend on the SSL
         * setting.
         *
         * @return an <code>SSLSocketFactory</code>
         */
        private SSLSocketFactory getFactory() throws IOException {
            try {
                if (ssl.equals(SSL_AUTHENTICATE)) {
                    // the default factory will produce a socket that authenticates
                    // the server using its certificate chain.
                    return (SSLSocketFactory) SSLSocketFactory.getDefault();
                }
                // Our custom factory will not authenticate the server.
                return factory();
            } catch (GeneralSecurityException e) {
                throw new IOException(e.getMessage());
            }
        }

        /**
         * Returns an SSLSocketFactory whose sockets will not authenticate the
         * server.
         *
         * @return an <code>SSLSocketFactory</code>
         */
        private static SSLSocketFactory factory()
                throws NoSuchAlgorithmException, KeyManagementException {
            if (factorySingleton == null) {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, trustManagers(), null);
                factorySingleton = ctx.getSocketFactory();
            }
            return factorySingleton;
        }

        private static TrustManager[] trustManagers() {
            X509TrustManager tm = new X509TrustManager() {
                
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                public void checkServerTrusted(X509Certificate[] chain, String x) {
                    // Dummy method
                }
                
                public void checkClientTrusted(X509Certificate[] chain, String x) {
                    // Dummy method
                }
                
            };

            return new X509TrustManager[]{tm};
        }

    }
}
