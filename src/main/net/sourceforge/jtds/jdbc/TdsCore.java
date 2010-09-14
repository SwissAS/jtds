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

import java.io.*;
import java.sql.*;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;

import net.sourceforge.jtds.ssl.*;
import net.sourceforge.jtds.util.*;

/**
 * This class implements the Sybase / Microsoft TDS protocol.
 * <p>
 * Implementation notes:
 * <ol>
 * <li>This class, together with TdsData, encapsulates all of the TDS specific logic
 *     required by the driver.
 * <li>This is a ground up reimplementation of the TDS protocol and is rather
 *     simpler, and hopefully easier to understand, than the original.
 * <li>The layout of the various Login packets is derived from the original code
 *     and freeTds work, and incorporates changes including the ability to login as a TDS 5.0 user.
 * <li>All network I/O errors are trapped here, reported to the log (if active)
 *     and the parent Connection object is notified that the connection should be considered
 *     closed.
 * <li>Rather than having a large number of classes one for each token, useful information
 *     about the current token is gathered together in the inner TdsToken class.
 * <li>As the rest of the driver interfaces to this code via higher-level method calls there
 *     should be know need for knowledge of the TDS protocol to leak out of this class.
 *     It is for this reason that all the TDS Token constants are private.
 * </ol>
 *
 * @author Mike Hutchinson
 * @author Matt Brinkley
 * @author Alin Sinpalean
 * @author freeTDS project
 * @version $Id: TdsCore.java,v 1.86.2.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public class TdsCore {
    /**
     * Inner static class used to hold information about TDS tokens read.
     */
    private static class TdsToken {
        /** The current TDS token byte. */
        byte token;
        /** The status field from a DONE packet. */
        byte status;
        /** The operation field from a DONE packet. */
        byte operation;
        /** The update count from a DONE packet. */
        int updateCount;

        /**
         * Retrieve the update count status.
         *
         * @return <code>boolean</code> true if the update count is valid.
         */
        boolean isUpdateCount() {
            return (token == TDS_DONE_TOKEN || token == TDS_DONEINPROC_TOKEN)
                    && (status & DONE_ROW_COUNT) != 0;
        }

        /**
         * Retrieve the DONE token status.
         *
         * @return <code>boolean</code> true if the current token is a DONE packet.
         */
        boolean isEndToken() {
            return token == TDS_DONE_TOKEN
                   || token == TDS_DONEINPROC_TOKEN
                   || token == TDS_DONEPROC_TOKEN;
        }

        /**
         * Retrieve the results pending status.
         *
         * @return <code>boolean</code> true if more results in input.
         */
        boolean resultsPending() {
            return !isEndToken() || ((status & DONE_MORE_RESULTS) != 0);
        }

        /**
         * Retrieve the result set status.
         *
         * @return <code>boolean</code> true if the current token is a result set.
         */
        boolean isResultSet() {
            return token == TDS7_RESULT_TOKEN
                   || token == TDS_COLINFO_TOKEN
                   || token == TDS_ROW_TOKEN;
        }

        /**
         * Retrieve the row data status.
         *
         * @return <code>boolean</code> true if the current token is a result row.
         */
        public boolean isRowData() {
            return token == TDS_ROW_TOKEN;
        }

    }
    /**
     * Inner static class used to hold table meta data.
     */
    private static class TableMetaData {
        /** Table catalog (database) name. */
        String catalog;
        /** Table schema (user) name. */
        String schema;
        /** Table name. */
        String name;
    }

    //
    // Package private constants
    //
    /** Minimum network packet size. */
    public static final int MIN_PKT_SIZE = 512;
    /** Default minimum network packet size for TDS 7.0 and newer. */
    public static final int DEFAULT_MIN_PKT_SIZE_TDS70 = 4096;
    /** Maximum network packet size. */
    public static final int MAX_PKT_SIZE = 32768;
    /** The size of the packet header. */
    public static final int PKT_HDR_LEN = 8;
    /** TDS 4.2 or 7.0 Query packet. */
    public static final byte QUERY_PKT = 1;
    /** TDS 4.2 or 5.0 Login packet. */
    public static final byte LOGIN_PKT = 2;
    /** TDS Remote Procedure Call. */
    public static final byte RPC_PKT = 3;
    /** TDS Reply packet. */
    public static final byte REPLY_PKT = 4;
    /** TDS Cancel packet. */
    public static final byte CANCEL_PKT = 6;
    /** TDS MSDTC packet. */
    public static final byte MSDTC_PKT = 14;
    /** TDS 7.0 Login packet. */
    public static final byte MSLOGIN_PKT = 16;
    /** TDS 7.0 NTLM Authentication packet. */
    public static final byte NTLMAUTH_PKT = 17;
    /** SQL 2000 prelogin negotiation packet. */
    public static final byte PRELOGIN_PKT = 18;
    /** SSL Mode - Login packet must be encrypted. */
    public static final int SSL_ENCRYPT_LOGIN = 0;
    /** SSL Mode - Client requested force encryption. */
    public static final int SSL_CLIENT_FORCE_ENCRYPT = 1;
    /** SSL Mode - No server certificate installed. */
    public static final int SSL_NO_ENCRYPT = 2;
    /** SSL Mode - Server requested force encryption. */
    public static final int SSL_SERVER_FORCE_ENCRYPT = 3;

    //
    // Sub packet types
    //
    /** TDS DBLIB Offsets token. */
    private static final byte TDS_OFFSETS_TOKEN     = (byte) 120;  // 0x78
    /** TDS Procedure call return status token. */
    private static final byte TDS_RETURNSTATUS_TOKEN= (byte) 121;  // 0x79
    /** TDS Procedure ID token. */
    private static final byte TDS_PROCID            = (byte) 124;  // 0x7C
    /** TDS 7.0 Result set column meta data token. */
    private static final byte TDS7_RESULT_TOKEN     = (byte) 129;  // 0x81
    /** TDS 7.0 Computed Result set column meta data token. */
    private static final byte TDS7_COMP_RESULT_TOKEN= (byte) 136;  // 0x88
    /** TDS Table name token. */
    private static final byte TDS_TABNAME_TOKEN     = (byte) 164;  // 0xA4
    /** TDS Cursor results column infomation token. */
    private static final byte TDS_COLINFO_TOKEN     = (byte) 165;  // 0xA5
    /** TDS Computed result set names token. */
    private static final byte TDS_COMP_NAMES_TOKEN  = (byte) 167;  // 0xA7
    /** TDS Computed result set token. */
    private static final byte TDS_COMP_RESULT_TOKEN = (byte) 168;  // 0xA8
    /** TDS Order by columns token. */
    private static final byte TDS_ORDER_TOKEN       = (byte) 169;  // 0xA9
    /** TDS error result token. */
    private static final byte TDS_ERROR_TOKEN       = (byte) 170;  // 0xAA
    /** TDS Information message token. */
    private static final byte TDS_INFO_TOKEN        = (byte) 171;  // 0xAB
    /** TDS Output parameter value token. */
    private static final byte TDS_PARAM_TOKEN       = (byte) 172;  // 0xAC
    /** TDS Login acknowledgement token. */
    private static final byte TDS_LOGINACK_TOKEN    = (byte) 173;  // 0xAD
    /** TDS control token. */
    private static final byte TDS_CONTROL_TOKEN     = (byte) 174;  // 0xAE
    /** TDS Result set data row token. */
    private static final byte TDS_ROW_TOKEN         = (byte) 209;  // 0xD1
    /** TDS Computed result set data row token. */
    private static final byte TDS_ALTROW            = (byte) 211;  // 0xD3
    /** TDS environment change token. */
    private static final byte TDS_ENVCHANGE_TOKEN   = (byte) 227;  // 0xE3
    /** TDS done token. */
    private static final byte TDS_DONE_TOKEN        = (byte) 253;  // 0xFD DONE
    /** TDS done procedure token. */
    private static final byte TDS_DONEPROC_TOKEN    = (byte) 254;  // 0xFE DONEPROC
    /** TDS done in procedure token. */
    private static final byte TDS_DONEINPROC_TOKEN  = (byte) 255;  // 0xFF DONEINPROC

    //
    // Environment change payload codes
    //
    /** Environment change: database changed. */
    private static final byte TDS_ENV_DATABASE      = (byte) 1;
    /** Environment change: language changed. */
    private static final byte TDS_ENV_LANG          = (byte) 2;
    /** Environment change: charset changed. */
    private static final byte TDS_ENV_CHARSET       = (byte) 3;
    /** Environment change: network packet size changed. */
    private static final byte TDS_ENV_PACKSIZE      = (byte) 4;
    /** Environment change: locale changed. */
    private static final byte TDS_ENV_LCID          = (byte) 5;
    /** Environment change: TDS 8 collation changed. */
    private static final byte TDS_ENV_SQLCOLLATION  = (byte) 7; // TDS8 Collation

    //
    // End token status bytes
    //
    /** Done: more results are expected. */
    private static final byte DONE_MORE_RESULTS     = (byte) 0x01;
    /** Done: command caused an error. */
    private static final byte DONE_ERROR            = (byte) 0x02;
    /** Done: There is a valid row count. */
    private static final byte DONE_ROW_COUNT        = (byte) 0x10;
    /** Done: Cancel acknowledgement. */
    static final byte DONE_CANCEL                   = (byte) 0x20;
    /**
     * Done: Response terminator (if more than one request packet is sent, each
     * response is terminated by a DONE packet with this flag set).
     */
    private static final byte DONE_END_OF_RESPONSE  = (byte) 0x80;

    //
    // Class variables
    //
    /** Name of the client host (it can take quite a while to find it out if DNS is configured incorrectly). */
    private static String hostName = null;

    //
    // Instance variables
    //
    /** The Connection object that created this object. */
    private ConnectionJDBC2 connection;
    /** The TDS version being supported by this connection. */
    private int tdsVersion;
    /** The Shared network socket object. */
    private SharedSocket socket;
    /** The output server request stream. */
    private RequestStream out;
    /** The input server response stream. */
    private ResponseStream in;
    /** True if the server response is fully read. */
    private boolean endOfResponse = true;
    /** True if the current result set is at end of file. */
    private boolean endOfResults  = true;
    /** The array of column meta data objects for this result set. */
    private ColInfo[] columns;
    /** The array of column data objects in the current row. */
    private Object[] rowData;
    /** The array of table names associated with this result. */
    private TableMetaData[] tables;
    /** The descriptor object for the current TDS token. */
    private TdsToken currentToken = new TdsToken();
    /** The stored procedure return status. */
    private Integer returnStatus;
    /** The return parameter meta data object for the current procedure call. */
    private ParamInfo returnParam;
    /** The array of parameter meta data objects for the current procedure call. */
    private ParamInfo[] parameters;
    /** The index of the next output parameter to populate. */
    private int nextParam = -1;
    /** The head of the diagnostic messages chain. */
    private SQLDiagnostic messages;
    /** Indicates that this object is closed. */
    private boolean isClosed;
    /** Indicates that a fatal error has occured and the connection will close. */
    private boolean fatalError;
    /** Mutual exclusion lock on connection. */
    private Semaphore connectionLock;
    /** Indicates type of SSL connection. */
    private int sslMode = SSL_NO_ENCRYPT;
    /** Indicates pending cancel that needs to be cleared. */
    private boolean cancelPending;
    /** Synchronization monitor for {@link #cancelPending}. */
    private Object cancelMonitor = new Object();

    /**
     * Construct a TdsCore object.
     *
     * @param connection The connection which owns this object.
     * @param messages The SQLDiagnostic messages chain.
     */
    TdsCore(ConnectionJDBC2 connection, SQLDiagnostic messages) {
        this.connection = connection;
        this.socket = connection.getSocket();
        this.messages = messages;
        tdsVersion = socket.getTdsVersion();
        out = socket.getRequestStream();
        in = socket.getResponseStream(out);
        out.setBufferSize(connection.getNetPacketSize());
        out.setMaxPrecision(connection.getMaxPrecision());
    }

    /**
     * Check that the connection is still open.
     *
     * @throws SQLException
     */
    private void checkOpen() throws SQLException {
        if (connection.isClosed()) {
            throw new SQLException(
                Messages.get("error.generic.closed", "Connection"),
                    "HY010");
        }
    }

    /**
     * Retrieve the TDS protocol version.
     *
     * @return The protocol version as an <code>int</code>.
     */
    int getTdsVersion() {
       return tdsVersion;
    }

    /**
     * Retrieve the current result set column descriptors.
     *
     * @return The column descriptors as a <code>ColInfo[]</code>.
     */
    ColInfo[] getColumns() {
        return columns;
    }

    /**
     * Retrieve the current result set data items.
     *
     * @return the row data as an <code>Object</code> array
     */
    Object[] getRowData() {
        return rowData;
    }

    /**
     * Negotiate SSL settings with SQL 2000+ server.
     * <p/>
     * Server returns the following values for SSL mode:
     * <ol>
     * <ll>0 = Certificate installed encrypt login packet only.
     * <li>1 = Certificate installed client requests force encryption.
     * <li>2 = No certificate no encryption possible.
     * <li>3 = Server requests force encryption.
     * </ol>
     * @param ssl The SSL URL property value.
     * @throws IOException
     */
    void negotiateSSL(String ssl)
            throws IOException, SQLException {
        if (!ssl.equalsIgnoreCase(Ssl.SSL_OFF)) {
            if (ssl.equalsIgnoreCase(Ssl.SSL_REQUIRE) ||
                    ssl.equalsIgnoreCase(Ssl.SSL_AUTHENTICATE)) {
                sendPreLoginPacket(true);
                sslMode = readPreLoginPacket();
                if (sslMode != SSL_CLIENT_FORCE_ENCRYPT &&
                    sslMode != SSL_SERVER_FORCE_ENCRYPT) {
                    throw new SQLException(
                            Messages.get("error.ssl.encryptionoff"),
                            "08S01");
                }
            } else {
                sendPreLoginPacket(false);
                sslMode = readPreLoginPacket();
            }
            if (sslMode != SSL_NO_ENCRYPT) {
                socket.enableEncryption(ssl);
            }
        }
    }

    /**
     * Login to the SQL Server.
     *
     * @param serverName server host name
     * @param database   required database
     * @param user       user name
     * @param password   user password
     * @param charset    required server character set
     * @param appName    application name
     * @param progName   library name
     * @param wsid       workstation ID
     * @param language   language to use for server messages
     * @param macAddress client network MAC address
     * @throws SQLException if an error occurs
     */
    void login(final String serverName,
               final String database,
               final String user,
               final String password,
               final String charset,
               final String appName,
               final String progName,
               String wsid,
               final String language,
               final String macAddress)
        throws SQLException {
        try {
            if (wsid.length() == 0) {
                wsid = getHostName();
            }
            sendMSLoginPkt(serverName, database, user, password,
                    appName, progName, wsid, language,
                    macAddress);
            if (sslMode == SSL_ENCRYPT_LOGIN) {
                socket.disableEncryption();
            }
            nextToken();

            while (!endOfResponse) {
                nextToken();
            }

            messages.checkErrors();
        } catch (IOException ioe) {
            throw Support.linkException(
                new SQLException(
                       Messages.get(
                                "error.generic.ioerror", ioe.getMessage()),
                                    "08S01"), ioe);
        }
    }

    /**
     * Get the next result set or update count from the TDS stream.
     *
     * @return <code>boolean</code> if the next item is a result set.
     * @throws SQLException
     */
    boolean getMoreResults() throws SQLException {
        checkOpen();
        nextToken();

        while (!endOfResponse
               && !currentToken.isUpdateCount()
               && !currentToken.isResultSet()) {
            nextToken();
        }
        messages.checkErrors();

        //
        // Cursor opens are followed by TDS_TAB_INFO and TDS_COL_INFO
        // Process these now so that the column descriptors are updated.
        // Sybase wide result set headers are followed by a TDS_CONTROL_TOKEN
        // skip that as well.
        //
        if (currentToken.isResultSet()) {
            byte saveToken = currentToken.token;
            try {
                byte x = (byte) in.peek();

                while (   x == TDS_TABNAME_TOKEN
                       || x == TDS_COLINFO_TOKEN
                       || x == TDS_CONTROL_TOKEN) {
                    nextToken();
                    x = (byte)in.peek();
                }
            } catch (IOException e) {
                connection.setClosed();

                throw Support.linkException(
                    new SQLException(
                           Messages.get(
                                "error.generic.ioerror", e.getMessage()),
                                    "08S01"), e);
            }
            currentToken.token = saveToken;
        }

        messages.checkErrors();

        return currentToken.isResultSet();
    }

    /**
     * Retrieve the status of the next result item.
     *
     * @return <code>boolean</code> true if the next item is a result set.
     */
    boolean isResultSet() {
        return currentToken.isResultSet();
    }

    /**
     * Retrieve the status of the next result item.
     *
     * @return <code>boolean</code> true if the next item is row data.
     */
    boolean isRowData() {
        return currentToken.isRowData();
    }

    /**
     * Retrieve the status of the next result item.
     *
     * @return <code>boolean</code> true if the next item is an update count.
     */
    boolean isUpdateCount() {
        return currentToken.isUpdateCount();
    }

    /**
     * Retrieve the update count from the current TDS token.
     *
     * @return The update count as an <code>int</code>.
     */
    int getUpdateCount() {
        if (currentToken.isEndToken()) {
            return currentToken.updateCount;
        }

        return -1;
    }

    /**
     * Retrieve the status of the response stream.
     *
     * @return <code>boolean</code> true if the response has been entirely consumed
     */
    boolean isEndOfResponse() {
        return endOfResponse;
    }

    /**
     * Empty the server response queue.
     *
     * @throws SQLException if an error occurs
     */
    void clearResponseQueue() throws SQLException {
        checkOpen();
        while (!endOfResponse) {
            nextToken();
        }
    }

    /**
     * Consume packets from the server response queue up to (and including) the
     * first response terminator.
     *
     * @throws SQLException if an error occurs
     */
    void consumeOneResponse() throws SQLException {
        checkOpen();
        while (!endOfResponse) {
            nextToken();
            // If it's a response terminator, return
            if (currentToken.isEndToken()
                    && (currentToken.status & DONE_END_OF_RESPONSE) != 0) {
                return;
            }
        }
        messages.checkErrors();
    }

    /**
     * Retrieve the next data row from the result set.
     *
     * @return <code>boolean</code> - <code>false</code> if at end of results.
     */
    boolean getNextRow() throws SQLException {
        if (endOfResponse || endOfResults) {
            return false;
        }
        checkOpen();
        nextToken();

        // Will either be first or next data row or end.
        while (!currentToken.isRowData() && !currentToken.isEndToken()) {
            nextToken(); // Could be messages
        }

        messages.checkErrors();

        return currentToken.isRowData();
    }

    /**
     * Retrieve the status of result set.
     * <p>
     * This does a quick read ahead and is needed to support the isLast()
     * method in the ResultSet.
     *
     * @return <code>boolean</code> - <code>true</code> if there is more data
     *          in the result set.
     */
    boolean isDataInResultSet() throws SQLException {
        byte x;

        checkOpen();

        try {
            x = (endOfResponse) ? TDS_DONE_TOKEN : (byte) in.peek();

            while (x != TDS_ROW_TOKEN
                   && x != TDS_DONE_TOKEN
                   && x != TDS_DONEINPROC_TOKEN
                   && x != TDS_DONEPROC_TOKEN) {
                nextToken();
                x = (byte) in.peek();
            }

            messages.checkErrors();
        } catch (IOException e) {
            connection.setClosed();
            throw Support.linkException(
                new SQLException(
                       Messages.get(
                                "error.generic.ioerror", e.getMessage()),
                                    "08S01"), e);
        }

        return x == TDS_ROW_TOKEN;
    }

    /**
     * Retrieve the return status for the current stored procedure.
     *
     * @return The return status as an <code>Integer</code>.
     */
    Integer getReturnStatus() {
        return this.returnStatus;
    }

    /**
     * Inform the server that this connection is closing.
     * <p>
     * A no-op for Microsoft.
     */
    synchronized void closeConnection() {
    }

    /**
     * Close the TDSCore connection object and associated streams.
     *
     * @throws SQLException
     */
    void close() throws SQLException {
       if (!isClosed) {
           try {
               clearResponseQueue();
               out.close();
               in.close();
           } finally {
               isClosed = true;
           }
        }
    }

    /**
     * Send (only) one cancel packet to the server.
     */
    void cancel() {
        Semaphore mutex = null;
        try {
            mutex = connection.getMutex();
            mutex.acquire();
            synchronized (cancelMonitor) {
                if (!cancelPending && !endOfResponse) {
                    cancelPending = socket.cancel(out.getStreamId());
                }
            }
        } catch (InterruptedException e) {
            mutex = null;
        } finally {
            if (mutex != null) {
                mutex.release();
            }
        }
    }

    /**
     * Submit a simple SQL statement to the server and process all output.
     *
     * @param sql the statement to execute
     * @throws SQLException if an error is returned by the server
     */
    void submitSQL(String sql) throws SQLException {
        checkOpen();

        if (sql.length() == 0) {
            throw new IllegalArgumentException("submitSQL() called with empty SQL String");
        }

        executeSQL(sql, null, null, false, 0, -1, -1, true);
        clearResponseQueue();
        messages.checkErrors();
    }

    /**
     * Send an SQL statement with optional parameters to the server.
     *
     * @param sql          SQL statement to execute
     * @param procName     stored procedure to execute or <code>null</code>
     * @param parameters   parameters for call or null
     * @param noMetaData   suppress meta data for cursor calls
     * @param timeOut      optional query timeout or 0
     * @param maxRows      the maximum number of data rows to return (-1 to
     *                     leave unaltered)
     * @param maxFieldSize the maximum number of bytes in a column to return
     *                     (-1 to leave unaltered)
     * @param sendNow      whether to send the request now or not
     * @throws SQLException if an error occurs
     */
    synchronized void executeSQL(String sql,
                                 String procName,
                                 ParamInfo[] parameters,
                                 boolean noMetaData,
                                 int timeOut,
                                 int maxRows,
                                 int maxFieldSize,
                                 boolean sendNow)
            throws SQLException {
        boolean sendFailed = true; // Used to ensure mutex is released.

        try {
            //
            // Obtain a lock on the connection giving exclusive access
            // to the network connection for this thread
            //
            if (connectionLock == null) {
                connectionLock = connection.getMutex();
                try {
                    connectionLock.acquire();
                } catch (InterruptedException e) {
                    connectionLock = null;
                    throw new IllegalStateException("Connection synchronization failed");
                }
            }
            checkOpen();
            clearResponseQueue();
            messages.exceptions = null;

            //
            // Set the connection row count and text size if required.
            // Once set these will not be changed within a
            // batch so execution of the set rows query will
            // only occur once a the start of a batch.
            // No other thread can send until this one has finished.
            //
            setRowCountAndTextSize(maxRows, maxFieldSize);

            messages.clearWarnings();
            this.returnStatus = null;
            //
            // Normalize the parameters argument to simplify later checks
            //
            if (parameters != null && parameters.length == 0) {
                parameters = null;
            }
            this.parameters = parameters;
            //
            // Normalise the procName argument as well
            //
            if (procName != null && procName.length() == 0) {
                procName = null;
            }

            if (parameters != null && parameters[0].isRetVal) {
                returnParam = parameters[0];
                nextParam = 0;
            } else {
                returnParam = null;
                nextParam = -1;
            }

            if (parameters != null) {
                if (procName == null && sql.startsWith("EXECUTE ")) {
                    //
                    // If this is a callable statement that could not be fully parsed
                    // into an RPC call convert to straight SQL now.
                    // An example of non RPC capable SQL is {?=call sp_example('literal', ?)}
                    //
                    for (int i = 0; i < parameters.length; i++){
                        // Output parameters not allowed.
                        if (!parameters[i].isRetVal && parameters[i].isOutput){
                            throw new SQLException(Messages.get("error.prepare.nooutparam",
                                    Integer.toString(i + 1)), "07000");
                        }
                    }
                    sql = Support.substituteParameters(sql, parameters);
                    parameters = null;
                } else {
                    //
                    // Check all parameters are either output or have values set
                    //
                    for (int i = 0; i < parameters.length; i++){
                        if (!parameters[i].isSet && !parameters[i].isOutput){
                            throw new SQLException(Messages.get("error.prepare.paramnotset",
                                    Integer.toString(i + 1)), "07000");
                        }
                        parameters[i].clearOutValue();
                        // FIXME Should only set TDS type if not already set
                        // but we might need to take a lot of care not to
                        // exceed size limitations (e.g. write 11 chars in a
                        // VARCHAR(10) )
                        TdsData.getNativeType(connection, parameters[i]);
                    }
                }
            }

            try {
                switch (tdsVersion) {
                    case Driver.TDS70:
                    case Driver.TDS80:
                    case Driver.TDS81:
                        executeSQL70(sql, procName, parameters, noMetaData, sendNow);
                        break;
                    default:
                        throw new IllegalStateException("Unknown TDS version " + tdsVersion);
                }

                if (sendNow) {
                    out.flush();
                    connectionLock.release();
                    connectionLock = null;
                    sendFailed = false;
                    endOfResponse = false;
                    endOfResults  = true;
                    wait(timeOut);
                } else {
                    sendFailed = false;
                }
            } catch (IOException ioe) {
                connection.setClosed();

                throw Support.linkException(
                    new SQLException(
                           Messages.get(
                                    "error.generic.ioerror", ioe.getMessage()),
                                        "08S01"), ioe);
            }
        } finally {
            if ((sendNow || sendFailed) && connectionLock != null) {
                connectionLock.release();
                connectionLock = null;
            }
        }
    }

    /**
     * Obtain the counts from a batch of SQL updates.
     * <p/>
     * If an error occurs Sybase will continue processing a batch consisting of
     * TDS_LANGUAGE records whilst SQL Server will stop after the first error.
     * Sybase will also stop after the first error when executing RPC calls.
     * For Sybase only therefore, this method returns the JDBC3
     * <code>EXECUTE_FAILED</code> constant in the counts array when a
     * statement fails with an error. For Sybase, care is taken to ensure that
     * <code>SQLException</code>s are chained because there could be several
     * errors reported in a batch.
     *
     * @param counts the <code>ArrayList</code> containing the update counts
     * @param sqlEx  any previous <code>SQLException</code>(s) encountered
     * @return updated <code>SQLException</code> or <code>null</code> if no
     *         error has yet occured
     */
    SQLException getBatchCounts(ArrayList counts, SQLException sqlEx) {
        Integer lastCount = JtdsStatement.SUCCESS_NO_INFO;

        try {
            checkOpen();
            while (!endOfResponse) {
                nextToken();
                if (currentToken.isResultSet()) {
                    // Serious error, statement must not return a result set
                    throw new SQLException(
                            Messages.get("error.statement.batchnocount"),
                            "07000");
                }
                //
                // Analyse type of end token and try to extract correct
                // update count when calling stored procs.
                //
                switch (currentToken.token) {
                    case TDS_DONE_TOKEN:
                        if ((currentToken.status & DONE_ERROR) == 0
                                && lastCount != JtdsStatement.EXECUTE_FAILED) {
                            if (currentToken.isUpdateCount()) {
                                counts.add(new Integer(currentToken.updateCount));
                            } else {
                                counts.add(lastCount);
                            }
                        }
                        lastCount = JtdsStatement.SUCCESS_NO_INFO;
                        break;
                    case TDS_DONEINPROC_TOKEN:
                        if ((currentToken.status & DONE_ERROR) != 0) {
                            lastCount = JtdsStatement.EXECUTE_FAILED;
                        } else if (currentToken.isUpdateCount()) {
                            lastCount = new Integer(currentToken.updateCount);
                        }
                        break;
                    case TDS_DONEPROC_TOKEN:
                        if ((currentToken.status & DONE_ERROR) == 0
                                && lastCount != JtdsStatement.EXECUTE_FAILED) {
                            counts.add(lastCount);
                        }
                        lastCount = JtdsStatement.SUCCESS_NO_INFO;
                        break;
                }
            }
            //
            // Check for any exceptions
            //
            messages.checkErrors();

        } catch (SQLException e) {
            //
            // Chain all exceptions
            //
            if (sqlEx != null) {
                sqlEx.setNextException(e);
            } else {
                sqlEx = e;
            }
        } finally {
            while (!endOfResponse) {
                // Flush rest of response
                try {
                    nextToken();
                } catch (SQLException ex) {
                    // Chain any exceptions to the BatchUpdateException
                    if (sqlEx != null) {
                        sqlEx.setNextException(ex);
                    } else {
                        sqlEx = ex;
                    }
                }
            }
        }

        return sqlEx;
    }

// ---------------------- Private Methods from here ---------------------

    /**
     * Send the SQL Server 2000 pre login packet.
     * <p>Packet contains; netlib version, ssl mode, instance
     * and process ID.
     * @param forceEncryption
     * @throws IOException
     */
    private void sendPreLoginPacket(boolean forceEncryption)
            throws IOException {
        out.setPacketType(PRELOGIN_PKT);
        // Write Netlib pointer
        out.write((short)0);
        out.write((short)21);
        out.write((byte)6);
        // Write Encrypt flag pointer
        out.write((short)1);
        out.write((short)27);
        out.write((byte)1);
        // Write Instance name pointer
        out.write((short)2);
        out.write((short)28);
        out.write((byte)1);
        // Write process ID pointer
        out.write((short)3);
        out.write((short)(29));
        out.write((byte)4);
        // Write terminator
        out.write((byte)0xFF);
        // Write fake net lib ID 8.341.0
        out.write(new byte[]{0x08, 0x00, 0x01, 0x55, 0x00, 0x00});
        // Write force encryption flag
        out.write((byte)(forceEncryption? 1: 0));
        // Write instance name
        out.write((byte)0);
        // Write dummy process ID
        out.write(new byte[]{0x01, 0x02, 0x00, 0x00});
        //
        out.flush();
    }

    /**
     * Process the pre login acknowledgement from the server.
     * <p>Packet contains; server version no, SSL mode, instance name
     * and process id.
     * <p>Server returns the following values for SSL mode:
     * <ol>
     * <ll>0 = Certificate installed encrypt login packet only.
     * <li>1 = Certificate installed client requests force encryption.
     * <li>2 = No certificate no encryption possible.
     * <li>3 = Server requests force encryption.
     * </ol>
     * @return The server side SSL mode.
     * @throws IOException
     */
    private int readPreLoginPacket() throws IOException {
        byte list[][] = new byte[8][];
        byte data[][] = new byte[8][];
        int recordCount = 0;

        byte record[] = new byte[5];
        // Read entry pointers
        record[0] = (byte)in.read();
        while ((record[0] & 0xFF) != 0xFF) {
            if (recordCount == list.length) {
                throw new IOException("Pre Login packet has more than 8 entries");
            }
            // Read record
            in.read(record, 1, 4);
            list[recordCount++] = record;
            record = new byte[5];
            record[0] = (byte)in.read();
        }
        // Read entry data
        for (int i = 0; i < recordCount; i++) {
            byte value[] = new byte[(byte)list[i][4]];
            in.read(value);
            data[i] = value;
        }
        if (Logger.isActive()) {
            // Diagnostic dump
            Logger.println("PreLogin server response");
            for (int i = 0; i < recordCount; i++) {
                Logger.println("Record " + i+ " = " +
                        Support.toHex(data[i]));
            }
        }
        if (recordCount > 1) {
            return data[1][0]; // This is the server side SSL mode
        } else {
            // Response too short to include SSL mode!
            return SSL_NO_ENCRYPT;
        }
    }

    /**
     * Send a TDS 7 login packet.
     * <p>
     * This method incorporates the Windows single sign on code contributed by
     * Magendran Sathaiah. To invoke single sign on just leave the user name
     * blank or null. NB. This can only work if the driver is being executed on
     * a Windows PC and <code>ntlmauth.dll</code> is on the path.
     *
     * @param serverName    server host name
     * @param database      required database
     * @param user          user name
     * @param password      user password
     * @param appName       application name
     * @param progName      program name
     * @param wsid          workstation ID
     * @param language      server language for messages
     * @param macAddress    client network MAC address
     * @throws IOException if an I/O error occurs
     */
    private void sendMSLoginPkt(final String serverName,
                                final String database,
                                final String user,
                                final String password,
                                final String appName,
                                final String progName,
                                final String wsid,
                                final String language,
                                final String macAddress)
            throws IOException, SQLException {
        final byte[] empty = new byte[0];

        if (user == null || user.length() == 0) {
            throw new SQLException(Messages.get("error.connection.sso"),
                    "08001");
        }

        short packSize = (short) (86 + 2 *
                (wsid.length() +
                appName.length() +
                serverName.length() +
                progName.length() +
                database.length() +
                language.length() +
                user.length() +
                password.length()));

        out.setPacketType(MSLOGIN_PKT);
        out.write((int)packSize);
        // TDS version
        if (tdsVersion == Driver.TDS70) {
            out.write((int)0x70000000);
        } else {
            out.write((int)0x71000001);
        }
        // Network Packet size requested by client; default
        out.write((int)0);
        // Program version?
        out.write((int)7);
        // Process ID
        out.write((int)123);
        // Connection ID
        out.write((int)0);
        // 0x20: enable warning messages if USE <database> issued
        // 0x40: change to initial database must succeed
        // 0x80: enable warning messages if SET LANGUAGE issued
        byte flags = (byte) (0x20 | 0x40 | 0x80);
        out.write(flags);

        //mdb: this byte controls what kind of auth we do.
        flags = 0x03; // ODBC (JDBC) driver
        out.write(flags);

        out.write((byte)0); // SQL type flag
        out.write((byte)0); // Reserved flag
        // TODO Set Timezone and collation?
        out.write(empty, 0, 4); // Time Zone
        out.write(empty, 0, 4); // Collation

        // Pack up value lengths, positions.
        short curPos = 86;

        // Hostname
        out.write((short)curPos);
        out.write((short) wsid.length());
        curPos += wsid.length() * 2;

        // Username
        out.write((short)curPos);
        out.write((short) user.length());
        curPos += user.length() * 2;

        // Password
        out.write((short)curPos);
        out.write((short) password.length());
        curPos += password.length() * 2;

        // App name
        out.write((short)curPos);
        out.write((short) appName.length());
        curPos += appName.length() * 2;

        // Server name
        out.write((short)curPos);
        out.write((short) serverName.length());
        curPos += serverName.length() * 2;

        // Unknown
        out.write((short) 0);
        out.write((short) 0);

        // Program name
        out.write((short)curPos);
        out.write((short) progName.length());
        curPos += progName.length() * 2;

        // Server language
        out.write((short)curPos);
        out.write((short) language.length());
        curPos += language.length() * 2;

        // Database
        out.write((short)curPos);
        out.write((short) database.length());
        curPos += database.length() * 2;

        // MAC address
        out.write(getMACAddress(macAddress));

        // Location of NTLM auth block
        out.write((short)curPos);
        out.write((short)0);

        //"next position" (same as total packet size)
        out.write((int)packSize);

        out.write(wsid);

        // Pack up the login values.
        final String scrambledPw = tds7CryptPass(password);
        out.write(user);
        out.write(scrambledPw);

        out.write(appName);
        out.write(serverName);
        out.write(progName);
        out.write(language);
        out.write(database);

        out.flush(); // Send the packet
        endOfResponse = false;
    }

    /**
     * Read the next TDS token from the response stream.
     *
     * @throws SQLException if an I/O or protocol error occurs
     */
    private void nextToken()
        throws SQLException
    {
        checkOpen();
        if (endOfResponse) {
            currentToken.token  = TDS_DONE_TOKEN;
            currentToken.status = 0;
            return;
        }
        try {
            currentToken.token = (byte)in.read();
            switch (currentToken.token) {
                case TDS_RETURNSTATUS_TOKEN:
                    tdsReturnStatusToken();
                    break;
                case TDS_PROCID:
                    tdsProcIdToken();
                    break;
                case TDS_OFFSETS_TOKEN:
                    tdsOffsetsToken();
                    break;
                case TDS7_RESULT_TOKEN:
                    tds7ResultToken();
                    break;
                case TDS7_COMP_RESULT_TOKEN:
                    tdsInvalidToken();
                    break;
                case TDS_TABNAME_TOKEN:
                    tdsTableNameToken();
                    break;
                case TDS_COLINFO_TOKEN:
                    tdsColumnInfoToken();
                    break;
                case TDS_COMP_NAMES_TOKEN:
                    tdsInvalidToken();
                    break;
                case TDS_COMP_RESULT_TOKEN:
                    tdsInvalidToken();
                    break;
                case TDS_ORDER_TOKEN:
                    tdsOrderByToken();
                    break;
                case TDS_ERROR_TOKEN:
                case TDS_INFO_TOKEN:
                    tdsErrorToken();
                    break;
                case TDS_PARAM_TOKEN:
                    tdsOutputParamToken();
                    break;
                case TDS_LOGINACK_TOKEN:
                    tdsLoginAckToken();
                    break;
                case TDS_CONTROL_TOKEN:
                    tdsControlToken();
                    break;
                case TDS_ROW_TOKEN:
                    tdsRowToken();
                    break;
                case TDS_ALTROW:
                    tdsInvalidToken();
                    break;
                case TDS_ENVCHANGE_TOKEN:
                    tdsEnvChangeToken();
                    break;
                case TDS_DONE_TOKEN:
                case TDS_DONEPROC_TOKEN:
                case TDS_DONEINPROC_TOKEN:
                    tdsDoneToken();
                    break;
                default:
                    throw new ProtocolException(
                            "Invalid packet type 0x" +
                                Integer.toHexString((int) currentToken.token & 0xFF));
            }
        } catch (IOException ioe) {
            connection.setClosed();
            throw Support.linkException(
                new SQLException(
                       Messages.get(
                                "error.generic.ioerror", ioe.getMessage()),
                                    "08S01"), ioe);
        } catch (ProtocolException pe) {
            connection.setClosed();
            throw Support.linkException(
                new SQLException(
                       Messages.get(
                                "error.generic.tdserror", pe.getMessage()),
                                    "08S01"), pe);
        } catch (OutOfMemoryError err) {
            // Consume the rest of the response
            in.skipToEnd();
            endOfResponse = true;
            endOfResults = true;
            cancelPending = false;
            throw err;
        }
    }

    /**
     * Report unsupported TDS token in input stream.
     *
     * @throws IOException
     */
    private void tdsInvalidToken()
        throws IOException, ProtocolException
    {
        in.skip(in.readShort());
        throw new ProtocolException("Unsupported TDS token: 0x" +
                            Integer.toHexString((int) currentToken.token & 0xFF));
    }

    /**
     * Process stored procedure return status token.
     *
     * @throws IOException
     */
    private void tdsReturnStatusToken() throws IOException, SQLException {
        returnStatus = new Integer(in.readInt());
        if (this.returnParam != null) {
            returnParam.setOutValue(Support.convert(this.connection,
                    returnStatus,
                    returnParam.jdbcType,
                    connection.getCharset()));
        }
    }

    /**
     * Process procedure ID token.
     * <p>
     * Used by DBLIB to obtain the object id of a stored procedure.
     */
    private void tdsProcIdToken() throws IOException {
        in.skip(8);
    }

    /**
     * Process offsets token.
     * <p>
     * Used by DBLIB to return the offset of various keywords in a statement.
     * This saves the client from having to parse a SQL statement. Enabled with
     * <code>&quot;set offsets from on&quot;</code>.
     */
    private void tdsOffsetsToken() throws IOException {
        /*int keyword =*/ in.read();
        /*int unknown =*/ in.read();
        /*int offset  =*/ in.readShort();
    }

    /**
     * Process a TDS 7.0 result set token.
     *
     * @throws IOException
     * @throws ProtocolException
     */
    private void tds7ResultToken()
            throws IOException, ProtocolException, SQLException {
        endOfResults = false;

        int colCnt = in.readShort();

        if (colCnt < 0) {
            // Short packet returned by TDS8 when the column meta data is
            // supressed on cursor fetch etc.
            // NB. With TDS7 no result set packet is returned at all.
            return;
        }

        this.columns = new ColInfo[colCnt];
        this.rowData = new Object[colCnt];
        this.tables = null;

        for (int i = 0; i < colCnt; i++) {
            ColInfo col = new ColInfo();

            col.userType = in.readShort();

            int flags = in.readShort();

            col.nullable = ((flags & 0x01) != 0) ?
                                ResultSetMetaData.columnNullable :
                                ResultSetMetaData.columnNoNulls;
            col.isCaseSensitive = (flags & 0X02) != 0;
            col.isIdentity = (flags & 0x10) != 0;
            col.isWriteable = (flags & 0x0C) != 0;
            TdsData.readType(in, col);
            // Set the charsetInfo field of col
            if (tdsVersion >= Driver.TDS80 && col.collation != null) {
                TdsData.setColumnCharset(col, connection);
            }

            int clen = in.read();

            col.realName = in.readUnicodeString(clen);
            col.name = col.realName;

            this.columns[i] = col;
        }
    }

    /**
     * Process a table name token.
     * <p> Sent by select for browse or cursor functions.
     *
     * @throws IOException
     */
    private void tdsTableNameToken() throws IOException, ProtocolException {
        final int pktLen = in.readShort();
        int bytesRead = 0;
        ArrayList tableList = new ArrayList();

        while (bytesRead < pktLen) {
            int    nameLen;
            String tabName;
            TableMetaData table;
            if (tdsVersion >= Driver.TDS81) {
                // TDS8.1 supplies the database.owner.table as three separate
                // components which allows us to have names with embedded
                // periods.
                // Can't think why anyone would want that!
                table = new TableMetaData();
                bytesRead++;
                switch (in.read()) {
                    case 3: nameLen = in.readShort();
                            bytesRead += nameLen * 2 + 2;
                            table.catalog = in.readUnicodeString(nameLen);
                    case 2: nameLen = in.readShort();
                            bytesRead += nameLen * 2 + 2;
                            table.schema = in.readUnicodeString(nameLen);
                    case 1: nameLen = in.readShort();
                            bytesRead += nameLen * 2 + 2;
                            table.name = in.readUnicodeString(nameLen);
                    case 0: break;
                    default:
                        throw new ProtocolException("Invalid table TAB_NAME_TOKEN");
                }
            } else {
                nameLen = in.readShort();
                bytesRead += nameLen * 2 + 2;
                tabName  = in.readUnicodeString(nameLen);

                table = new TableMetaData();
                // tabName can be a fully qualified name
                int dotPos = tabName.lastIndexOf('.');
                if (dotPos > 0) {
                    table.name = tabName.substring(dotPos + 1);

                    int nextPos = tabName.lastIndexOf('.', dotPos-1);
                    if (nextPos + 1 < dotPos) {
                        table.schema = tabName.substring(nextPos + 1, dotPos);
                    }
                    dotPos = nextPos;
                    nextPos = tabName.lastIndexOf('.', dotPos-1);
                    if (nextPos + 1 < dotPos) {
                        table.catalog = tabName.substring(nextPos + 1, dotPos);
                    }
                } else {
                    table.name = tabName;
                }
            }
            tableList.add(table);
        }
        if (tableList.size() > 0) {
            this.tables = (TableMetaData[]) tableList.toArray(new TableMetaData[tableList.size()]);
        }
    }

    /**
     * Process a column infomation token.
     * <p>Sent by select for browse or cursor functions.
     * @throws IOException
     * @throws ProtocolException
     */
    private void tdsColumnInfoToken()
        throws IOException, ProtocolException
    {
        final int pktLen = in.readShort();
        int bytesRead = 0;
        int columnIndex = 0;

        // In some cases (e.g. if the user calls 'CREATE CURSOR', the
        // TDS_TABNAME packet seems to be missing. Weird.
        if (tables == null) {
            in.skip(pktLen);
        } else {
            while (bytesRead < pktLen) {
                // Seems like all columns are always returned in the COL_INFO
                // packet and there might be more than 255 columns, so we'll
                // just increment a counter instead.
                // Ignore the column index.
                in.read();
                if (columnIndex >= columns.length) {
                    throw new ProtocolException("Column index " + (columnIndex + 1) +
                                                     " invalid in TDS_COLINFO packet");
                }
                ColInfo col = columns[columnIndex++];
                int tableIndex = in.read();
                if (tableIndex > tables.length) {
                    throw new ProtocolException("Table index " + tableIndex +
                                                     " invalid in TDS_COLINFO packet");
                }
                byte flags = (byte)in.read(); // flags
                bytesRead += 3;

                if (tableIndex != 0) {
                    TableMetaData table = tables[tableIndex-1];
                    col.catalog   = table.catalog;
                    col.schema    = table.schema;
                    col.tableName = table.name;
                }

                col.isKey           = (flags & 0x08) != 0;
                col.isHidden        = (flags & 0x10) != 0;

                // If bit 5 is set, we have a column name
                if ((flags & 0x20) != 0) {
                    final int nameLen = in.read();
                    bytesRead += 1;
                    final String colName = in.readString(nameLen);
                    // FIXME This won't work with multi-byte charsets
                    bytesRead += nameLen * 2;
                    col.realName = colName;
                }
            }
        }
    }

    /**
     * Process an order by token.
     * <p>Sent to describe columns in an order by clause.
     * @throws IOException
     */
    private void tdsOrderByToken()
        throws IOException
    {
        // Skip this packet type
        int pktLen = in.readShort();
        in.skip(pktLen);
    }

    /**
     * Process a TD4/TDS7 error or informational message.
     *
     * @throws IOException
     */
    private void tdsErrorToken()
    throws IOException
    {
        int pktLen = in.readShort(); // Packet length
        int sizeSoFar = 6;
        int number = in.readInt();
        int state = in.read();
        int severity = in.read();
        int msgLen = in.readShort();
        String message = in.readString(msgLen);
        sizeSoFar += 2 + msgLen * 2;
        final int srvNameLen = in.read();
        String server = in.readString(srvNameLen);
        sizeSoFar += 1 + srvNameLen * 2;

        final int procNameLen = in.read();
        String procName = in.readString(procNameLen);
        sizeSoFar += 1 + procNameLen * 2;

        int line = in.readShort();
        sizeSoFar += 2;
        // FIXME This won't work with multi-byte charsets
        // Skip any EED information to read rest of packet
        if (pktLen - sizeSoFar > 0)
            in.skip(pktLen - sizeSoFar);

        if (currentToken.token == TDS_ERROR_TOKEN)
        {
            if (severity < 10) {
                severity = 11; // Ensure treated as error
            }
            if (severity >= 20) {
                // A fatal error has occured, the connection will be closed by
                // the server immediately after the last TDS_DONE packet
                fatalError = true;
            }
        } else {
            if (severity > 9) {
                severity = 9; // Ensure treated as warning
            }
        }
        messages.addDiagnostic(number, state, severity,
                message, server, procName, line);
    }

    /**
     * Process output parameters.
     *
     * @throws IOException
     * @throws ProtocolException
     */
    private void tdsOutputParamToken()
        throws IOException, ProtocolException, SQLException {
        in.readShort(); // Packet length
        String name = in.readString(in.read()); // Column Name
        in.skip(5);

        ColInfo col = new ColInfo();
        TdsData.readType(in, col);
        // Set the charsetInfo field of col
        if (tdsVersion >= Driver.TDS80 && col.collation != null) {
            TdsData.setColumnCharset(col, connection);
        }
        Object value = TdsData.readData(connection, in, col);

        //
        // Real output parameters will either be unnamed or will have a valid
        // parameter name beginning with '@'. Ignore any other spurious parameters
        // such as those returned from calls to writetext in the proc.
        //
        if (parameters != null
                && (name.length() == 0 || name.startsWith("@"))) {
            if (tdsVersion >= Driver.TDS80
                && returnParam != null
                && !returnParam.isSetOut) {
                // TDS 8 Allows function return values of types other than int
                if (value != null) {
                    parameters[nextParam].setOutValue(
                        Support.convert(connection, value,
                                parameters[nextParam].jdbcType,
                                connection.getCharset()));
                    parameters[nextParam].collation = col.collation;
                    parameters[nextParam].charsetInfo = col.charsetInfo;
                } else {
                    parameters[nextParam].setOutValue(null);
                }
            } else {
                // Look for next output parameter in list
                while (++nextParam < parameters.length) {
                    if (parameters[nextParam].isOutput) {
                        if (value != null) {
                            parameters[nextParam].setOutValue(
                                Support.convert(connection, value,
                                        parameters[nextParam].jdbcType,
                                        connection.getCharset()));
                            parameters[nextParam].collation = col.collation;
                            parameters[nextParam].charsetInfo = col.charsetInfo;
                        } else {
                            parameters[nextParam].setOutValue(null);
                        }
                        break;
                    }
                }
            }
        }
    }

    /**
     * Process a login acknowledgement packet.
     *
     * @throws IOException
     */
    private void tdsLoginAckToken() throws IOException {
        String product;
        int major, minor, build = 0;
        in.readShort(); // Packet length

        in.read(); // Ack TDS 5 = 5 for OK 6 for fail, 1/0 for the others

        // Update the TDS protocol version in this TdsCore and in the Socket.
        // The Connection will update itself immediately after this call.
        // As for other objects containing a TDS version value, there are none
        // at this point (we're just constructing the Connection).
        tdsVersion = TdsData.getTdsVersion(((int) in.read() << 24) | ((int) in.read() << 16)
                | ((int) in.read() << 8) | (int) in.read());
        socket.setTdsVersion(tdsVersion);

        product = in.readString(in.read());

        major = in.read();
        minor = in.read();
        build = in.read() << 8;
        build += in.read();

        if (product.length() > 1 && -1 != product.indexOf('\0')) {
            product = product.substring(0, product.indexOf('\0'));
        }

        connection.setDBServerInfo(product, major, minor, build);
    }

    /**
     * Process a control token (function unknown).
     *
     * @throws IOException
     */
    private void tdsControlToken() throws IOException {
        int pktLen = in.readShort();

        in.skip(pktLen);
    }

    /**
     * Process a row data token.
     *
     * @throws IOException
     * @throws ProtocolException
     */
    private void tdsRowToken() throws IOException, ProtocolException {
        for (int i = 0; i < columns.length; i++) {
            rowData[i] =  TdsData.readData(connection, in, columns[i]);
        }

        endOfResults = false;
    }

    /**
     * Process an environment change packet.
     *
     * @throws IOException
     * @throws SQLException
     */
    private void tdsEnvChangeToken()
        throws IOException, SQLException
    {
        int len = in.readShort();
        int type = in.read();

        switch (type) {
            case TDS_ENV_DATABASE:
                {
                    int clen = in.read();
                    final String newDb = in.readString(clen);
                    clen = in.read();
                    final String oldDb = in.readString(clen);
                    connection.setDatabase(newDb, oldDb);
                    break;
                }

            case TDS_ENV_LANG:
                {
                    int clen = in.read();
                    String language = in.readString(clen);
                    clen = in.read();
                    String oldLang = in.readString(clen);
                    if (Logger.isActive()) {
                        Logger.println("Language changed from " + oldLang + " to " + language);
                    }
                    break;
                }

            case TDS_ENV_CHARSET:
                {
                    final int clen = in.read();
                    final String charset = in.readString(clen);
                    in.skip(len - 2 - clen * 2);
                    connection.setServerCharset(charset);
                    break;
                }

            case TDS_ENV_PACKSIZE:
                    {
                        final int blocksize;
                        final int clen = in.read();
                        blocksize = Integer.parseInt(in.readString(clen));
                        in.skip(len - 2 - clen * 2);
                        this.connection.setNetPacketSize(blocksize);
                        out.setBufferSize(blocksize);
                        if (Logger.isActive()) {
                            Logger.println("Changed blocksize to " + blocksize);
                        }
                    }
                    break;

            case TDS_ENV_LCID:
                    // Only sent by TDS 7
                    // In TDS 8 replaced by column specific collation info.
                    // TODO Make use of this for character set conversions?
                    in.skip(len - 1);
                    break;

            case TDS_ENV_SQLCOLLATION:
                {
                    int clen = in.read();
                    byte collation[] = new byte[5];
                    if (clen == 5) {
                        in.read(collation);
                        connection.setCollation(collation);
                    } else {
                        in.skip(clen);
                    }
                    clen = in.read();
                    in.skip(clen);
                    break;
                }

            default:
                {
                    if (Logger.isActive()) {
                        Logger.println("Unknown environment change type 0x" +
                                            Integer.toHexString(type));
                    }
                    in.skip(len - 1);
                    break;
                }
        }
    }

    /**
     * Process a DONE, DONEINPROC or DONEPROC token.
     *
     * @throws IOException
     */
    private void tdsDoneToken() throws IOException {
        currentToken.status = (byte)in.read();
        in.skip(1);
        currentToken.operation = (byte)in.read();
        in.skip(1);
        currentToken.updateCount = in.readInt();

        if (!endOfResults) {
            // This will eliminate the select row count for sybase
            currentToken.status &= ~DONE_ROW_COUNT;
            endOfResults = true;
        }

        //
        // Check for cancel ack
        //
        if ((currentToken.status & DONE_CANCEL) != 0) {
            // Synchronize setting of the cancelPending flag to ensure it
            // doesn't happen during the sending of a cancel request
            synchronized (cancelMonitor) {
                cancelPending = false;
            }
            // Indicates cancel packet
            messages.addException(
                     new SQLException("Request cancelled", "S1008", 0));
        }

        if ((currentToken.status & DONE_MORE_RESULTS) == 0) {
            //
            // There are no more results or pending cancel packets
            // to process.
            //
            endOfResponse = !cancelPending;

            if (fatalError) {
                // A fatal error has occured, the server has closed the
                // connection
                connection.setClosed();
            }
        }

        //
        // MS SQL Server provides additional information we
        // can use to return special row counts for DDL etc.
        //
        if (currentToken.operation == (byte) 0xC1) {
            currentToken.status &= ~DONE_ROW_COUNT;
        }
    }

    /**
     * Map of system stored procedures that have shortcuts in TDS8.
     */
    private static HashMap tds8SpNames = new HashMap();
    static {
        tds8SpNames.put("sp_cursor",            new Integer(1));
        tds8SpNames.put("sp_cursoropen",        new Integer(2));
        tds8SpNames.put("sp_cursorprepare",     new Integer(3));
        tds8SpNames.put("sp_cursorexecute",     new Integer(4));
        tds8SpNames.put("sp_cursorprepexec",    new Integer(5));
        tds8SpNames.put("sp_cursorunprepare",   new Integer(6));
        tds8SpNames.put("sp_cursorfetch",       new Integer(7));
        tds8SpNames.put("sp_cursoroption",      new Integer(8));
        tds8SpNames.put("sp_cursorclose",       new Integer(9));
        tds8SpNames.put("sp_executesql",        new Integer(10));
        tds8SpNames.put("sp_prepare",           new Integer(11));
        tds8SpNames.put("sp_execute",           new Integer(12));
        tds8SpNames.put("sp_prepexec",          new Integer(13));
        tds8SpNames.put("sp_prepexecrpc",       new Integer(14));
        tds8SpNames.put("sp_unprepare",         new Integer(15));
    }

    /**
     * Execute SQL using TDS 7.0 protocol.
     *
     * @param sql The SQL statement to execute.
     * @param procName Stored procedure to execute or <code>null</code>.
     * @param parameters Parameters for call or <code>null</code>.
     * @param noMetaData Suppress meta data for cursor calls.
     * @throws SQLException
     */
    private void executeSQL70(String sql,
                              String procName,
                              ParamInfo[] parameters,
                              boolean noMetaData,
                              boolean sendNow)
        throws IOException, SQLException {

        if (procName == null) {
            if (parameters != null) {
                ParamInfo[] params;

                params = new ParamInfo[2 + parameters.length];
                System.arraycopy(parameters, 0, params, 2, parameters.length);

                params[0] = new ParamInfo(Types.LONGVARCHAR,
                        Support.substituteParamMarkers(sql, parameters),
                        ParamInfo.UNICODE);
                TdsData.getNativeType(connection, params[0]);

                params[1] = new ParamInfo(Types.LONGVARCHAR,
                        Support.getParameterDefinitions(parameters),
                        ParamInfo.UNICODE);
                TdsData.getNativeType(connection, params[1]);

                parameters = params;

                // Use sp_executesql approach
                procName = "sp_executesql";
            }
        }

        if (procName != null) {
            // RPC call
            out.setPacketType(RPC_PKT);
            Integer shortcut;

            if (tdsVersion >= Driver.TDS80
                    && (shortcut = (Integer) tds8SpNames.get(procName)) != null) {
                // Use the shortcut form of procedure name for TDS8
                out.write((short) -1);
                out.write((short) shortcut.shortValue());
            } else {
                out.write((short) procName.length());
                out.write(procName);
            }

            out.write((short) (noMetaData ? 2 : 0));

            if (parameters != null) {
                for (int i = nextParam + 1; i < parameters.length; i++) {
                    if (parameters[i].name != null) {
                       out.write((byte) parameters[i].name.length());
                       out.write(parameters[i].name);
                    } else {
                       out.write((byte) 0);
                    }

                    out.write((byte) (parameters[i].isOutput ? 1 : 0));

                    TdsData.writeParam(out,
                            connection.getCharsetInfo(),
                            connection.getCollation(),
                            parameters[i]);
                }
            }
            if (!sendNow) {
                // Append RPC packets
                out.write((byte) DONE_END_OF_RESPONSE);
            }
        } else if (sql.length() > 0) {
            // Simple query
            out.setPacketType(QUERY_PKT);
            out.write(sql);
            if (!sendNow) {
                // Append SQL packets
                out.write("\r\n");
            }
        }
    }

    /**
     * Set the server row count (to limit the number of rows in a result set)
     * and text size (to limit the size of returned TEXT/NTEXT fields).
     *
     * @param rowCount the number of rows to return or 0 for no limit or -1 to
     *                 leave as is
     * @param textSize the maximum number of bytes in a TEXT column to return
     *                 or -1 to leave as is
     * @throws SQLException if an error is returned by the server
     */
    private void setRowCountAndTextSize(int rowCount, int textSize)
            throws SQLException {
        boolean newRowCount =
                rowCount >= 0 && rowCount != connection.getRowCount();
        boolean newTextSize =
                textSize >= 0 && textSize != connection.getTextSize();
        if (newRowCount || newTextSize) {
            try {
                StringBuffer query = new StringBuffer(64);
                if (newRowCount) {
                    query.append("SET ROWCOUNT ").append(rowCount);
                }
                if (newTextSize) {
                    query.append(" SET TEXTSIZE ")
                            .append(textSize == 0 ? 2147483647 : textSize);
                }
                out.setPacketType(QUERY_PKT);
                out.write(query.toString());
                out.flush();
                endOfResponse = false;
                endOfResults  = true;
                wait(0);
                clearResponseQueue();
                messages.checkErrors();
                // Update the values stored in the Connection
                connection.setRowCount(rowCount);
                connection.setTextSize(textSize);
            } catch (IOException ioe) {
                throw new SQLException(
                            Messages.get("error.generic.ioerror",
                                                    ioe.getMessage()), "08S01");
            }
        }
    }

    /**
     * Wait for the first byte of the server response.
     *
     * @param timeOut The time out period in seconds or 0.
     */
    private void wait(int timeOut) throws IOException, SQLException {
        Object timer = null;
        try {
            if (timeOut > 0) {
                // Start a query timeout timer
                timer = TimerThread.getInstance().setTimer(timeOut * 1000,
                        new TimerThread.TimerListener() {
                            public void timerExpired() {
                                TdsCore.this.cancel();
                            }
                        });
            }
            in.peek();
        } finally {
            if (timer != null) {
                if (!TimerThread.getInstance().cancelTimer(timer)) {
                    throw new SQLException(
                          Messages.get("error.generic.timeout"), "HYT00");
                }
            }
        }
    }

    /**
     * Convert a user supplied MAC address into a byte array.
     *
     * @param macString The MAC address as a hex string.
     * @return The MAC address as a <code>byte[]</code>.
     */
    private static byte[] getMACAddress(String macString) {
        byte[] mac = new byte[6];
        boolean ok = false;

        if (macString != null && macString.length() == 12) {
            try {
                for (int i = 0, j = 0; i < 6; i++, j += 2) {
                    mac[i] = (byte) Integer.parseInt(
                            macString.substring(j, j + 2), 16);
                }

                ok = true;
            } catch (Exception ex) {
                // Ignore it. ok will be false.
            }
        }

        if (!ok) {
            Arrays.fill(mac, (byte) 0);
        }

        return mac;
    }

    /**
     * Try to figure out what client name we should identify ourselves as. Get
     * the hostname of this machine,
     *
     * @return    name we will use as the client.
     */
    private static String getHostName() {
        if (hostName != null) {
            return hostName;
        }

        String name;

        try {
            name = java.net.InetAddress.getLocalHost().getHostName().toUpperCase();
        } catch (java.net.UnknownHostException e) {
            hostName = "UNKNOWN";
            return hostName;
        }

        int pos = name.indexOf('.');

        if (pos >= 0) {
            name = name.substring(0, pos);
        }

        if (name.length() == 0) {
            hostName = "UNKNOWN";
            return hostName;
        }

        try {
            Integer.parseInt(name);
            // All numbers probably an IP address
            hostName = "UNKNOWN";
            return hostName;
        } catch (NumberFormatException e) {
            // Bit tacky but simple check for all numbers
        }

        hostName = name;
        return name;
    }

    /**
     * This is a <B>very</B> poor man's "encryption."
     *
     * @param  pw  password to encrypt
     * @return     encrypted password
     */
    private static String tds7CryptPass(final String pw) {
        final int xormask = 0x5A5A;
        final int len = pw.length();
        final char[] chars = new char[len];

        for (int i = 0; i < len; ++i) {
            final int c = (int) (pw.charAt(i)) ^ xormask;
            final int m1 = (c >> 4) & 0x0F0F;
            final int m2 = (c << 4) & 0xF0F0;

            chars[i] = (char) (m1 | m2);
        }

        return new String(chars);
    }
}
