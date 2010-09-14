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
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.sql.*;
import java.util.Arrays;
import java.util.concurrent.Semaphore;
import java.util.Timer;
import java.util.TimerTask;
import net.sourceforge.jtds.util.Logger;


/**
 * This base class implements the Sybase / Microsoft TDS protocol support.
 * <p>
 * Implementation notes:
 * <ol>
 * <li>This class, and its subclasses, encapsulates all of the TDS specific logic 
 * required by the driver. 
 * <li>This is a ground up reimplementation of the TDS protocol and is rather
 *     simpler, and hopefully easier to understand, than the original jTDS code.
 * <li>The layout of the various Login packets is derived from the original code
 *     and freeTds work, and incorporates changes including the ability to login
 *     as a TDS 5.0 user.
 * <li>All network I/O errors are trapped here, reported to the log (if active)
 *     and the parent Connection object is notified that the connection should be considered
 *     closed.
 * <li>As the rest of the driver interfaces to this code via higher-level method calls there
 *     should be know need for knowledge of the TDS protocol to leak out of this class.
 *     It is for this reason that all the TDS Token constants are private.
 * </ol>
 *
 * @author Mike Hutchinson
 * @author Matt Brinkley
 * @author Alin Sinpalean
 * @author FreeTDS project
 * @version $Id: TdsCore.java,v 1.3 2009-07-23 19:35:35 ickzon Exp $
 */
abstract class TdsCore  {

    /**
     * Inner static class used to hold table meta data.
     */
    static class TableMetaData {
        /** Table catalog (database) name. */
        String catalog;
        /** Table schema (user) name. */
        String schema;
        /** Table name. */
        String name;
    }

    /**
     * Inner static class used to describe TDS data types;
     */
    static class TypeInfo {
        /** The SQL type name. */
        final String sqlType;
        /**
         * The size of this type or &lt; 0 for variable sizes.
         * <p> Special values as follows:
         * <ol>
         * <li> -5 sql_variant type.
         * <li> -4 text, image or ntext types.
         * <li> -2 SQL Server 7+ long char and var binary types.
         * <li> -1 varchar, varbinary, null types.
         * </ol>
         */
        final int size;
        /**
         * The precision of the type.
         * <p>If this is -1 precision must be calculated from buffer size
         * eg for varchar fields.
         */
        final int precision;
        /**
         * The scale of the type.
         */
        final int scale;
        /**
         * The display size of the type.
         * <p>-1 If the display size must be calculated from the buffer size.
         */
        final int displaySize;
        /** The java.sql.Types constant for this data type. */
        final int jdbcType;

        /**
         * Construct a new TDS data type descriptor.
         *
         * @param sqlType   SQL type name.
         * @param size Byte size for this type or &lt; 0 for variable length types.
         * @param precision Decimal precision or -1
         * @param scale the decimal scale
         * @param displaySize Printout size for this type or special values -1,-2.
         * @param jdbcType The java.sql.Type constant for this type.
         */
        TypeInfo(final String sqlType, 
                 final int size, 
                 final int precision, 
                 final int scale, 
                 final int displaySize,
                 final int jdbcType) 
        {
            this.sqlType = sqlType;
            this.size = size;
            this.precision = precision;
            this.scale = scale;
            this.displaySize = displaySize;
            this.jdbcType = jdbcType;
        }

    }

    //
    // Global TDS constants
    //
    /** Minimum network packet size. */
    static final int MIN_PKT_SIZE = 512;
    /** Default minimum network packet size for TDS 7.0 and newer. */
    static final int DEFAULT_MIN_PKT_SIZE_TDS70 = 4096;
    /** Maximum network packet size. */
    static final int MAX_PKT_SIZE = 32768;
    /** The size of the packet header. */
    public static final int PKT_HDR_LEN = 8;
    /** TDS 4.2 or 7.0 Query packet. */
    static final byte QUERY_PKT = 1;
    /** TDS 4.2 or 5.0 Login packet. */
    static final byte LOGIN_PKT = 2;
    /** TDS Remote Procedure Call. */
    static final byte RPC_PKT = 3;
    /** TDS Reply packet. */
    static final byte REPLY_PKT = 4;
    /** TDS Cancel packet. */
    static final byte CANCEL_PKT = 6;
    /** TDS MSDTC packet. */
    static final byte MSDTC_PKT = 14;
    /** TDS 5.0 Query packet. */
    static final byte SYBQUERY_PKT = 15;
    /** TDS 7.0 Login packet. */
    static final byte MSLOGIN_PKT = 16;
    /** TDS 7.0 NTLM Authentication packet. */
    static final byte NTLMAUTH_PKT = 17;
    /** SQL 2000 prelogin negotiation packet. */
    static final byte PRELOGIN_PKT = 18;
    /** SSL Mode - Login packet must be encrypted. */
    static final int SSL_ENCRYPT_LOGIN = 0;
    /** SSL Mode - Client requested force encryption. */
    static final int SSL_CLIENT_FORCE_ENCRYPT = 1;
    /** SSL Mode - No server certificate installed. */
    static final int SSL_NO_ENCRYPT = 2;
    /** SSL Mode - Server requested force encryption. */
    static final int SSL_SERVER_FORCE_ENCRYPT = 3;
    /** SQL Server 2000 version number. */
    static final int SQL_SERVER_2000 = 8;
    /** SQL Server 2005 version number. */
    static final int SQL_SERVER_2005 = 9;
    //
    /** TDS 4.2 protocol (SQL Server 6.5 and later and Sybase 9 and later). */
    static final int TDS42 = 1;
    /** TDS 5.0 protocol (Sybase 10 and later). */
    static final int TDS50 = 2;
    /** TDS 7.0 protocol (SQL Server 7.0 and later). */
    static final int TDS70 = 3;
    /** TDS 8.0 protocol (SQL Server 2000 and later) */
    static final int TDS80 = 4;
    /** TDS 8.1 protocol (SQL Server 2000 SP1 and later). */
    static final int TDS81 = 5;
    /** TDS 9.0 protocol (SQL Server 2005). */
    static final int TDS90 = 6;
    /** Microsoft SQL Server connection property constant. */
    static final int SQLSERVER = 1;
    /** Sybase ASE connection property constant. */
    static final int SYBASE = 2;    
    /** Sybase ASA connection property constant. */
    static final int ANYWHERE = 3;    

    //
    // End token status bytes
    //
    /** Done: more results are expected. */
    protected static final byte DONE_MORE_RESULTS     = (byte) 0x01;
    /** Done: command caused an error. */
    protected static final byte DONE_ERROR            = (byte) 0x02;
    /** Done: There is a valid row count. */
    protected static final byte DONE_ROW_COUNT        = (byte) 0x10;
    /** Done: Cancel acknowledgement. */
    protected static final byte DONE_CANCEL           = (byte) 0x20;
    /*
     * Done: Response terminator (if more than one request packet is sent, each
     * response is terminated by a DONE packet with this flag set).
     */
    protected static final byte DONE_END_OF_RESPONSE  = (byte) 0x80;
    /** Batch statement separator for SQL Server 6, 7 and 2000. */
    protected static final byte BATCH_SEPARATOR       = (byte) 0x80;
    /** Batch statement separator for 2005 TDS 9. */
    protected static final byte BATCH_SEPARATOR_TDS90 = (byte) 0xFF;

    //
    // Prepared SQL types
    //
    /** Do not prepare SQL */
    static final int UNPREPARED = 0;
    /** Prepare SQL using temporary stored procedures */
    static final int TEMPORARY_STORED_PROCEDURES = 1;
    /** Prepare SQL using sp_executesql */
    static final int EXECUTE_SQL = 2;
    /** Prepare SQL using sp_prepare and sp_execute */
    static final int PREPARE = 3;
    
    /** Cancel has been generated by <code>Statement.cancel()</code>. */
    protected final static int ASYNC_CANCEL = 0;
    /** Cancel has been generated by a query timeout. */
    protected final static int TIMEOUT_CANCEL = 1;
    /** Indicates no update count present. */
    protected final static Integer NO_COUNT = new Integer(-1);
    protected static final Integer EXECUTE_FAILED  = new Integer(Statement.EXECUTE_FAILED);
    protected static final Integer SUCCESS_NO_INFO = new Integer(Statement.SUCCESS_NO_INFO);
    //
    // TDS Sub packet types
    //
    /** TDS 5.0 Parameter format token. */
    protected static final byte TDS5_PARAMFMT2_TOKEN  = (byte) 32;   // 0x20
    /** TDS 5.0 Language token. */
    protected static final byte TDS_LANG_TOKEN        = (byte) 33;   // 0x21
    /** TSD 5.0 Wide result set token. */
    protected static final byte TDS5_WIDE_RESULT      = (byte) 97;   // 0x61
    /** TDS 5.0 Close token. */
    protected static final byte TDS_CLOSE_TOKEN       = (byte) 113;  // 0x71
    /** TDS DBLIB Offsets token. */
    protected static final byte TDS_OFFSETS_TOKEN     = (byte) 120;  // 0x78
    /** TDS Procedure call return status token. */
    protected static final byte TDS_RETURNSTATUS_TOKEN= (byte) 121;  // 0x79
    /** TDS Procedure ID token. */
    protected static final byte TDS_PROCID            = (byte) 124;  // 0x7C
    /** TDS 7.0 Result set column meta data token. */
    protected static final byte TDS7_RESULT_TOKEN     = (byte) 129;  // 0x81
    /** TDS 7.0 Computed Result set column meta data token. */
    protected static final byte TDS7_COMP_RESULT_TOKEN= (byte) 136;  // 0x88
    /** TDS 4.2 Column names token. */
    protected static final byte TDS_COLNAME_TOKEN     = (byte) 160;  // 0xA0
    /** TDS 4.2 Column meta data token. */
    protected static final byte TDS_COLFMT_TOKEN      = (byte) 161;  // 0xA1
    /** TDS Table name token. */
    protected static final byte TDS_TABNAME_TOKEN     = (byte) 164;  // 0xA4
    /** TDS Cursor results column infomation token. */
    protected static final byte TDS_COLINFO_TOKEN     = (byte) 165;  // 0xA5
   /** TDS Optional command token. */
    protected static final byte TDS_OPTIONCMD_TOKEN   = (byte) 166;  // 0xA6
    /** TDS Computed result set names token. */
    protected static final byte TDS_COMP_NAMES_TOKEN  = (byte) 167;  // 0xA7
    /** TDS Computed result set token. */
    protected static final byte TDS_COMP_RESULT_TOKEN = (byte) 168;  // 0xA8
    /** TDS Order by columns token. */
    protected static final byte TDS_ORDER_TOKEN       = (byte) 169;  // 0xA9
    /** TDS error result token. */
    protected static final byte TDS_ERROR_TOKEN       = (byte) 170;  // 0xAA
    /** TDS Information message token. */
    protected static final byte TDS_INFO_TOKEN        = (byte) 171;  // 0xAB
    /** TDS Output parameter value token. */
    protected static final byte TDS_PARAM_TOKEN       = (byte) 172;  // 0xAC
    /** TDS Login acknowledgement token. */
    protected static final byte TDS_LOGINACK_TOKEN    = (byte) 173;  // 0xAD
    /** TDS control token. */
    protected static final byte TDS_CONTROL_TOKEN     = (byte) 174;  // 0xAE
    /** TDS Result set data row token. */
    protected static final byte TDS_ROW_TOKEN         = (byte) 209;  // 0xD1
    /** TDS Computed result set data row token. */
    protected static final byte TDS_ALTROW            = (byte) 211;  // 0xD3
    /** TDS 5.0 parameter value token. */
    protected static final byte TDS5_PARAMS_TOKEN     = (byte) 215;  // 0xD7
    /** TDS 5.0 capabilities token. */
    protected static final byte TDS_CAP_TOKEN         = (byte) 226;  // 0xE2
    /** TDS environment change token. */
    protected static final byte TDS_ENVCHANGE_TOKEN   = (byte) 227;  // 0xE3
    /** TDS 5.0 message token. */
    protected static final byte TDS_MSG50_TOKEN       = (byte) 229;  // 0xE5
    /** TDS 5.0 RPC token. */
    protected static final byte TDS_DBRPC_TOKEN       = (byte) 230;  // 0xE6
    /** TDS 5.0 Dynamic SQL token. */
    protected static final byte TDS5_DYNAMIC_TOKEN    = (byte) 231;  // 0xE7
    /** TDS 5.0 parameter descriptor token. */
    protected static final byte TDS5_PARAMFMT_TOKEN   = (byte) 236;  // 0xEC
    /** TDS 7.0 NTLM authentication challenge token. */
    protected static final byte TDS_AUTH_TOKEN        = (byte) 237;  // 0xED
    /** TDS 5.0 Result set column meta data token. */
    protected static final byte TDS_RESULT_TOKEN      = (byte) 238;  // 0xEE
    /** TDS done token. */
    protected static final byte TDS_DONE_TOKEN        = (byte) 253;  // 0xFD DONE
    /** TDS done procedure token. */
    protected static final byte TDS_DONEPROC_TOKEN    = (byte) 254;  // 0xFE DONEPROC
    /** TDS done in procedure token. */
    protected static final byte TDS_DONEINPROC_TOKEN  = (byte) 255;  // 0xFF DONEINPROC
    //
    // Environment change payload codes
    //
    /** Environment change: database changed. */
    protected static final byte TDS_ENV_DATABASE      = (byte) 1;
    /** Environment change: language changed. */
    protected static final byte TDS_ENV_LANG          = (byte) 2;
    /** Environment change: charset changed. */
    protected static final byte TDS_ENV_CHARSET       = (byte) 3;
    /** Environment change: network packet size changed. */
    protected static final byte TDS_ENV_PACKSIZE      = (byte) 4;
    /** Environment change: locale changed. */
    protected static final byte TDS_ENV_LCID          = (byte) 5; // TDS7 Only
    /** Environment change: unicode comparison style. */
    protected static final byte TDS_ENV_UNICODE_COMP  = (byte) 6; // TDS7 Only
    /** Environment change: TDS 8 collation changed. */
    protected static final byte TDS_ENV_SQLCOLLATION  = (byte) 7; // TDS8 Collation
    /** Environment change: start transaction. */
    protected static final byte TDS_ENV_START_TRAN    = (byte) 8; // TDS9 only
    /** Environment change: end transaction. */
    protected static final byte TDS_ENV_END_TRAN      = (byte) 9; // TDS9 only
    /** Environment change: transaction aborted. */
    protected static final byte TDS_ENV_TRAN_ABORTED  = (byte) 10; // TDS9 only
    /** Environment change: start XA transaction. */
    protected static final byte TDS_ENV_START_XATRAN  = (byte) 11; // TDS9 only
    /** Environment change: end XA transaction. */
    protected static final byte TDS_ENV_END_XATRAN    = (byte) 12; // TDS9 only
    /*
     * Constants for TDS data types
     */
    protected static final int SYBCHAR               = 47; // 0x2F
    protected static final int SYBVARCHAR            = 39; // 0x27
    protected static final int SYBLONGDATA           = 36; // 0x24 SYBASE 12
    protected static final int SYBINTN               = 38; // 0x26
    protected static final int SYBINT1               = 48; // 0x30
    protected static final int SYBDATE               = 49; // 0x31 Sybase 12
    protected static final int SYBTIME               = 51; // 0x33 Sybase 12
    protected static final int SYBINT2               = 52; // 0x34
    protected static final int SYBINT4               = 56; // 0x38
    protected static final int SYBINT8               = 127;// 0x7F
    protected static final int SYBFLT8               = 62; // 0x3E
    protected static final int SYBDATETIME           = 61; // 0x3D
    protected static final int SYBBIT                = 50; // 0x32
    protected static final int SYBTEXT               = 35; // 0x23
    protected static final int SYBNTEXT              = 99; // 0x63
    protected static final int SYBIMAGE              = 34; // 0x22
    protected static final int SYBMONEY4             = 122;// 0x7A
    protected static final int SYBMONEY              = 60; // 0x3C
    protected static final int SYBDATETIME4          = 58; // 0x3A
    protected static final int SYBREAL               = 59; // 0x3B
    protected static final int SYBBINARY             = 45; // 0x2D
    protected static final int SYBVOID               = 31; // 0x1F
    protected static final int SYBVARBINARY          = 37; // 0x25
    protected static final int SYBNVARCHAR           = 103;// 0x67
    protected static final int SYBBITN               = 104;// 0x68
    protected static final int SYBNUMERIC            = 108;// 0x6C
    protected static final int SYBDECIMAL            = 106;// 0x6A
    protected static final int SYBFLTN               = 109;// 0x6D
    protected static final int SYBMONEYN             = 110;// 0x6E
    protected static final int SYBDATETIMN           = 111;// 0x6F
    protected static final int SYBDATEN              = 123;// 0x7B SYBASE 12
    protected static final int SYBTIMEN              = 147;// 0x93 SYBASE 12
    protected static final int XSYBCHAR              = 175;// 0xAF
    protected static final int XSYBVARCHAR           = 167;// 0xA7
    protected static final int XSYBNVARCHAR          = 231;// 0xE7
    protected static final int XSYBNCHAR             = 239;// 0xEF
    protected static final int XSYBVARBINARY         = 165;// 0xA5
    protected static final int XSYBBINARY            = 173;// 0xAD
    protected static final int SYBUNITEXT            = 174;// 0xAE SYBASE 15
    protected static final int SYBLONGBINARY         = 225;// 0xE1 SYBASE 12
    protected static final int SYBSINT1              = 64; // 0x40
    protected static final int SYBUINT2              = 65; // 0x41 SYBASE 15
    protected static final int SYBUINT4              = 66; // 0x42 SYBASE 15
    protected static final int SYBUINT8              = 67; // 0x43 SYBASE 15
    protected static final int SYBUINTN              = 68; // 0x44 SYBASE 15
    protected static final int SYBUNIQUE             = 36; // 0x24 SQL Server
    protected static final int SYBVARIANT            = 98; // 0x62 SQL Server
    protected static final int SYBSINT8              = 191;// 0xBF SYBASE 15
    protected static final int SYBMSUDT              = 240;// 0xF0 SQL 2005 
    protected static final int SYBMSXML              = 241;// 0xF1 SQL 2005 
    /*
     * Constants for Sybase User Defined data types used to
     * qualify the new longchar and longbinary types.
     */
    // Common to Sybase and SQL Server
    protected static final int UDT_CHAR              =  1; // 0x01
    protected static final int UDT_VARCHAR           =  2; // 0x02
    protected static final int UDT_BINARY            =  3; // 0x03
    protected static final int UDT_VARBINARY         =  4; // 0x04
    protected static final int UDT_SYSNAME           = 18; // 0x12
    // Sybase only
    protected static final int UDT_NCHAR             = 24; // 0x18
    protected static final int UDT_NVARCHAR          = 25; // 0x19
    protected static final int UDT_UNICHAR           = 34; // 0x22
    protected static final int UDT_UNIVARCHAR        = 35; // 0x23
    protected static final int UDT_UNITEXT           = 36; // 0x24
    protected static final int UDT_LONGSYSNAME       = 42; // 0x2A
    protected static final int UDT_TIMESTAMP         = 80; // 0x50
    // SQL Server 7+
    protected static final int UDT_NEWSYSNAME        =256; // 0x100
        
    /**
     * Array of TDS data type descriptors.
     */
    protected final static TypeInfo types[] = new TypeInfo[256];
    
    //
    // Instance variables
    //
    /** Name of the client host (it can take quite a while to find it out if DNS is configured incorrectly). */
    protected static String hostName;
    /** The Connection object that created this object. */
    protected final ConnectionImpl connection;
    /** The TDS version being supported by this connection. */
    protected int tdsVersion;
    /** The make of SQL Server (Sybase/Microsoft). */
    protected int serverType;
    /** The Shared network socket object. */
    protected final TdsSocket socket;
    /** The output server request stream. */
    protected final TdsStream out;
    /** The input server response stream. */
    protected final TdsStream in;
    /** The current TDS token byte. */
    protected byte token;
    /** The status field from a DONE packet. */
    protected byte doneStatus;
    /** The count field from a DONE packet. */
    protected Integer doneCount;
    /** True if the server response is fully read. */
    protected boolean endOfResponse = true;
    /** The array of table names associated with this result. */
    protected TableMetaData[] tables;
    /** Indicates that this object is closed. */
    protected boolean isClosed;
    /** Indicates that a fatal error has occured and the connection will close. */
    protected boolean fatalError;
    /** Indicates processing a batch. */
    protected boolean inBatch;
    /** Indicates first (or only) packet in batch. */
    protected boolean startBatch;
    /** Indicates pending cancel that needs to be cleared. */
    protected boolean cancelPending;
    /** Synchronization monitor for {@link #cancelPending}. */
    protected final int[] cancelMonitor = new int[1];
    /** Context that owns the current server response. */
    protected StatementImpl currentContext;
    /** Mutual exclusion lock to control access to connection. */
    protected final Semaphore mutex = new Semaphore(1);
    /** Synchronization monitor for net send. */
    protected boolean[] netSendInProgress = new boolean[1];
    /** Connection's current rowcount limit. */
    protected int rowCount;
    /** Connection's current maximum field size limit. */
    protected int textSize;
    /** Stored procedure unique ID number. */
    protected static int spSequenceNo = 1; // FIXME: static to get driver-wide unique IDs for ASA, should be changed back if possible (doesn't help if multiple clients are connected, anyway)

// -------------------- public methods from here -----------------------
    
    /**
     * Construct a TdsCore object.
     *
     * @param connection The connection which owns this object.
     * @param socket The TDS socket instance.
     * @param serverType the sever type (sqlserver,sybase,anywhere).
     * @param tdsVersion the required TDS version level.
     */
    TdsCore(final ConnectionImpl connection, 
            final TdsSocket socket, 
            final int serverType, 
            final int tdsVersion) 
    {
        if (Logger.isTraceActive()){
            Logger.printMethod(this, null, 
                    new Object[]{connection, socket, 
                                    new Integer(serverType), new Integer(tdsVersion)});
        }
        this.connection = connection;
        this.socket = socket;
        this.serverType = serverType;
        this.tdsVersion = tdsVersion;
        this.out = new TdsStream(this, socket);
        this.in = out;
    }
    
    /**
     * Retrieves the connection mutex and acquires an exclusive lock on the
     * network connection.
     * <p/>This lock is used by the outer API for example Statement.execute()
     * to ensure that the Connection object is reserved for the duration of 
     * the request/response exchange.
     *
     * @param cx StatementImpl instance.
     * @return the mutex object as a <code>Semaphore</code>.
     */
    Semaphore getMutex(final StatementImpl cx) throws SQLException 
    {
        // Thread.interrupted() will clear the interrupt status
        boolean interrupted = Thread.interrupted();
        try {
            this.mutex.acquire();
        } catch (InterruptedException e) {
            throw new IllegalStateException("Thread execution interrupted");
        }
        if (interrupted) {
            // Bug [1596743] do not absorb interrupt status
            Thread.currentThread().interrupt();
        }
        //
        // If the requestor has not cleared the previous response do that
        // now otherwise if another statement still has results outstanding 
        // read and cache these now so that this request can take over the 
        // network connection.
        //
        if (currentContext != null) {
            if (currentContext == cx) {
                clearResponseQueue(cx);
            } else {
                synchronized (currentContext) {
                    processResults(currentContext, true);
                }
            }
        }
                
        return this.mutex;
    }

    /**
     * Inform the server that this connection is closing.
     * <p>
     * Used by Sybase a no-op for Microsoft.
     * @param cx StatementImpl instance.
     */
    void close(final StatementImpl cx) throws SQLException 
    {
        if (!isClosed) {
            isClosed = true;
            in.close();
        }
    }

    /**
     * Send (only) one cancel packet to the server.
     * <p/>We can only send a cancel if the network connection is 
     * not currently being used to send a data packet and if we
     * have not already sent a cancel.
     *
     * @param cx StatementImpl instance.
     * @param timeout true if this is a query timeout cancel
     */
    void cancel(final StatementImpl cx, final boolean timeout) 
    {
        Logger.printMethod(this, "cancel", null);
        synchronized (this.netSendInProgress) {
            if (!this.netSendInProgress[0]) {
                synchronized (cancelMonitor) {
                    if (!cancelPending && !endOfResponse) {
                        try {
                            // If this cancel is called from the wait routine
                            // for query timeout then the currentContext must be
                            // the one that called executeSQL. If this cancel is
                            // called from a statement check that that this 
                            // statement's context is the one currently waiting 
                            // for results.
                            if ((timeout && currentContext != null) ||
                                 (!timeout && cx == currentContext)) {
                                //
                                // Send a cancel packet.
                                //
                                cancelPending = true;
                                byte[] cancel = new byte[PKT_HDR_LEN];
                                cancel[0] = CANCEL_PKT;
                                cancel[1] = 1;
                                cancel[2] = 0;
                                cancel[3] = 8;
                                cancel[4] = 0;
                                cancel[5] = 0;
                                cancel[6] = (tdsVersion >= TDS70) ? (byte) 1 : 0;
                                cancel[7] = 0;
                                socket.sendBytes(cancel);
                            }
                        } catch (IOException e) {
                            // Ignore error as network is probably dead anyway
                        }
                    }
                    // If a cancel request was sent, reset the end of response flag
                    // to ensure cancel packet is processed.
                    if (cancelPending) {
                        cancelMonitor[0] = timeout ? TIMEOUT_CANCEL : ASYNC_CANCEL;
                        endOfResponse = false;
                    }
                }
            }
        }
    }

    /**
     * Submit a simple SQL statement to the server and process all output.
     *
     * @param cx StatementImpl instance.
     * @param sql the statement to execute
     * @throws SQLException if an error is returned by the server
     */
    void submitSQL(final StatementImpl cx, final String sql) throws SQLException 
    {
        checkOpen();

        if (sql.length() == 0) {
            throw new IllegalArgumentException("submitSQL() called with empty SQL String");
        }

        executeSQL(cx, sql, null, null, false, 0, -1, -1, true);
        processResults(cx, true);
        cx.getMessages().checkErrors();
    }
    
    /**
     * Send an SQL statement with optional parameters to the server.
     *
     * @param cx           StatementImpl instance.
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
     void executeSQL(final StatementImpl cx, 
                     String sql,
                     String procName,
                     ParamInfo[] parameters,
                     final boolean noMetaData,
                     final int timeOut,
                     final int maxRows,
                     final int maxFieldSize,
                     final boolean sendNow)
            throws SQLException 
     {
         
        boolean sendFailed = true;     // Used to ensure send flag is released.

        try {
           //
            // Set the send in progress flag which is used to prevent
            // cancel packets being sent in the middle of this packet.
            //
            if (lockNetwork()) {
                this.startBatch = true;  // Indicates first packet in batch
                this.inBatch = !sendNow; // Indicates we are in a batch
            }
            checkOpen();
            //
            // All existing results are destroyed
            //
            cx.initContext();

            //
            // Set the connection row count and text size if required.
            // Once set these will not be changed within a
            // batch so execution of the set rows query will
            // only occur once a the start of a batch.
            // No other thread can send until this one has finished.
            //
            setRowCountAndTextSize(cx, maxRows, maxFieldSize);

            //
            // Normalize the parameters argument to simplify later checks
            //
            if (parameters != null && parameters.length == 0) {
                parameters = null;
            }
            cx.setParameters(parameters);
            //
            // Normalise the procName argument as well
            //
            if (procName != null && procName.length() == 0) {
                procName = null;
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
                    sql = Support.substituteParameters(sql, parameters, connection);
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
                        setNativeType(parameters[i]);
                    }
                }
            }
            try {

                localExecuteSQL(cx, sql, procName, parameters, noMetaData, sendNow);

                if (sendNow) {
                    out.flush();
                    inBatch = false;
                    endOfResponse = false;
                    currentContext = cx;
                    // Clear the send flag so that cancel can work
                    freeNetwork();
                    // Wait for server to respond
                    wait(timeOut);
                    // Process server results
                    processResults(cx, false);
                }
                // Indicate send was sucessful
                sendFailed = false;
            } catch (IOException ioe) {
                connection.setClosed();
                SQLException sqle = new SQLException(
                           Messages.get(
                                    "error.generic.ioerror", ioe.getMessage()),
                                        "08S01");
                sqle.initCause(ioe);
                throw sqle;
            }
        } finally {
            if (sendFailed) {
                // Ensure send flag is cleared on error
                freeNetwork();
            }
            // Clear the in batch flag
            if (sendNow) {
                inBatch = false;
            }
            // Clear the start batch flag
            startBatch = false;
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
     * Negotiate the required level of SSL support with the server.
     * @param instance the SQL Server instance name.
     * @param ssl the required SSL level (OFF, REQUEST, REQUIRE, AUTHENTICATE).
     * @throws IOException
     * @throws SQLException
     */
     void negotiateSSL(final String instance, final String ssl)
     throws IOException, SQLException {
         throw new IllegalStateException("SSL not supported with current TDS version.");
     }
     
    /**
     * Enlist the current connection in a distributed transaction or request the location of the
     * MSDTC instance controlling the server we are connected to.
     *
     * @param cx StatementImpl instance.
     * @param type      set to 0 to request TM address or 1 to enlist connection
     * @param oleTranID the 40 OLE transaction ID
     * @return a <code>byte[]</code> array containing the TM address data
     * @throws SQLException
     */
     byte[] enlistConnection(final StatementImpl cx, 
                             final int type, 
                             final byte[] oleTranID) throws SQLException 
     {
         throw new IllegalStateException("Native XA enlistment not supported with current TDS version.");
     }

    /**
     * Login to the SQL Server.
     *
     * @param cx         StatementImpl instance
     * @param serverName server host name
     * @param database   required database
     * @param user       user name
     * @param password   user password
     * @param domain     Windows NT domain (or null)
     * @param charset    required server character set
     * @param appName    application name
     * @param progName   library name
     * @param wsid       workstation ID
     * @param language   language to use for server messages
     * @param macAddress client network MAC address
     * @param packetSize required network packet size
     * @throws SQLException if an error occurs
     */
    abstract void login(final StatementImpl cx,
                        final String serverName,
                        final String database,
                        final String user,
                        final String password,
                        final String domain,
                        final String charset,
                        final String appName,
                        final String progName,
                        final String wsid,
                        final String language,
                        final String macAddress,
                        final int packetSize)
        throws SQLException ;
    
    /**
     * Prepares the SQL.
     *
     * @param cx                   the StatementImpl owning this prepare.
     * @param sql                  the SQL statement to prepare.
     * @param params               the actual parameter list
     * @param needCursor           true if a cursorprepare is required
     * @param resultSetType        value of the resultSetType parameter when
     *                             the Statement was created
     * @param resultSetConcurrency value of the resultSetConcurrency parameter
     *                             whenthe Statement was created
     * @return a <code>ProcEntry</code> instance.
     * @exception SQLException
     */
    abstract ProcEntry prepare(final StatementImpl cx,
                               final String sql,
                               final ParamInfo[] params,
                               final boolean needCursor,
                               final int resultSetType,
                               final int resultSetConcurrency,
                               final boolean returnKeys)
            throws SQLException; 

    /**
     * Drops a temporary stored procedure.
     *
     * @param cx the StatementImpl instance.
     * @param procName the temporary procedure name
     * @throws SQLException if an error occurs
     */
    void unPrepare(final StatementImpl cx, final String procName) throws SQLException 
    {
        throw new IllegalStateException("Unprepare not supported by the current TDS version.");
    }

    /**
     * Retrieve the TDS native type code for the parameter.
     *
     * @param pi         the parameter descriptor
     */
    abstract void setNativeType(final ParamInfo pi) throws SQLException;
    
    /**
     * Generates a unique statement key for a given SQL statement.
     *
     * @param sql        the sql statment to generate the key for
     * @param params     the statement parameters
     * @param catalog    the catalog is required for uniqueness on Microsoft
     *                   SQL Server
     * @param autoCommit true if in auto commit mode
     * @param cursor     true if this is a prepared cursor
     * @return the unique statement key
     */
     abstract String getStatementKey(final String sql, 
                                     final ParamInfo[] params,
                                     final String catalog,
                                     final boolean autoCommit, 
                                     final boolean cursor)  throws SQLException;

     /**
      * Execute SQL using TDS protocol.
      *
      * @param cx the StatementImpl instance that owns this request.
      * @param sql The SQL statement to execute.
      * @param procName Stored procedure to execute or null.
      * @param parameters Parameters for call or null.
      * @param noMetaData Suppress meta data for cursor calls.
      * @param sendNow true to actually send the packet.
      * @throws SQLException
      */
     protected abstract void localExecuteSQL(final StatementImpl cx,
                                             final String sql,
                                             final String procName,
                                             final ParamInfo[] parameters,
                                             final boolean noMetaData,
                                             final boolean sendNow)
             throws IOException, SQLException;    

     /**
      * Read the next TDS token from the response stream.
      *
      * @param cx StatementImpl instance.
      * @throws SQLException if an I/O or protocol error occurs
      */
     protected abstract void nextToken(final StatementImpl cx)
         throws SQLException;

     
     /**
      * Process the server responses and cache them in the StatementImpl.
      * <p/>This code also implements the lastUpdateCount=true logic.
      * @param cx the StatementImpl that owns the current server response.
      * @param processAll set to true to cache entire response.
      * @throws SQLException
      */
     void processResults(final StatementImpl cx, final boolean processAll) 
         throws SQLException 
     {
         if (cx != currentContext) {
             // This context already cleared by another thread!
             return;
         }
         try {
             checkOpen();
             if (endOfResponse) {
                 // Nothing left to do
                 return;
             }
             Integer lastResult = NO_COUNT;
             //
             // Loop processing all results or the first row of a result set has been
             // processed.
             //
             do {
                 nextToken(cx);
                 switch (this.token) {
                     //
                     // Look for tokens that can legally start a result set
                     //
                     case TDS_COLFMT_TOKEN:
                     case TDS7_RESULT_TOKEN:
                     case TDS_RESULT_TOKEN:
                     case TDS5_WIDE_RESULT:
                     {
                         if (lastResult != NO_COUNT) {
                             cx.addUpateCount(lastResult);
                             lastResult = NO_COUNT;
                         }
                         byte x = (byte) in.peek();
                         while (   x == TDS_TABNAME_TOKEN
                                || x == TDS_COLINFO_TOKEN
                                || x == TDS_CONTROL_TOKEN
                                || x == TDS_ORDER_TOKEN) {
                             // Start of result set can be followed by other tokens
                             // before the first data row so process these now.
                             nextToken(cx);
                             x = (byte)in.peek();
                         }
                         // Start of a result set
                         cx.addResultSet();
                         if (x != TDS_ROW_TOKEN) {
                             // This is an empty result set with now rows
                             cx.setEndOfResults();
                             // Result set should be terminated with a DONE token.
                             // Discard this token as we do not need the row count.
                             if (x == TDS_DONE_TOKEN 
                                     || x == TDS_DONEPROC_TOKEN 
                                     || x == TDS_DONEINPROC_TOKEN) {
                                     nextToken(cx);
                             }
                         }
                         break;
                    }
                    //
                    // Process result set rows
                    //
                    case TDS_ROW_TOKEN: {
                         // Save the row in the TDS Context
                         cx.addRow();
                         byte x = (byte)in.peek();
                         if (x != TDS_ROW_TOKEN) {
                             cx.setEndOfResults();
                             // Result set should be terminated with a DONE token.
                             // Discard this token as we do not need the row count.
                             if (x == TDS_DONE_TOKEN 
                                 || x == TDS_DONEPROC_TOKEN 
                                 || x == TDS_DONEINPROC_TOKEN) {
                                 nextToken(cx);
                             }
                         } else {
                             if (!processAll) {
                                 // This option avoids the need for jTDS to cache
                                 // direct selects in most cases.
                                 return;
                             }
                         }
                         break;
                    }
                    //
                    // Process DONE tokens that terminate a stored procedure.
                    //
                    case TDS_DONEPROC_TOKEN: {
                        if (lastResult != NO_COUNT) {
                            cx.addUpateCount(lastResult);
                            lastResult = NO_COUNT;
                        }
                        break;
                    }
                    //
                    // Process DONE tokens that terminate the statement response.
                    //
                    case TDS_DONE_TOKEN: {
                        if ((this.doneStatus & DONE_ERROR) != 0) {
                            if (lastResult != NO_COUNT) {
                                cx.addUpateCount(lastResult);
                            }
                            lastResult = cx.isExecuteBatch()? EXECUTE_FAILED: NO_COUNT;
                        } else {
                            if ((this.doneStatus & DONE_ROW_COUNT) > 0) {
                                lastResult = new Integer(this.doneCount);
                            } else {
                                if (lastResult == NO_COUNT) {
                                    lastResult = cx.isExecuteBatch()? SUCCESS_NO_INFO: NO_COUNT;
                                }
                            }
                        }
                        if (lastResult != NO_COUNT) {
                            cx.addUpateCount(lastResult);
                            lastResult = NO_COUNT;
                        }
                        break;
                    }
                    //
                    // Process DONE IN PROC tokens that terminate a statement within 
                    // stored procedures.
                    //
                    case TDS_DONEINPROC_TOKEN: {
                        if ((this.doneStatus & DONE_ERROR) != 0) {
                            lastResult = cx.isExecuteBatch()? EXECUTE_FAILED: NO_COUNT;
                        } else {
                            if ((this.doneStatus & DONE_ROW_COUNT) > 0) {
                                lastResult = new Integer(this.doneCount);
                            } else {
                                lastResult = cx.isExecuteBatch()? SUCCESS_NO_INFO: NO_COUNT;
                            }
                        }
                        if (lastResult != NO_COUNT && !cx.isLastUpdateCount()) {
                            cx.addUpateCount(lastResult);
                            lastResult = NO_COUNT;
                        }
                        break;
                    }
                 }
                 
             } while (!endOfResponse);
             if (Logger.isTraceActive()) {
                 Logger.printTrace(this.getClass().getName() + 
                         ".processResults() - No more results.");
             }
             currentContext = null;
              
         } catch (SQLException e) {
             if (!connection.isClosed()) {
                 clearResponseQueue(cx);
             }
             throw e;
         } catch (IOException e) {
             connection.setClosed();
             SQLException sqle = new SQLException(
                     Messages.get(
                             "error.generic.ioerror", e.getMessage()),
                     "08S01");
             sqle.initCause(e);
             throw sqle;
         }
     }

     /**
      * Empty the server response queue.
      *
      * @param cx StatementImpl instance.
      * @throws SQLException if an error occurs
      */
     protected void clearResponseQueue(final StatementImpl cx) throws SQLException 
     {
         checkOpen();
         while (!endOfResponse) {
             nextToken(cx);
         }
         currentContext = null;
     }

     /**
      * Check that the connection is still open.
      *
      * @throws SQLException
      */
     protected void checkOpen() throws SQLException {
         if (connection.isClosed()) {
             throw new SQLException(
                 Messages.get("error.generic.closed", "Connection"),
                     "HY010");
         }
     }

    /**
     * Obtain a short duration lock on the network channel to prevent 
     * cancels being sent while we are transmitting.
     * @return <code>boolean</code> true if lock aquired on this call.
     */
    protected boolean lockNetwork() {
        synchronized (this.netSendInProgress) {
            if (this.netSendInProgress[0]) {
                return false;
            }
            this.netSendInProgress[0] = true;
            return true;
        }        
    }
    
    /**
     * Free the network lock to allow other threads to transmit.
     */
    protected void freeNetwork() {
        synchronized (this.netSendInProgress) {
            this.netSendInProgress[0] = false;
        }
    }
    
    /**
     * Write a TDS login packet string. Text followed by padding followed
     * by a byte sized length.
     * @param txt the text to write to the tds stream.
     * @param len the length to pad string out to.
     */
    protected void putLoginString(String txt, int len)
        throws IOException {
        ByteBuffer bb = connection.getCharset().encode(txt);
        byte buf[] = new byte[bb.remaining()];
        bb.get(buf);
        out.write(buf, 0, len);
        out.write((byte) (buf.length < len ? buf.length : len));
    }

    /**
     * Report unsupported TDS token in input stream.
     *
     * @throws IOException
     */
    protected void tdsInvalidToken() throws IOException
    {
        throw new IOException("Unsupported TDS token: " + (this.token & 0xFF));
    }

    /**
     * Sets the server row count (to limit the number of rows in a result set)
     * and text size (to limit the size of returned TEXT/NTEXT fields).
     *
     * @param cx the StatementImpl instance that owns this request.
     * @param rowCount the number of rows to return or 0 for no limit or -1 to
     *                 leave as is
     * @param textSize the maximum number of bytes in a TEXT column to return
     *                 or -1 to leave as is
     * @throws SQLException if an error is returned by the server
     */
    protected void setRowCountAndTextSize(final StatementImpl cx, 
                                          final int rowCount, 
                                          final int textSize)
            throws SQLException 
    {
        boolean newRowCount =
                rowCount >= 0 && rowCount != this.rowCount;
        boolean newTextSize =
                textSize >= 0 && textSize != this.textSize;
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
                localExecuteSQL(cx, query.toString(), null, null, false, true);
                out.flush();
                endOfResponse = false;
                wait(0);
                clearResponseQueue(cx);
                cx.getMessages().checkErrors();
                // Update the values stored for the Connection
                this.rowCount = rowCount;
                this.textSize = textSize;
            } catch (IOException ioe) {
                throw new SQLException(
                            Messages.get("error.generic.ioerror",
                                                    ioe.getMessage()), "08S01");
            }
        }
    }

    /**
     * Waits for the first byte of the server response.
     *
     * @param timeOut the timeout period in seconds or 0
     */
    protected void wait(final int timeOut) throws IOException, SQLException 
    {
        Timer timer = null;
        TimerTask tt = null;
        try {
            if (timeOut > 0) {
                // Start a query timeout timer
                timer = connection.getTimer();
                tt = new TimerTask() {
                    public void run() {
                        TdsCore.this.cancel(null, true);
                    }
                };
                timer.schedule(tt, timeOut * 1000);
            }
            in.peek();
        } finally {
            if (tt != null) {
                if (!tt.cancel()) {
                    throw new SQLException(
                          Messages.get("error.generic.timeout"), "HYT00");
                }
            }
        }
    }

    /**
     * Converts a user supplied MAC address into a byte array.
     *
     * @param macString the MAC address as a hex string
     * @return the MAC address as a <code>byte[]</code>
     */
    protected static byte[] getMACAddress(String macString) 
    {
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
     * Tries to figure out what client name we should identify ourselves as.
     * Gets the hostname of this machine,
     *
     * @return name to use as the client
     */
    protected static String getHostName() 
    {
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
     * Retrieves the next unique stored procedure name.
     * <p>Notes:
     * <ol>
     * <li>Some versions of Sybase require an id with
     * a length of &lt;= 10.
     * <li>The format of this name works for sybase and Microsoft
     * and allows for 16M names per session.
     * <li>The leading '#jtds' indicates this is a temporary procedure and
     * the '#' is removed by the lower level TDS5 routines.
     * </ol>
     *
     * @return the next temporary SP name as a <code>String</code>
     */
    synchronized String getProcName() {
        String seq = "000000" + Integer.toHexString(spSequenceNo++).toUpperCase();

        return "#jtds" + seq.substring(seq.length() - 6, seq.length());
    }
    
    /**
     * Set the server charset for use in optimised mapping of
     * single byte character sets.
     * @param cs the Charset instance.
     */
    void setCharset(final Charset cs) {
        out.setCharset(cs);
    }
}
