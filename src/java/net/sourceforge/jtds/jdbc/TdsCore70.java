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

import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.Semaphore;

import net.sourceforge.jtds.util.Logger;
import net.sourceforge.jtds.util.NtlmAuth;
import net.sourceforge.jtds.util.SSPIJNIClient;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import sun.misc.HexDumpEncoder;

/**
 * This class implements the Microsoft TDS 7.0+ protocol.
 *
 * @author Mike Hutchinson
 * @author Matt Brinkley
 * @author Alin Sinpalean
 * @author FreeTDS project
 * @version $Id: TdsCore70.java,v 1.2 2009/07/24 14:15:29 ickzon Exp $
 */
class TdsCore70 extends TdsCore {
    //
    // SQL Server Login database security error message codes
    //
    /** Error 916: Server user id ? is not a valid user in database '?'.*/
    private static final int ERR_INVALID_USER   = 916;
    /** Error 10351: Server user id ? is not a valid user in database '?'.*/
    private static final int ERR_INVALID_USER_2 = 10351;
    /** Error 4001: Cannot open default database '?'.*/
    private static final int ERR_NO_DEFAULT_DB  = 4001;
        
    /** Map of system stored procedures that have shortcuts in TDS8. */
    private static HashMap<String, Integer> tds8SpNames = new HashMap<String, Integer>();
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

    /** Max length of variable length data types. */
    private static final int MS_LONGVAR_MAX        = 8000;
    /** Length of a MS collation field. */
    private static final int COLLATION_SIZE        = 5;

    /**
     * Static block to initialise TDS data type descriptors.
     */
    static {//                             SQL Type       Size Prec scale DS TDS8 Col java Type
        types[SYBCHAR]      = new TypeInfo("char",          -1, -1, 0, 0, java.sql.Types.CHAR);
        types[SYBVARCHAR]   = new TypeInfo("varchar",       -1, -1, 0, 0, java.sql.Types.VARCHAR);
        types[SYBINTN]      = new TypeInfo("int",           -1, 10, 0,11, java.sql.Types.INTEGER);
        types[SYBINT1]      = new TypeInfo("tinyint",        1,  3, 0, 4, java.sql.Types.TINYINT);
        types[SYBINT2]      = new TypeInfo("smallint",       2,  5, 0, 6, java.sql.Types.SMALLINT);
        types[SYBINT4]      = new TypeInfo("int",            4, 10, 0,11, java.sql.Types.INTEGER);
        types[SYBINT8]      = new TypeInfo("bigint",         8, 19, 0,20, java.sql.Types.BIGINT);
        types[SYBFLT8]      = new TypeInfo("float",          8, 15, 0,24, java.sql.Types.DOUBLE);
        types[SYBDATETIME]  = new TypeInfo("datetime",       8, 23, 3,23, java.sql.Types.TIMESTAMP);
        types[SYBBIT]       = new TypeInfo("bit",            1,  1, 0, 1, java.sql.Types.BIT);
        types[SYBTEXT]      = new TypeInfo("text",          -4,  0, 0, 0, java.sql.Types.CLOB);
        types[SYBNTEXT]     = new TypeInfo("ntext",         -4,  0, 0, 0, java.sql.Types.CLOB);
        types[SYBIMAGE]     = new TypeInfo("image",         -4,  0, 0, 0, java.sql.Types.BLOB);
        types[SYBMONEY4]    = new TypeInfo("smallmoney",     4, 10, 4,12, java.sql.Types.DECIMAL);
        types[SYBMONEY]     = new TypeInfo("money",          8, 19, 4,21, java.sql.Types.DECIMAL);
        types[SYBDATETIME4] = new TypeInfo("smalldatetime",  4, 16, 0,19, java.sql.Types.TIMESTAMP);
        types[SYBREAL]      = new TypeInfo("real",           4,  7, 0,14, java.sql.Types.REAL);
        types[SYBBINARY]    = new TypeInfo("binary",        -1, -3, 0, 0, java.sql.Types.BINARY);
        types[SYBVOID]      = new TypeInfo("void",          -1,  1, 0, 1, 0);
        types[SYBVARBINARY] = new TypeInfo("varbinary",     -1, -3, 0, 0, java.sql.Types.VARBINARY);
        types[SYBNVARCHAR]  = new TypeInfo("nvarchar",      -1, -1, 0, 0, java.sql.Types.VARCHAR);
        types[SYBBITN]      = new TypeInfo("bit",           -1,  1, 0, 1, java.sql.Types.BIT);
        types[SYBNUMERIC]   = new TypeInfo("numeric",       -1,  0, 0, 0, java.sql.Types.NUMERIC);
        types[SYBDECIMAL]   = new TypeInfo("decimal",       -1,  0, 0, 0, java.sql.Types.DECIMAL);
        types[SYBFLTN]      = new TypeInfo("float",         -1, 15, 0,24, java.sql.Types.DOUBLE);
        types[SYBMONEYN]    = new TypeInfo("money",         -1, 19, 4,21, java.sql.Types.DECIMAL);
        types[SYBDATETIMN]  = new TypeInfo("datetime",      -1, 23, 3,23, java.sql.Types.TIMESTAMP);
        types[XSYBCHAR]     = new TypeInfo("char",          -2,  0, 0, 0, java.sql.Types.CHAR);
        types[XSYBVARCHAR]  = new TypeInfo("varchar",       -2,  0, 0, 0, java.sql.Types.VARCHAR);
        types[XSYBNVARCHAR] = new TypeInfo("nvarchar",      -2,  0, 0, 0, java.sql.Types.VARCHAR);
        types[XSYBNCHAR]    = new TypeInfo("nchar",         -2,  0, 0, 0, java.sql.Types.CHAR);
        types[XSYBVARBINARY]= new TypeInfo("varbinary",     -2,  0, 0, 0, java.sql.Types.VARBINARY);
        types[XSYBBINARY]   = new TypeInfo("binary",        -2,  0, 0, 0, java.sql.Types.BINARY);
        types[SYBSINT1]     = new TypeInfo("tinyint",        1,  2, 0, 3, java.sql.Types.TINYINT);
        types[SYBUNIQUE]    = new TypeInfo("uniqueidentifier",-1,36, 0,36,java.sql.Types.CHAR);
        types[SYBVARIANT]   = new TypeInfo("sql_variant",   -5,  0, 0,8000,java.sql.Types.VARCHAR);
        types[SYBMSUDT]     = new TypeInfo("udt",           -2,  0, 0, 0, java.sql.Types.VARBINARY);
        types[SYBMSXML]     = new TypeInfo("xml",           -1,  0, 0, 0, java.sql.Types.CLOB);
    }

    //
    // Class variables
    //
    /** A reference to ntlm.SSPIJNIClient. */
    private static SSPIJNIClient sspiJNIClient;
    /** SQL 2005 (TDS90) null transaction descriptor. */
    private static final byte nullTransDesc[] = {0,0,0,0,0,0,0,0};

    //
    // Instance variables
    //
    /** Flag that indicates if logon() should try to use Windows
     * Single Sign On using SSPI or Kerberos SSO via Java native GSSAPI.
     */
    private boolean ntlmAuthSSO;
    private GSSContext _gssContext = null;

    /** The nonce from an NTLM challenge packet. */
    byte[] nonce;
    /** NTLM authentication message. */
    byte[] ntlmMessage;    
    /** NTLMv2 Target information. */
    byte[] ntlmTarget;
    /** Indicates type of SSL connection. */
    private int sslMode = SSL_NO_ENCRYPT;

    /** SQL 2005 (TDS90) transaction descriptor. */
    private byte[] transDescriptor = nullTransDesc;
    /** SQL 2005 (TDS90) XA transaction descriptor. */
    private byte[] xaTransDescriptor = nullTransDesc;

    /**
     * Construct a TdsCore object.
     *
     * @param connection The connection which owns this object.
     * @param socket The TDS socket instance.
     * @param tdsVersion the required TDS version level.
     */
    TdsCore70(final ConnectionImpl connection, 
              final TdsSocket socket, 
              final int tdsVersion) 
    {
        super(connection, socket, SQLSERVER, tdsVersion);
    }

    /**
     * Retrieves the connection mutex and acquires an exclusive lock on the
     * network connection.
     * <p/>This lock is used by the outer API for example Statement.execute()
     * to ensure that the Connection object is reserved for the duration of 
     * the request/response exchange.
     *
     * @param cx         StatementImpl instance
     * @return the mutex object as a <code>Semaphore</code>
     */
    Semaphore getMutex(final StatementImpl cx) throws SQLException 
    {
        super.getMutex(cx);
        
        if (xaTransDescriptor != nullTransDesc && xaTransDescriptor != transDescriptor) {
            // An XA abort has occured on SQL 2005 using TDS90. 
            // We need to unenlist the connection to prevent 
            // "Distributed Transaction completed" server exceptions.
            this.enlistConnection(cx, 1, null);
            xaTransDescriptor = nullTransDesc;
        }
                
        return this.mutex;
    }
    
    /**
     * Negotiate prelogin SSL and protocol settings with SQL 2000+ server.
     * <p/>
     * Server returns the following values for SSL mode:
     * <ol>
     * <ll>0 = Certificate installed encrypt login packet only.
     * <li>1 = Certificate installed client requests force encryption.
     * <li>2 = No certificate no encryption possible.
     * <li>3 = Server requests force encryption.
     * </ol>
     * @param instance The server instance name.
     * @param ssl The SSL URL property value.
     * @throws IOException
     */
    void negotiateSSL(final String instance, final String ssl)
            throws IOException, SQLException 
    {
        int options[];
        if (!ssl.equalsIgnoreCase(SecureSocket.SSL_OFF)) {
            if (ssl.equalsIgnoreCase(SecureSocket.SSL_REQUIRE) ||
                    ssl.equalsIgnoreCase(SecureSocket.SSL_AUTHENTICATE)) {
                sendPreLoginPacket(instance, SSL_CLIENT_FORCE_ENCRYPT);
                options = readPreLoginPacket();
                if (options[0] != SSL_CLIENT_FORCE_ENCRYPT &&
                    options[0] != SSL_SERVER_FORCE_ENCRYPT) {
                    throw new SQLException(
                            Messages.get("error.ssl.encryptionoff"),
                            "08S01");
                }
            } else {
                sendPreLoginPacket(instance, SSL_ENCRYPT_LOGIN);
                options = readPreLoginPacket();
            }
        } else {
            sendPreLoginPacket(instance, SSL_NO_ENCRYPT);
            options = readPreLoginPacket();
        }
        sslMode = options[0];
        if (sslMode != SSL_NO_ENCRYPT) {
            socket.enableEncryption(ssl);
        }
        //
        // Testing the option flag allows us to select the newest
        // TDS protocol if possible.
        //
        if (options[1] > SQL_SERVER_2000 && tdsVersion >= TDS80) {
            tdsVersion = TDS90;
        }
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
    void login(final StatementImpl cx,
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
        throws SQLException {
        Logger.printMethod(this, "login", null);
        try {
            sendMSLoginPkt(serverName, database, user, password,
                           domain, appName, progName, 
                           (wsid.length() == 0)? getHostName(): wsid, 
                           language, macAddress, packetSize);
            if (sslMode == SSL_ENCRYPT_LOGIN) {
                socket.disableEncryption();
            }
            endOfResponse = false;
            nextToken(cx);

            while (!endOfResponse) {
                if (this.token == TDS_AUTH_TOKEN) {
		    // If _gssContext exists, we are doing GSS instead
		    // of NTLM
		    if (_gssContext != null)
			sendGssToken();
		    else
			sendNtlmChallengeResponse(user, password, domain);
                }

                nextToken(cx);
            }

            cx.getMessages().checkErrors();
        } catch (IOException ioe) {
            SQLException sqle = new SQLException(
                       Messages.get(
                                "error.generic.ioerror", ioe.getMessage()),
                                    "08S01");
            sqle.initCause(ioe);
            throw sqle;
        }
    }

    /**
     * Constructs a parameter definition string for use with
     * sp_executesql, sp_prepare, sp_prepexec, sp_cursoropen,
     * sp_cursorprepare and sp_cursorprepexec.
     *
     * @param parameters Parameters to construct the definition for
     * @return a parameter definition string
     */
    String getParameterDefinitions(final ParamInfo[] parameters) throws SQLException 
    {
        StringBuilder sql = new StringBuilder(parameters.length * 15);

        for (int i = 0; i < parameters.length; i++) {
            setNativeType(parameters[i]);
        }

        // Build parameter descriptor
        for (int i = 0; i < parameters.length; i++) {
            if (parameters[i].name == null) {
                sql.append("@P");
                sql.append(i);
            } else {
                sql.append(parameters[i].name);
            }

            sql.append(' ');
            sql.append(parameters[i].sqlType);

            if (i + 1 < parameters.length) {
                sql.append(',');
            }
        }

        return sql.toString();
    }

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
     String getStatementKey(final String sql, 
                            final ParamInfo[] params,
                            final String catalog,
                            final boolean autoCommit, 
                            final boolean cursor)  throws SQLException 
     {
        StringBuilder key;
        //
        // obtain native types
        //
        for (int i = 0; i < params.length; i++) {
           setNativeType(params[i]);
        }

        key = new StringBuilder(1 + catalog.length() + sql.length()
                    + 11 * params.length);
        // Need to distinguish otherwise identical SQL for cursor and
        // non cursor prepared statements (sp_prepare/sp_cursorprepare).
        key.append((cursor) ? 'C':'X');
        // Need to ensure that the current database is included in the key
        // as procedures and handles are database specific.
        key.append(catalog);
        // Now the actual SQL statement
        key.append(sql);
        //
        // Append parameter data types to key.
        //
        for (int i = 0; i < params.length; i++) {
            key.append(params[i].sqlType);
        }
        
        return key.toString();
    }

    /**
     * Prepares the SQL for use with Microsoft server.
     *
     * @param cx                   the StatementImpl owning this prepare.
     * @param sql                  the SQL statement to prepare.
     * @param params               the actual parameter list
     * @param needCursor           true if a cursorprepare is required
     * @param resultSetType        value of the resultSetType parameter when
     *                             the Statement was created
     * @param resultSetConcurrency value of the resultSetConcurrency parameter
     *                             when the Statement was created
     * @param returnKeys           set to true if statement will return
     *                             generated keys.                            
     * @return a <code>ProcEntry</code> instance.
     * @exception SQLException
     */
    ProcEntry prepare(final StatementImpl cx,
                      final String sql,
                      final ParamInfo[] params,
                      final boolean needCursor,
                      final int resultSetType,
                      final int resultSetConcurrency,
                      final boolean returnKeys)
            throws SQLException {
        //
        checkOpen();
        
        int prepareSql = connection.getPrepareSql();

        if (prepareSql == TEMPORARY_STORED_PROCEDURES) {
            StringBuffer spSql = new StringBuffer(sql.length() + 32 + params.length * 15);
            String procName = getProcName();

            spSql.append("create proc ");
            spSql.append(procName);
            spSql.append(' ');

            for (int i = 0; i < params.length; i++) {
                spSql.append("@P");
                spSql.append(i);
                spSql.append(' ');
                spSql.append(params[i].sqlType);

                if (i + 1 < params.length) {
                    spSql.append(',');
                }
            }

            // continue building proc
            spSql.append(" as ");
            spSql.append(Support.substituteParamMarkers(sql, params));

            try {
                submitSQL(cx, spSql.toString());
                ProcEntry pe = new ProcEntry();
                pe.setName(procName);
                pe.setType(ProcEntry.PROCEDURE);
                return pe;
            } catch (SQLException e) {
                if ("08S01".equals(e.getSQLState())) {
                    // Serious (I/O) error, rethrow
                    throw e;
                }
                // This exception probably caused by failure to prepare
                // Add a warning
                SQLWarning sqlw = new SQLWarning(
                                Messages.get("error.prepare.prepfailed",
                                        e.getMessage()),
                                e.getSQLState(), e.getErrorCode());
                sqlw.initCause(e);
                cx.getMessages().addWarning(sqlw);
            }

        } else if (prepareSql == PREPARE) {
            int scrollOpt, ccOpt;

            ParamInfo prepParam[] = new ParamInfo[needCursor ? 6 : 4];

            // Setup prepare handle param
            prepParam[0] = new ParamInfo(Types.INTEGER, null, ParamInfo.OUTPUT);

            // Setup parameter descriptor param
            prepParam[1] = new ParamInfo(Types.LONGVARCHAR,
                    getParameterDefinitions(params),
                    ParamInfo.UNICODE);

            // Setup sql statemement param
            prepParam[2] = new ParamInfo(Types.LONGVARCHAR,
                    Support.substituteParamMarkers(sql, params),
                    ParamInfo.UNICODE);

            // Setup options param
            prepParam[3] = new ParamInfo(Types.INTEGER, new Integer(1), ParamInfo.INPUT);

            if (needCursor) {
                // Select the correct type of Server side cursor to
                // match the scroll and concurrency options.
                scrollOpt = MSCursorResultSet.getCursorScrollOpt(resultSetType,
                        resultSetConcurrency, true);
                ccOpt = MSCursorResultSet.getCursorConcurrencyOpt(resultSetConcurrency);

                // Setup scroll options parameter
                prepParam[4] = new ParamInfo(Types.INTEGER,
                        new Integer(scrollOpt),
                        ParamInfo.OUTPUT);

                // Setup concurrency options parameter
                prepParam[5] = new ParamInfo(Types.INTEGER,
                        new Integer(ccOpt),
                        ParamInfo.OUTPUT);
            }

            try {
                executeSQL(cx, null, needCursor ? "sp_cursorprepare" : "sp_prepare",
                        prepParam, false, 0, -1, -1, true);
                cx.processResults(true);
                if (cx.getTdsResultSet() == null) {
                    // There are none or more than one result sets
                    // in the response. Meta data cannot be cached!
                    cx.setColumns(null);
                }
                Integer prepareHandle = (Integer) prepParam[0].getOutValue();
                if (prepareHandle != null) {
                    ProcEntry pe = new ProcEntry();
                    pe.setName(prepareHandle.toString());
                    pe.setType(needCursor? ProcEntry.CURSOR: ProcEntry.PREPARE);
                    pe.setColMetaData(cx.getColumns());
                    return pe;
                }
                // Probably an exception occured, check for it
                cx.getMessages().checkErrors();
            } catch (SQLException e) {
                if ("08S01".equals(e.getSQLState())) {
                    // Serious (I/O) error, rethrow
                    throw e;
                }
                // This exception probably caused by failure to prepare
                // Add a warning
                SQLWarning sqlw = new SQLWarning(
                        Messages.get("error.prepare.prepfailed",
                                e.getMessage()),
                        e.getSQLState(), e.getErrorCode());
                sqlw.initCause(e);
                cx.getMessages().addWarning(sqlw);
            }
        }

        return null;
    }

    /**
     * Enlist the current connection in a distributed transaction or request the location of the
     * MSDTC instance controlling the server we are connected to.
     *
     * @param cx       the StatementImpl owning this prepare.
     * @param type      set to 0 to request TM address or 1 to enlist connection
     * @param oleTranID the 40 OLE transaction ID
     * @return a <code>byte[]</code> array containing the TM address data
     * @throws SQLException
     */
    byte[] enlistConnection(final StatementImpl cx, 
                            final int type, 
                            final byte[] oleTranID) throws SQLException 
    {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "enlistConnection", new Object[]{cx, new Integer(type), oleTranID}); 
        }
        if (tdsVersion >= TDS90 && type == 1 && oleTranID == null 
            && xaTransDescriptor == nullTransDesc) {
            // Already unenlisted after a transaction abort
            // do nothing now.
            return null;
        }
        try {
            lockNetwork();
            cx.initContext();
            
            out.setPacketType(MSDTC_PKT);
            if (tdsVersion >= TDS90) {
                writeTDS90Prefix(this.xaTransDescriptor);
            }
            out.write((short)type);
            switch (type) {
                case 0: // Get result set with location of MSTDC
                    out.write((short)0);
                    break;
                case 1: // Set OLE transaction ID
                    if (oleTranID != null) {
                        out.write((short)oleTranID.length);
                        out.write(oleTranID);
                    } else {
                        // Delist the connection from all transactions.
                        out.write((short)0);
                    }
                    break;
            }
            out.flush();
            endOfResponse = false;
            processResults(cx, true);
            byte[] tmAddress = null;
            ResultSetImpl rs = cx.getTdsResultSet();
            if (rs != null && rs.next()) {
                tmAddress = rs.getBytes(1);                
            }
            clearResponseQueue(cx);
            cx.getMessages().checkErrors();
            return tmAddress;
        } catch (IOException ioe) {
            connection.setClosed();
            SQLException sqle = new SQLException(
                            Messages.get(
                                    "error.generic.ioerror", ioe.getMessage()),
                            "08S01");
            sqle.initCause(ioe);
            throw sqle;
        } finally {
            freeNetwork();
        }

    }

// ---------------------- Private Methods from here ---------------------

    /**
     * Send the SQL Server 2000 pre login packet.
     * <p>Packet contains; netlib version, ssl mode, instance
     * and process ID.
     * @param instance
     * @param encryptionMode
     * @throws IOException
     */
    private void sendPreLoginPacket(final String instance, final int encryptionMode)
            throws IOException 
    {
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
        out.write((byte)(instance.length()+1));
        // Write process ID pointer
        out.write((short)3);
        out.write((short)(28+instance.length()+1));
        out.write((byte)4);
        // Write terminator
        out.write((byte)0xFF);
        // Write fake net lib ID 8.341.0
//        out.write(new byte[]{0x08, 0x00, 0x01, 0x55, 0x00, 0x00});
        out.write(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        // Write force encryption flag
        out.write((byte)encryptionMode);
        // Write instance name
        out.write(instance, connection.getCharset());
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
    private int[] readPreLoginPacket() throws IOException {
        byte list[][] = new byte[8][];
        byte data[][] = new byte[8][];
        int recordCount = 0;

        byte record[] = new byte[5];
        // Read entry pointers
        record[0] = (byte)in.read();
        if (record[0] == TDS_ERROR_TOKEN) {
            // Probably connecting to SQL Server 6.5
            throw new IOException(Messages.get("error.io.noprelogin"));
        }
        while ((record[0] & 0xFF) != 0xFF) {
            if (recordCount == list.length) {
                throw new IOException(Messages.get("error.io.badprelogin"));
            }
            // Read record
            in.read(record, 1, 4);
            list[recordCount++] = record;
            record = new byte[5];
            record[0] = (byte)in.read();
        }
        // Read entry data
        for (int i = 0; i < recordCount; i++) {
            byte value[] = new byte[list[i][4]];
            in.read(value);
            data[i] = value;
        }
        if (Logger.isTraceActive()) {
            // Diagnostic dump
            Logger.printTrace("PreLogin server response");
            for (int i = 0; i < recordCount; i++) {
                Logger.printTrace("Record " + i+ " = " +
                        Support.toHex(data[i]));
            }
        }
        int results[] =  new int[2];
        // Get SSL mode
        if (recordCount > 1) {
            results[0] = data[1][0]; // This is the server side SSL mode
        } else {
            // Response too short to include SSL mode!
            results[0] = SSL_NO_ENCRYPT;
        }
        // Server version
        if (recordCount > 0) {
            results[1] = data[0][0];
        } else {
            results[1] = SQL_SERVER_2000;
        }
        return results;
    }
    
    /**
     * Checks the <code>os.name</code> system property to see if it starts
     * with "windows".
     *
     * @return <code>true</code> if <code>os.name</code> starts with "windows",
     * else <code>false</code>.
     */
    static boolean isWindowsOS() {
        return System.getProperty("os.name").toLowerCase().startsWith("windows");
    }

    /**
     * Initializes the GSS context and creates the initial token.
     *
     * @throws GSSException
     * @throws UnknownHostException
     */
    private byte[] createGssToken() throws GSSException, UnknownHostException {
        GSSManager manager = GSSManager.getInstance();

        // Oids for Kerberos5
        Oid mech = new Oid("1.2.840.113554.1.2.2");
        Oid nameType = new Oid("1.2.840.113554.1.2.2.1");

        // Canonicalize hostname to create SPN like MIT Kerberos does
        String host = InetAddress.getByName(socket.getHost()).getCanonicalHostName();
        int port = socket.getPort();

        GSSName serverName = manager.createName("MSSQLSvc/" + host + ":" + port, nameType);

        Logger.println("GSS: Using SPN " + serverName);

        _gssContext = manager.createContext(serverName, mech, null, GSSContext.DEFAULT_LIFETIME);
        _gssContext.requestMutualAuth(true);

        byte[] token = new byte[0]; // Ignored on first call
        token = _gssContext.initSecContext(token, 0, token.length);

        Logger.println("GSS: Created GSS token (length: " + token.length + ")");

        return token;
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
     * @param domain        Windows NT domain (or <code>null</code>)
     * @param appName       application name
     * @param progName      program name
     * @param wsid          workstation ID
     * @param language      server language for messages
     * @param macAddress    client network MAC address
     * @param netPacketSize TDS packet size to use
     * @throws IOException if an I/O error occurs
     */
    private void sendMSLoginPkt(final String serverName,
                                final String database,
                                final String user,
                                final String password,
                                final String domain,
                                final String appName,
                                final String progName,
                                final String wsid,
                                final String language,
                                final String macAddress,
                                final int netPacketSize)
            throws IOException, SQLException {
        //
        // Check domain and user 
        //
        // It is possible to specify a SQL MDF file to attach but
        // there is no connection property for this defined at present.
        //
        final String databaseFile = "";

        final byte[] empty = new byte[0];
        boolean ntlmAuth = false;
        ntlmMessage = null;
        //
        // Set position of variable data relative to size of fixed part
        // of login block. SQL 2005 (TDS90) includes extra pointers.
        //
        short curPos = (short)((tdsVersion > TDS81)? 94: 86);

        boolean useKerberos = connection.getDataSource().getUseKerberos();
        if (useKerberos || user == null || user.length() == 0) {
             ntlmAuthSSO = true;
	         ntlmAuth = true;
        } else if (domain != null && domain.length() > 0) {
            // Assume we want to use Windows authentication with
            // supplied user and password.
            ntlmAuth = true;
        }
        if(useKerberos){
            try {
                ntlmMessage = createGssToken();
	        }catch (GSSException gsse) {
               throw new IOException("GSS Failed: " + gsse.getMessage());
            }
	         Logger.printTrace("Using Kerberos GSS authentication.");
        }else if (ntlmAuthSSO && isWindowsOS()) {
            // See if executing on a Windows platform and if so try and
            // use the single sign on native library.
            try {
                // Create the NTLM request block using the native library
                sspiJNIClient = SSPIJNIClient.getInstance();
                ntlmMessage = sspiJNIClient.invokePrepareSSORequest();
            } catch (Exception e) {
                throw new IOException("SSO Failed: " + e.getMessage());
            }
            Logger.printTrace("Using native SSO library for Windows Authentication.");
        } else if (ntlmAuthSSO) {
            // Try Unix-based Kerberos SSO
	         try {
                ntlmMessage = createGssToken();
	         }
            catch (GSSException gsse) {
               throw new IOException("GSS Failed: " + gsse.getMessage());
            }
	         Logger.printTrace("Using Kerberos GSS authentication.");
        }

        //mdb:begin-change
        short packSize = (short) (curPos + 2 *
                (wsid.length() +
                appName.length() +
                serverName.length() +
                progName.length() +
                database.length() +
                language.length()));
        final short authLen;
        //NOTE(mdb): ntlm includes auth block; sql auth includes uname and pwd.
        if (ntlmAuth) {
            if (ntlmAuthSSO && ntlmMessage != null) {
                authLen = (short) ntlmMessage.length;
            } else {
                authLen = (short) (32 + domain.length()); // 32 = size of ntlm block
            }
            packSize += authLen;
        } else {
            authLen = 0;
            packSize += (2 * (user.length() + password.length()));
        }
        //mdb:end-change

        out.setPacketType(MSLOGIN_PKT);
        out.write((int)packSize);
        // TDS version
        if (tdsVersion == TDS70) {
            // SQL Server 7
            out.write((int)0x70000000);
        } else 
        if (tdsVersion == TDS90) {
            // SQL Server 2005
            out.write((int)0x72090002);
        } else {
            // SQL Server 2000
            out.write((int)0x71000001);
        }
        // Network Packet size requested by client
        out.write((int)netPacketSize);
        // Program version?
        out.write(0x7000000);
        // Process ID - no way to get this from java so use 123
        out.write((int)123);
        // Connection ID
        out.write((int)0);
        // 0x10: enable bulk load / copy
        // 0x20: enable warning messages if USE <database> issued
        // 0x40: change to initial database must succeed
        // 0x80: enable warning messages if SET LANGUAGE issued
        byte flags = (byte) (0x20 | 0x40 | 0x80);
        out.write(flags);

        //mdb: this byte controls what kind of auth we do.
        flags = 0x03; // ODBC (JDBC) driver
        if (ntlmAuth)
            flags |= 0x80; // Use NT authentication
        out.write(flags);

        out.write((byte)0); // SQL type flag
        out.write((byte)0); // Reserved flag
        // TODO Set Timezone and collation?
        out.write(empty, 0, 4); // Time Zone
        out.write(empty, 0, 4); // Collation

        // Pack up value lengths, positions.

        // Hostname
        out.write((short)curPos);
        out.write((short) wsid.length());
        curPos += wsid.length() * 2;

        //mdb: NTLM doesn't send username and password...
        if (!ntlmAuth) {
            // Username
            out.write((short)curPos);
            out.write((short) user.length());
            curPos += user.length() * 2;

            // Password
            out.write((short)curPos);
            out.write((short) password.length());
            curPos += password.length() * 2;
        } else {
            out.write((short)curPos); 
            out.write((short) 0);

            out.write((short)curPos); 
            out.write((short) 0);
        }

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

        //mdb: location of ntlm auth block. note that for sql auth, authLen==0.
        // Allow for database file name which must come before NTLM block if used
        out.write((short)(curPos + databaseFile.length() * 2));
        out.write((short)authLen);

        out.write((short)curPos);
        out.write((short)(databaseFile.length() * 2));
        
        if (tdsVersion >= TDS90) {
            out.write((int)0); // Unknown possibly old and new passwords
            out.write((int)0); // for client side password expiry feature?
        }
        out.writeUnicode(wsid);

        // Pack up the login values.
        //mdb: for ntlm auth, uname and pwd aren't sent up...
        if (!ntlmAuth) {
            final String scrambledPw = tds7CryptPass(password);
            out.writeUnicode(user);
            out.writeUnicode(scrambledPw);
        }

        out.writeUnicode(appName);
        out.writeUnicode(serverName);
        out.writeUnicode(progName);
        out.writeUnicode(language);
        out.writeUnicode(database);
        out.writeUnicode(databaseFile);

        //mdb: add the ntlm auth info...
        if (ntlmAuth) {
            if (ntlmAuthSSO) {
                // Use the NTLM message generated by the native library
                out.write(ntlmMessage);
            } else {
                // host and domain name are _narrow_ strings.
                final byte[] domainBytes = domain.getBytes("UTF8");
                //byte[] hostBytes   = localhostname.getBytes("UTF8");

                final byte[] header = {0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00};
                out.write(header); //header is ascii "NTLMSSP\0"
                out.write((int)1);          //sequence number = 1
                if(connection.getDataSource().getUseNTLMv2())
                    out.write((int)0x8b205);  //flags (same as below, only with Request Target and NTLM2 set)
                else
                    out.write((int)0xb201);     //flags (see below)

                // NOTE: flag reference:
                //  0x80000 = negotiate NTLM2 key
                //  0x08000 = negotiate always sign
                //  0x02000 = client is sending workstation name
                //  0x01000 = client is sending domain name
                //  0x00200 = negotiate NTLM
                //  0x00004 - Request Target, which requests that server send target
                //  0x00001 = negotiate Unicode

                //domain info
                out.write((short) domainBytes.length);
                out.write((short) domainBytes.length);
                out.write((int)32); //offset, relative to start of auth block.

                //host info
                //NOTE(mdb): not sending host info; hope this is ok!
                out.write((short) 0);
                out.write((short) 0);
                out.write((int)32); //offset, relative to start of auth block.

                // add the variable length data at the end...
                out.write(domainBytes);
            }
        }
        out.flush(); // Send the packet
    }

    /**
     * Send the next GSS authentication token.
     *
     * @throws IOException
     */
    private void sendGssToken() throws IOException {
			try {
				  Logger.println(new HexDumpEncoder().encodeBuffer(ntlmMessage)); 
			    byte gssMessage[] = _gssContext.initSecContext(ntlmMessage,
									   0,
									   ntlmMessage.length);
			    
			    if (_gssContext.isEstablished()) {
						Logger.println("GSS: Security context established.");
			    }
			    
			    if (gssMessage != null) {
						Logger.println("GSS: Sending token (length: " +
							       ntlmMessage.length + ")");
						out.setPacketType(NTLMAUTH_PKT);
						out.write(gssMessage);
						out.flush();
			    }
			}
			catch (GSSException e) {
			    throw new IOException("GSS failure: " + e.getMessage());
			}
    }
    
    /**
     * Send the response to the NTLM authentication challenge.
     * @param user The user name.
     * @param password The user password.
     * @param domain The Windows NT Dommain.
     * @throws java.io.IOException
     */
    private void sendNtlmChallengeResponse(final String user,
                                           final String password,
                                           final String domain)
            throws java.io.IOException {
        out.setPacketType(NTLMAUTH_PKT);

        // Prepare and Set NTLM Type 2 message appropriately
        // Author: mahi@aztec.soft.net
        if (ntlmAuthSSO) {
            try {
                // Create the challenge response using the native library
                this.ntlmMessage = sspiJNIClient.invokePrepareSSOSubmit(this.ntlmMessage);
            } catch (Exception e) {
                throw new IOException("SSO Failed: " + e.getMessage());
            }
            out.write(this.ntlmMessage);
        } else {
            // host and domain name are _narrow_ strings.
            //byte[] domainBytes = domain.getBytes("UTF8");
            //byte[] user        = user.getBytes("UTF8");


            byte[] lmAnswer, ntAnswer;
            //the response to the challenge...

            if(connection.getDataSource().getUseNTLMv2())
            {
                //TODO: does this need to be random?
                //byte[] clientNonce = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
                byte[] clientNonce = new byte[8];
                (new Random()).nextBytes(clientNonce);

                lmAnswer = NtlmAuth.answerLmv2Challenge(domain, user, password, nonce, clientNonce);
                ntAnswer = NtlmAuth.answerNtlmv2Challenge(
                        domain, user, password, nonce, this.ntlmTarget, clientNonce);
            }
            else
            {
                //LM/NTLM (v1)
                lmAnswer = NtlmAuth.answerLmChallenge(password, nonce);
                ntAnswer = NtlmAuth.answerNtChallenge(password, nonce);
            }

            final byte[] header = {0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00};
            out.write(header); //header is ascii "NTLMSSP\0"
            out.write((int)3); //sequence number = 3
            final int domainLenInBytes = domain.length() * 2;
            final int userLenInBytes = user.length() * 2;
            //mdb: not sending hostname; I hope this is ok!
            final int hostLenInBytes = 0; //localhostname.length()*2;
            int pos = 64 + domainLenInBytes + userLenInBytes + hostLenInBytes;
            // lan man response: length and offset
            out.write((short)lmAnswer.length);
            out.write((short)lmAnswer.length);
            out.write((int)pos);
            pos += lmAnswer.length;
            // nt response: length and offset
            out.write((short)ntAnswer.length);
            out.write((short)ntAnswer.length);
            out.write((int)pos);
            pos = 64;
            //domain
            out.write((short) domainLenInBytes);
            out.write((short) domainLenInBytes);
            out.write((int)pos);
            pos += domainLenInBytes;

            //user
            out.write((short) userLenInBytes);
            out.write((short) userLenInBytes);
            out.write((int)pos);
            pos += userLenInBytes;
            //local hostname
            out.write((short) hostLenInBytes);
            out.write((short) hostLenInBytes);
            out.write((int)pos);
            pos += hostLenInBytes;
            //unknown
            out.write((short) 0);
            out.write((short) 0);
            out.write((int)pos);
            //flags
            if(connection.getDataSource().getUseNTLMv2())
                out.write((int)0x88201);
            else
                out.write((int)0x8201);
            //variable length stuff...
            out.writeUnicode(domain);
            out.writeUnicode(user);
            //Not sending hostname...I hope this is OK!
            //comm.appendChars(localhostname);

            //the response to the challenge...
            out.write(lmAnswer);
            out.write(ntAnswer);
        }
        out.flush();
    }

    /**
     * Read the next TDS token from the response stream.
     * @param  cx the StatementImpl instance that owns this request.
     * @throws SQLException if an I/O or protocol error occurs
     */
    protected void nextToken(final StatementImpl cx)
        throws SQLException
    {
        try {
            this.token = (byte)in.read();
            switch (this.token) {
                case TDS_RETURNSTATUS_TOKEN:
                    tdsReturnStatusToken(cx);
                    break;
                case TDS_PROCID:
                    tdsProcIdToken();
                    break;
                case TDS_OFFSETS_TOKEN:
                    tdsOffsetsToken();
                    break;
                case TDS7_RESULT_TOKEN:
                    tds7ResultToken(cx);
                    break;
                case TDS7_COMP_RESULT_TOKEN:
                    tdsInvalidToken();
                    break;
                case TDS_TABNAME_TOKEN:
                    tdsTableNameToken();
                    break;
                case TDS_COLINFO_TOKEN:
                    tdsColumnInfoToken(cx);
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
                    tdsErrorToken(cx);
                    break;
                case TDS_PARAM_TOKEN:
                    tdsOutputParamToken(cx);
                    break;
                case TDS_LOGINACK_TOKEN:
                    tdsLoginAckToken(cx);
                    break;
                case TDS_CONTROL_TOKEN:
                    tdsControlToken();
                    break;
                case TDS_ROW_TOKEN:
                    tdsRowToken(cx);
                    break;
                case TDS_ALTROW:
                    tdsInvalidToken();
                    break;
                case TDS_ENVCHANGE_TOKEN:
                    tdsEnvChangeToken();
                    break;
                case TDS_AUTH_TOKEN:
                    if (_gssContext != null) {
                       tdsGssToken();  
                    } else {
                       tdsNtlmAuthToken();
                    }
                    break;
                case TDS_DONE_TOKEN:
                case TDS_DONEPROC_TOKEN:
                case TDS_DONEINPROC_TOKEN:
                    tdsDoneToken(cx);
                    break;
                default:
                    tdsInvalidToken();
            }
        } catch (IOException ioe) {
            connection.setClosed();
            SQLException sqle = new SQLException(
                       Messages.get(
                                "error.generic.ioerror", ioe.getMessage()),
                                    "08S01");
            sqle.initCause(ioe);
            throw sqle;
        } catch (OutOfMemoryError err) {
            // Consume the rest of the response
            in.skipToEnd();
            endOfResponse = true;
            cancelPending = false;
            throw err;
        }
    }

    /**
     * Process stored procedure return status token.
     *
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tdsReturnStatusToken(final StatementImpl cx) 
        throws IOException, SQLException 
    {
        cx.setReturnParam(in.readInt());
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
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tds7ResultToken(final StatementImpl cx)
            throws IOException, SQLException 
    {

        int colCnt = in.readShort();

        if (colCnt < 0) {
            // Short packet returned by TDS8 when the column meta data is
            // supressed on cursor fetch etc.
            // NB. With TDS7 no result set packet is returned at all.
            return;
        }

        ColInfo[] columns = new ColInfo[colCnt];
        tables = null;

        for (int i = 0; i < colCnt; i++) {
            ColInfo col = new ColInfo();

            if (tdsVersion < TDS90) {
                col.userType = in.readShort();
            } else {
                // User type extended to 32 bits for SQL 2005
                col.userType = in.readInt();
            }
            int flags = in.readShort();

            col.nullable = ((flags & 0x01) != 0) ?
                                ResultSetMetaData.columnNullable :
                                ResultSetMetaData.columnNoNulls;
            col.isCaseSensitive = (flags & 0X02) != 0;
            col.isIdentity = (flags & 0x10) != 0;
            col.isWriteable = (flags & 0x0C) != 0;
            readType(col);

            int clen = in.read();

            col.realName = in.readUnicode(clen);
            col.name = col.realName;

            columns[i] = col;
        }
        cx.setColumns(columns);
    }

    /**
     * Process a table name token.
     * <p> Sent by select for browse or cursor functions.
     *
     * @throws IOException
     */
    private void tdsTableNameToken() throws IOException {
        final int pktLen = in.readShort();
        int bytesRead = 0;
        ArrayList<TableMetaData> tableList = new ArrayList<TableMetaData>();

        while (bytesRead < pktLen) {
            int    nameLen;
            String tabName;
            TableMetaData table;
            if (tdsVersion >= TDS81) {
                // TDS8.1 supplies the server.database.owner.table as up to
                // four separate components which allows us to have names
                // with embedded periods.
                table = new TableMetaData();
                bytesRead++;
                int tableNameToken = in.read();
                switch (tableNameToken) {
                    case 4: nameLen = in.readShort();
                            bytesRead += nameLen * 2 + 2;
                            // Read and discard server name; see Bug 1403067
                            in.readUnicode(nameLen);
                    case 3: nameLen = in.readShort();
                            bytesRead += nameLen * 2 + 2;
                            table.catalog = in.readUnicode(nameLen);
                    case 2: nameLen = in.readShort();
                            bytesRead += nameLen * 2 + 2;
                            table.schema = in.readUnicode(nameLen);
                    case 1: nameLen = in.readShort();
                            bytesRead += nameLen * 2 + 2;
                            table.name = in.readUnicode(nameLen);
                    case 0: break;
                    default:
                        throw new IOException("Invalid table TAB_NAME_TOKEN: "
                                                    + tableNameToken);
                }
            } else {
                nameLen = in.readShort();
                bytesRead += nameLen * 2 + 2;
                tabName  = in.readUnicode(nameLen);
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
            this.tables = tableList.toArray(new TableMetaData[tableList.size()]);
        }
    }

    /**
     * Process a column infomation token.
     * <p>Sent by select for browse or cursor functions.
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tdsColumnInfoToken(final StatementImpl cx)
        throws IOException
    {
        final int pktLen = in.readShort();
        int bytesRead = 0;
        int columnIndex = 0;
        ColInfo[] columns = cx.getColumns();
        
        while (bytesRead < pktLen) {
            // Seems like all columns are always returned in the COL_INFO
            // packet and there might be more than 255 columns, so we'll
            // just increment a counter instead.
            // Ignore the column index.
            in.read();
            if (columnIndex >= columns.length) {
                throw new IOException("Column index " + (columnIndex + 1) +
                        " invalid in TDS_COLINFO packet");
            }
            ColInfo col = columns[columnIndex++];
            int tableIndex = in.read();
            // In some cases (e.g. if the user calls 'CREATE CURSOR'), the
            // TDS_TABNAME packet seems to be missing although the table index
            // in this packet is > 0. Weird.
            // If tables are available check for valid table index.
            if (tables != null && tableIndex > tables.length) {
                throw new IOException("Table index " + tableIndex +
                        " invalid in TDS_COLINFO packet");
            }
            byte flags = (byte)in.read(); // flags
            bytesRead += 3;

            if (tableIndex != 0 && tables != null) {
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
                final String colName = in.readUnicode(nameLen);
                bytesRead += nameLen * 2;
                col.realName = colName;
            }
        }
    }

    /**
     * Process an order by token.
     * <p>Sent to describe columns in an order by clause.
     * @throws IOException
     */
    private void tdsOrderByToken() throws IOException
    {
        // Skip this packet type
        int pktLen = in.readShort();
        in.skip(pktLen);
    }

    /**
     * Process a TD4/TDS7 error or informational message.
     *
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tdsErrorToken(final StatementImpl cx) throws IOException
    {
        int pktLen = in.readShort(); // Packet length
        int sizeSoFar = 6;
        int number = in.readInt();
        in.read(); // state
        int severity = in.read();
        int msgLen = in.readShort();
        String message = in.readUnicode(msgLen);
        sizeSoFar += 2 + msgLen * 2;
        final int srvNameLen = in.read();
        in.readUnicode(srvNameLen); // server name
        sizeSoFar += 1 + srvNameLen * 2;

        final int procNameLen = in.read();
        in.readUnicode(procNameLen); // proc name
        sizeSoFar += 1 + procNameLen * 2;

        in.readShort(); // line
        sizeSoFar += 2;
        // Skip any EED information to read rest of packet
        if (pktLen - sizeSoFar > 0)
            in.skip(pktLen - sizeSoFar);

        if (this.token == TDS_ERROR_TOKEN)
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

        cx.getMessages().addDiagnostic(number, severity, message);
    }

    /**
     * Process output parameters.
     * </p>
     * Normally the output parameters are preceded by a TDS type 79
     * (procedure return value) record; however there are at least two
     * situations with TDS version 8 where this is not the case:
     * <ol>
     * <li>For the return value of a SQL 2000+ user defined function.</li>
     * <li>For a remote procedure call (server.database.user.procname) where
     * the 79 record is only sent if a result set is also returned by the remote
     * procedure. In this case the 79 record just acts as marker for the start of
     * the output parameters. The actual return value is in an output param token.</li>
     * </ol>
     * Output parameters are distinguished from procedure return values by the value of
     * a byte that immediately follows the parameter name. A value of 1 seems to indicate
     * a normal output parameter while a value of 2 indicates a procedure return value.
     *
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tdsOutputParamToken(final StatementImpl cx)
        throws IOException, SQLException {
        in.readShort(); // Packet length
        String name = in.readUnicode(in.read()); // Column Name
        // Next byte indicates if output parameter or return value
        // 1 = normal output param, 2 = function or stored proc return
        boolean funcReturnVal = (in.read() == 2);
        // Next byte is the parameter type that we supplied which
        // may not be the same as the parameter definition
        /* int inputTdsType = */ in.read();
        // Not sure what these bytes are (they always seem to be zero).
        if (tdsVersion < TDS90) {
            in.skip(3);
        } else {
            in.skip(5);
        }
        ColInfo col = new ColInfo();
        readType(col);
        Object value = readData(col);

        //
        // Real output parameters will either be unnamed or will have a valid
        // parameter name beginning with '@'. Ignore any other spurious parameters
        // such as those returned from calls to writetext in the proc.
        //
        if (name.length() == 0 || name.startsWith("@")) {
            if (tdsVersion >= TDS80 && funcReturnVal) {
                // TDS 8 Allows function return values of types other than int
                // Also used to for return value of remote procedure calls.
                cx.setReturnParam(value, col);
            } else {
                // Set next output parameter in list
                cx.setNextOutputParam(value, col);
            }
        }
    }

    /**
     * Process a login acknowledgement packet.
     *
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tdsLoginAckToken(final StatementImpl cx) throws IOException {
        String product;
        int major, minor, build = 0;
        in.readShort(); // Packet length

        /* int ack = */in.read(); // 1/0 value

        // Update the TDS protocol version in this TdsCore and in the Socket.
        // The Connection will update itself immediately after this call.
        // As for other objects containing a TDS version value, there are none
        // at this point (we're just constructing the Connection).
        tdsVersion = getTdsSubVersion((in.read() << 24) | (in.read() << 16)
                | (in.read() << 8) | in.read());

        product = in.readUnicode(in.read());

        major = in.read();
        minor = in.read();
        build = in.read() << 8;
        build += in.read();

        if (product.length() > 1 && -1 != product.indexOf('\0')) {
            product = product.substring(0, product.indexOf('\0'));
        }

        connection.setDBServerInfo(product, major, minor, build, this.serverType);

        // MJH 2005-11-02
        // If we get this far we are logged in OK so convert
        // any database security exceptions into warnings. 
        // Any exceptions are likely to be caused by problems in 
        // accessing the default database for this login id for 
        // SQL 7.0+ will fail to login if there is
        // no access to the default or specified database.
        // I am not convinced that this is a good idea but it
        // appears that other drivers e.g. jConnect do this and
        // return the exceptions on the connection warning chain.
        // See bug/RFE [1346086] Problem with DATABASE name change on Sybase
        //
        // Avoid returning useless warnings about language
        // character set etc.
        cx.getMessages().clearWarnings();
        //
        // Get list of exceptions
        SQLException ex = cx.getMessages().getExceptions();
        // Clear old exception list
        cx.getMessages().clearExceptions();
        //
        // Convert default database security exceptions to warnings
        //
        while (ex != null) {
            if (ex.getErrorCode() == ERR_INVALID_USER 
                || ex.getErrorCode() == ERR_INVALID_USER_2
                || ex.getErrorCode() == ERR_NO_DEFAULT_DB) {
                cx.getMessages().addWarning(new SQLWarning(ex.getMessage(), 
                                             ex.getSQLState(), 
                                             ex.getErrorCode()));
            } else {
                cx.getMessages().addException(new SQLException(ex.getMessage(), 
                                                 ex.getSQLState(), 
                                                 ex.getErrorCode()));
            }
            ex = ex.getNextException();
        }
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
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tdsRowToken(final StatementImpl cx) throws IOException, SQLException {
        ColInfo[] columns = cx.getColumns();
        Object[] row  = cx.getRowBuffer();
        for (int i = 0; i < columns.length; i++) {
            row[i] = readData(columns[i]);
        }
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
                    final String newDb = in.readUnicode(clen);
                    clen = in.read();
                    final String oldDb = in.readUnicode(clen);
                    connection.setDatabase(newDb, oldDb);
                    break;
                }

            case TDS_ENV_LANG:
                {
                    int clen = in.read();
                    String language = in.readUnicode(clen);
                    clen = in.read();
                    String oldLang = in.readUnicode(clen);
                    if (Logger.isTraceActive()) {
                        Logger.printTrace("Language changed from " + oldLang + " to " + language);
                    }
                    break;
                }

            case TDS_ENV_CHARSET:
                {
                    final int clen = in.read();
                    final String charset = in.readUnicode(clen);
                    in.skip(len - 2 - clen * 2);
                    connection.setServerCharset(charset);
                    break;
                }

            case TDS_ENV_PACKSIZE:
                    {
                        final int blocksize;
                        final int clen = in.read();
                        blocksize = Integer.parseInt(in.readUnicode(clen));
                        in.skip(len - 2 - clen * 2);
                        out.setBufferSize(blocksize);
                        if (Logger.isTraceActive()) {
                            Logger.printTrace("Changed blocksize to " + blocksize);
                        }
                    }
                    break;

            case TDS_ENV_LCID:
                    // Locale ID - Only sent by TDS 7
                    // In TDS 8 replaced by column specific collation info.
                    in.skip(len - 1);
                    break;

            case TDS_ENV_UNICODE_COMP:
                    // Unicode comparison style - Only sent by TDS 7
                    // In TDS 8 replaced by column specific collation info.
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

            case TDS_ENV_START_TRAN:
                {
                    int tlen = in.read();
                    if (tlen != 8) {
                        Logger.println("SQL 2005 start tran expected 8 bytes");
                    }
                    byte tranDesc[] = new byte[tlen];
                    in.read(tranDesc);
                    tlen = in.read();
                    if (tlen != 0) {
                        Logger.println("SQL 2005 start tran expected 0 bytes");
                    }
                    if (Logger.isTraceActive()) {
                        Logger.printTrace("Start Transaction " + 
                                Support.toHex(tranDesc));
                    }
                    this.transDescriptor = tranDesc;
                    break;
                }

            case TDS_ENV_END_TRAN:
            {
                int tlen = in.read();
                if (tlen != 0) {
                    Logger.println("SQL 2005 end tran expected 0 bytes");
                }
                in.skip(tlen);
                tlen = in.read();
                if (tlen != 8) {
                    Logger.println("SQL 2005 end tran expected 8 bytes");
                }
                in.skip(tlen);
                if (Logger.isTraceActive()) {
                    Logger.printTrace("End Transaction " + 
                            Support.toHex(this.transDescriptor));
                }
                this.transDescriptor = nullTransDesc;
                break;
            }

                
            case TDS_ENV_TRAN_ABORTED:
                {
                    int tlen = in.read();
                    if (tlen != 0) {
                        Logger.println("SQL 2005 tran aborted expected 0 bytes");
                    }
                    in.skip(tlen);
                    tlen = in.read();
                    if (tlen != 8) {
                        Logger.println("SQL 2005 tran aborted expected 8 bytes");
                    }
                    in.skip(tlen);
                    if (Logger.isTraceActive()) {
                        Logger.printTrace("Transaction aborted " + 
                                Support.toHex(this.transDescriptor));
                    }
                    this.transDescriptor = nullTransDesc;
                    //
                    // It may make sense to generate a specific exception for 
                    // transaction aborts rather than relying on the original
                    // cause generating an exception.
                    //
                    // cx.addException(
                    //        new SQLException(
                    //               Messages.get("error.generic.txabort"), 
                    //                "S1000", 
                    //                0));
                    break;
                }
                
            case TDS_ENV_START_XATRAN:
                {
                    int tlen = in.read();
                    if (tlen != 8) {
                        Logger.println("SQL 2005 start XA tran expected 8 bytes");
                    }
                    byte tranDesc[] = new byte[tlen];
                    in.read(tranDesc);
                    tlen = in.read();
                    if (tlen != 0) {
                        Logger.println("SQL 2005 start XA tran expected 0 bytes");
                    }
                    if (Logger.isTraceActive()) {
                        Logger.printTrace("Start XA Transaction " + 
                                Support.toHex(tranDesc));
                    }
                    this.transDescriptor = tranDesc;
                    this.xaTransDescriptor = tranDesc;
                    break;
                }

            case TDS_ENV_END_XATRAN:
                {
                    int tlen = in.read();
                    if (tlen != 0) {
                        Logger.println("SQL 2005 end XA tran expected 0 bytes");
                    }
                    in.skip(tlen);
                    tlen = in.read();
                    if (tlen != 8) {
                        Logger.println("SQL 2005 end XA tran expected 8 bytes");
                    }
                    in.skip(tlen);
                    if (Logger.isTraceActive()) {
                        Logger.printTrace("End XA Transaction " + 
                                Support.toHex(this.xaTransDescriptor));
                    }
                    this.transDescriptor   = nullTransDesc;
                    this.xaTransDescriptor = nullTransDesc;
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
     * Receive a GSS token.
     *
     * @throws IOException
     */
    private void tdsGssToken() throws IOException
    {
	int pktLen = in.readShort();

	this.ntlmMessage = new byte[pktLen];
	in.read(this.ntlmMessage);

	Logger.println("GSS: Received token (length: " +
		       this.ntlmMessage.length + ")");
    }
    
    /**
     * Process a NTLM Authentication challenge.
     *
     * @throws IOException
     */
    private void tdsNtlmAuthToken() throws IOException
    {
        int pktLen = in.readShort(); // Packet length

        int hdrLen = 40;

        if (pktLen < hdrLen)
            throw new IOException("NTLM challenge: packet is too small:" + pktLen);

        this.ntlmMessage = new byte[pktLen];
        in.read(this.ntlmMessage);

        final int seq = getIntFromBuffer(this.ntlmMessage, 8);
        if (seq != 2)
            throw new IOException("NTLM challenge: got unexpected sequence number:" + seq);

        // final int flags = getIntFromBuffer(this.ntlmMessage, 20 );
        //NOTE: the context is always included; if not local, then it is just
        //      set to all zeros.
        //boolean hasContext = ((flags &   0x4000) != 0);
        //final boolean hasContext = true;
        //NOTE: even if target is omitted, the length will be zero.
        //final boolean hasTarget  = ((flags & 0x800000) != 0);

        //extract the target, if present. This will be used for ntlmv2 auth.
        final int headerOffset = 40; // The assumes the context is always there, which appears to be the case.
        //header has: 2 byte lenght, 2 byte allocated space, and four-byte offset.
        int size = getShortFromBuffer( this.ntlmMessage, headerOffset);
        int offset = getIntFromBuffer( this.ntlmMessage, headerOffset + 4);
        this.ntlmTarget = new byte[size];
        System.arraycopy(this.ntlmMessage, offset, this.ntlmTarget, 0, size);

        this.nonce = new byte[8];
        System.arraycopy(ntlmMessage, 24, this.nonce, 0, 8);
    }

    private static int getIntFromBuffer(final byte[] buf, final int offset)
    {
        int b1 = (buf[offset] & 0xff);
        int b2 = (buf[offset+1] & 0xff) << 8;
        int b3 = (buf[offset+2] & 0xff) << 16;
        int b4 = (buf[offset+3] & 0xff) << 24;
        return b4 | b3 | b2 | b1;
    }

    private static int getShortFromBuffer(final byte[] buf, final int offset)
    {
        int b1 = (buf[offset] & 0xff);
        int b2 = (buf[offset+1] & 0xff) << 8;
        return b2 | b1;
    }

    /**
     * Process a DONE, DONEINPROC or DONEPROC token.
     *
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tdsDoneToken(final StatementImpl cx) throws IOException {
        this.doneStatus = (byte)in.read();
        in.skip(1);
        byte operation = (byte)in.read();
        in.skip(1);
        this.doneCount = in.readInt();
        if (tdsVersion >= TDS90) {
            // Update count extended to 64 bits for SQL 2005
            if (in.readInt() > 0) {
                // More than 2G results
                this.doneCount = Integer.MAX_VALUE;
            }
        }

        //
        // Check for cancel ack
        //
        if ((this.doneStatus & DONE_CANCEL) != 0) {
            // Synchronize resetting of the cancelPending flag to ensure it
            // doesn't happen during the sending of a cancel request
            synchronized (cancelMonitor) {
                cancelPending = false;
                // Only throw an exception if this was a cancel() call
                if (cancelMonitor[0] == ASYNC_CANCEL) {
                    cx.getMessages().addException(
                        new SQLException(Messages.get("error.generic.cancelled",
                                                      "Statement"),
                                         "HY008"));
                }
            }
        }

        if ((this.doneStatus & DONE_MORE_RESULTS) == 0) {
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
        if (operation == (byte) 0xC1) {
            // For select supress row counts
            this.doneStatus &= ~DONE_ROW_COUNT;
        }
    }

    /**
     * Returns <code>true</code> if the specified <code>procName</code>
     * is a sp_prepare or sp_prepexec handle; returns <code>false</code>
     * otherwise.
     *
     * @param procName Stored procedure to execute or <code>null</code>.
     * @return <code>true</code> if the specified <code>procName</code>
     *   is a sp_prepare or sp_prepexec handle; <code>false</code>
     *   otherwise.
     */
    static boolean isPreparedProcedureName(final String procName) {
        return procName != null && procName.length() > 0
                && Character.isDigit(procName.charAt(0));
    }

    /**
     * Write the SQL 2005 TDS90 packet prefix.
     * 
     * @throws IOException
     */
    private void writeTDS90Prefix(final byte[] transDesc) throws IOException
    {
        out.write((int)22); // Prefix length
        out.write((int)18); // ?
        out.write((short)2);
        out.write(transDesc);
        out.write((int)1);
    }
    
    /**
     * Execute SQL using TDS 7.0 protocol.
     *
     * @param cx the StatementImpl instance that owns this request.
     * @param sql The SQL statement to execute.
     * @param procName Stored procedure to execute or <code>null</code>.
     * @param parameters Parameters for call or <code>null</code>.
     * @param noMetaData Suppress meta data for cursor calls.
     * @param sendNow true to actually send the packet.
     * @throws SQLException
     */
    protected void localExecuteSQL(final StatementImpl cx,
                                   String sql,
                                   String procName,
                                   ParamInfo[] parameters,
                                   final boolean noMetaData,
                                   final boolean sendNow)
        throws IOException, SQLException {
        int prepareSql = connection.getPrepareSql();

        if (parameters == null && prepareSql == EXECUTE_SQL) {
            // Downgrade EXECUTE_SQL to UNPREPARED
            // if there are no parameters.
            //
            // Should we downgrade TEMPORARY_STORED_PROCEDURES and PREPARE as well?
            // No it may be a complex select with no parameters but costly to
            // evaluate for each execution.
            prepareSql = UNPREPARED;
        }

        if (inBatch) {
            // For batch execution with parameters
            // we need to be consistant and use
            // execute SQL
            prepareSql = EXECUTE_SQL;
        }

        if (procName == null) {
            // No procedure name so not a callable statement and also
            // not a temporary stored procedure call.
            if (parameters != null) {
                if (prepareSql == UNPREPARED) {
                    // Low tech approach just substitute parameter data into the
                    // SQL statement.
                    sql = Support.substituteParameters(sql, parameters, connection);
                } else {
                    // If we have parameters then we need to use sp_executesql to
                    // parameterise the statement
                    ParamInfo[] params;

                    params = new ParamInfo[2 + parameters.length];
                    System.arraycopy(parameters, 0, params, 2, parameters.length);

                    params[0] = new ParamInfo(Types.LONGVARCHAR,
                            Support.substituteParamMarkers(sql, parameters),
                            ParamInfo.UNICODE);
                    setNativeType(params[0]);

                    params[1] = new ParamInfo(Types.LONGVARCHAR,
                            getParameterDefinitions(parameters),
                            ParamInfo.UNICODE);
                    setNativeType(params[1]);

                    parameters = params;

                    // Use sp_executesql approach
                    procName = "sp_executesql";
                }
            }
        } else {
            // Either a stored procedure name has been supplied or this
            // statement should executed using a prepared statement handle
            if (isPreparedProcedureName(procName)) {
                // If the procedure is a prepared handle then redefine the
                // procedure name as sp_execute with the handle as a parameter.
                ParamInfo params[];

                if (parameters != null) {
                    params = new ParamInfo[1 + parameters.length];
                    System.arraycopy(parameters, 0, params, 1, parameters.length);
                } else {
                    params = new ParamInfo[1];
                }

                params[0] = new ParamInfo(Types.INTEGER, new Integer(procName),
                        ParamInfo.INPUT);
                setNativeType(params[0]);

                parameters = params;

                // Use sp_execute approach
                procName = "sp_execute";
            }
        }

        if (procName != null) {
            // RPC call
            Logger.printRPC(procName);
            out.setPacketType(RPC_PKT);
            if (tdsVersion >= TDS90 && startBatch) {
                writeTDS90Prefix(transDescriptor);
            }
            Integer shortcut;

            if (tdsVersion >= TDS80
                    && (shortcut = tds8SpNames.get(procName)) != null) {
                // Use the shortcut form of procedure name for TDS8
                out.write((short) -1);
                out.write((short) shortcut.shortValue());
            } else {
                out.write((short) procName.length());
                out.writeUnicode(procName);
            }
            //
            // If noMetaData is true then column meta data will be supressed.
            // This option is used by sp_cursorfetch or optionally by sp_execute
            // provided that the required meta data has been cached.
            //
            out.write((short) (noMetaData ? 2 : 0));

            if (parameters != null) {
                // Send the required parameter data
                for (int i = cx.getParamIndex() + 1; i < parameters.length; i++) {
                    if (parameters[i].name != null) {
                       out.write((byte) parameters[i].name.length());
                       out.writeUnicode(parameters[i].name);
                    } else {
                       out.write((byte) 0);
                    }

                    out.write((byte) (parameters[i].isOutput ? 1 : 0));

                    writeParam(parameters[i]);
                }
            }
            if (!sendNow) {
                // Append RPC packets
                out.write((tdsVersion >= TDS90)? 
                           (byte) BATCH_SEPARATOR_TDS90:
                           (byte) BATCH_SEPARATOR);
            }
        } else if (sql.length() > 0) {
            // Simple SQL query with no parameters
            Logger.printSql(sql);
            out.setPacketType(QUERY_PKT);
            if (tdsVersion >= TDS90 && startBatch) {
                writeTDS90Prefix(this.transDescriptor);
            }
            out.writeUnicode(sql);
            if (!sendNow) {
                // Append SQL packets
                out.writeUnicode(" ");
            }
        }
    }

    /**
     * A <B>very</B> poor man's "encryption".
     *
     * @param pw password to encrypt
     * @return encrypted password
     */
    private String tds7CryptPass(final String pw) {
        final int xormask = 0x5A5A;
        final int len = pw.length();
        final char[] chars = new char[len];

        for (int i = 0; i < len; ++i) {
            final int c = pw.charAt(i) ^ xormask;
            final int m1 = (c >> 4) & 0x0F0F;
            final int m2 = (c << 4) & 0xF0F0;

            chars[i] = (char) (m1 | m2);
        }

        return new String(chars);
    }

    /**
     * Extract the TDS protocol version from the value returned by the server in the LOGINACK
     * packet.
     *
     * @param rawTdsVersion the TDS protocol version as returned by the server
     * @return the jTDS internal value for the protocol version (i.e one of the
     *         <code>TdsCore.TDS<i>XX</i></code> values)
     */
    private int getTdsSubVersion(final int rawTdsVersion) {
        if (rawTdsVersion >= 0x72000000) {
            return TdsCore.TDS90;
        } else if (rawTdsVersion >= 0x71000001) {
            return TdsCore.TDS81;
        } else if (rawTdsVersion >= 0x07010000) {
            return TdsCore.TDS80;
        } else if (rawTdsVersion >= 0x07000000) {
            return TdsCore.TDS70;
        } else if (rawTdsVersion >= 0x05000000) {
            return TdsCore.TDS50;
        } else {
            return TdsCore.TDS42;
        }
    }
    /**
     * Set the <code>charsetInfo</code> field of <code>ci</code> according to
     * the value of its <code>collation</code> field.
     * <p>
     * The <code>Connection</code> is used to find out whether a specific
     * charset was requested. In this case, the column charset will be ignored.
     *
     * @param in    the Tds input stream.
     * @param ci    the Column information instance describing the data.
     * @throws SQLException if a <code>CharsetInfo</code> is not found for this
     *                      particular column collation
     */
    private void setColumnCharset(final TdsStream in, final ColInfo ci)
            throws IOException, SQLException 
    {
        if (connection.isCharsetSpecified() || 
            ci.tdsType == SYBNTEXT || ci.tdsType == XSYBNCHAR || ci.tdsType == XSYBNVARCHAR ) {
            // If a charset was requested on connection creation, or column is unicode 
            // ignore the column collation and use default
            in.skip(COLLATION_SIZE);
            ci.charset = this.connection.getCharset();
        } else {
            // TDS version will be 8.0 or higher in this case and connection
            // collation will be non-null
            byte collation[] = new byte[COLLATION_SIZE];
            in.read(collation);
            if (Arrays.equals(collation, this.connection.getCollation())) {
                ci.charset = this.connection.getCharset();
            } else {
                ci.charset = CharsetUtil.getCharset(collation);
            }
        }
    }

    /**
     * Read the TDS datastream and populate the ColInfo parameter with
     * data type and related information.
     * <p>The type infomation conforms to one of the following formats:
     * <ol>
     * <li> [int1 type]  - eg SYBINT4.
     * <li> [int1 type] [int1 buffersize]  - eg VARCHAR &lt; 256
     * <li> [int1 type] [int2 buffersize]  - eg VARCHAR &gt; 255.
     * <li> [int1 type] [int4 buffersize] [int1 tabnamelen] [int1*n tabname] - eg text.
     * <li> [int1 type] [int4 buffersize] - eg sql_variant.
     * <li> [int1 type] [int1 buffersize] [int1 precision] [int1 scale] - eg decimal.
     * </ol>
     * For TDS 8 large character types include a 5 byte collation field after the buffer size.
     *
     * @param ci The ColInfo column descriptor object.
     * @return The number of bytes read from the input stream.
     * @throws IOException
     */
    private int readType(final ColInfo ci) throws IOException, SQLException {
        int bytesRead = 1;
        // Get the TDS data type code
        int type = in.read();

        ci.tdsType     = type;
        ci.jdbcType    = types[type].jdbcType;
        ci.scale       = types[type].scale;
        ci.sqlType     = types[type].sqlType;
        ci.charset     = this.connection.getCharset();
        
        // Now get the buffersize if required
        switch (types[type].size) {
            case -5:
                // sql_variant
                // Sybase long binary
                ci.bufferSize = in.readInt();
                bytesRead += 4;
                break;

            case -4:
                // text or image
                ci.bufferSize = in.readInt();
                if (tdsVersion >= TdsCore.TDS80 && type != SYBIMAGE) {
                    // text and ntext have collation data
                    if (type == SYBNTEXT) {
                        in.skip(COLLATION_SIZE);
                    } else {
                        // Read TDS8 collation info
                        setColumnCharset(in, ci);
                    }
                    bytesRead += COLLATION_SIZE;
                }
                if (this.tdsVersion >= TdsCore.TDS90) {
                    // SQL 2005 not sure what this is?
                    in.read();
                    bytesRead++;
                }
                int lenName = in.readShort();

                ci.tableName = in.readUnicode(lenName);
                bytesRead += 6 + lenName * 2;
                break;

            case -3:
                break;

            case -2:
                // longvarchar longvarbinary
                ci.bufferSize = in.readShort();
                bytesRead += 2;
                break;

            case -1:
                // varchar varbinary decimal etc
                bytesRead += 1;
                ci.bufferSize = in.read();
                break;

            default:
                ci.bufferSize = types[type].size;
                break;
        }

        // Now fine tune sizes for specific types
        switch (type) {
            // Establish actual size of nullable datetime
            case SYBDATETIMN:
                type = (ci.bufferSize == 4)? SYBDATETIME4: SYBDATETIME;
                ci.jdbcType    = types[type].jdbcType;
                ci.scale       = types[type].scale;
                ci.sqlType     = types[type].sqlType;
                break;
            // Establish actual size of nullable float
            case SYBFLTN:
                type = (ci.bufferSize == 4)? SYBREAL: SYBFLT8;
                ci.jdbcType    = types[type].jdbcType;
                ci.sqlType     = types[type].sqlType;
                break;
            // Establish actual size of nullable int
            case SYBINTN:
                switch (ci.bufferSize) {
                    case 8:
                        type = SYBINT8;
                        break;
                    case 4:
                        type = SYBINT4;
                        break;
                    case 2:
                        type = SYBINT2;
                        break;
                    default:
                        type = SYBINT1;
                    break;
                }
                ci.jdbcType    = types[type].jdbcType;
                ci.sqlType     = types[type].sqlType;
                break;
            // Establish actual size of nullable money
            case SYBMONEYN:
                type = (ci.bufferSize == 8)? SYBMONEY: SYBMONEY4;
                ci.jdbcType    = types[type].jdbcType;
                ci.sqlType     = types[type].sqlType;
                break;

            // Read in scale and precision for decimal types
            case SYBDECIMAL:
            case SYBNUMERIC:
                ci.precision   = in.read();
                ci.scale       = in.read();
                ci.displaySize = ((ci.scale > 0) ? 2 : 1) + ci.precision;
                bytesRead     += 2;
                break;

            // Although a binary type force displaysize to MAXINT
            case SYBIMAGE:
                ci.precision   = Integer.MAX_VALUE;
                ci.displaySize = Integer.MAX_VALUE;
                break;
                
            case SYBTEXT:
                ci.precision   = Integer.MAX_VALUE;
                ci.displaySize = Integer.MAX_VALUE;
                break;
                
            case SYBMSXML:
                if (ci.bufferSize != 0) {
                    // XML Schema details follow for typed XML
                    int len = in.read();
                    in.readUnicode(len); // Database name
                    bytesRead += 1 + len * 2;
                    len = in.read();
                    in.readUnicode(len); // Database schema name
                    bytesRead += 1 + len * 2;
                    len = in.readShort();
                    in.readUnicode(len); // XML schema name
                    bytesRead += 2 + len * 2;
                }
                ci.bufferSize  = -1;
                ci.precision   = Integer.MAX_VALUE / 2;
                ci.displaySize = Integer.MAX_VALUE / 2;
                break;
                
            case SYBNTEXT:
                ci.precision   = Integer.MAX_VALUE / 2;
                ci.displaySize = Integer.MAX_VALUE / 2;
                break;

                // SQL 2005 User defined Type
            case SYBMSUDT: 
                {
                    int len = in.read();
                    in.readUnicode(len); // Database name
                    bytesRead += 1 + len * 2;
                    len = in.read();
                    in.readUnicode(len); // Schema name
                    bytesRead += 1 + len * 2;
                    len = in.read();
                    ci.sqlType = in.readUnicode(len); // Type name
                    bytesRead += 1+ len * 2;
                    len = in.readShort();
                    in.readUnicode(len); // Assembly name
                    bytesRead += 2 + len * 2;
                    ci.precision = 8000;
                    ci.displaySize = 16000;
                }
                break;

            // SQL Server 7+ varbinary     
            case XSYBBINARY:
            case XSYBVARBINARY:
                if (ci.bufferSize < 0) {
                    ci.precision = Integer.MAX_VALUE;
                    ci.displaySize = Integer.MAX_VALUE;
                    ci.jdbcType    = java.sql.Types.BLOB;
                } else {
                    ci.precision = ci.bufferSize;
                    ci.displaySize = ci.precision * 2;                    
                }
                break;

            // SQL Server 7+ unicode chars can only display half as many chars
            case XSYBNCHAR:
            case XSYBNVARCHAR:
                if (tdsVersion >= TdsCore.TDS80) {
                    // Skip TDS8 collation info
                    in.skip(COLLATION_SIZE);
                    bytesRead += COLLATION_SIZE;
                }
                if (ci.bufferSize < 0) {
                    ci.jdbcType    = java.sql.Types.CLOB;
                    ci.displaySize = Integer.MAX_VALUE / 2;
                } else {
                    ci.displaySize = ci.bufferSize / 2;
                }
                ci.precision   = ci.displaySize;
                break;
                
            // SQL Server 7+ varchar     
            case XSYBVARCHAR:
            case XSYBCHAR:
                if (tdsVersion >= TdsCore.TDS80) {
                    // Read TDS8 collation info
                    setColumnCharset(in, ci);
                    bytesRead += COLLATION_SIZE;
                }
                if (ci.bufferSize < 0) {
                    ci.jdbcType    = java.sql.Types.CLOB;
                    ci.displaySize = Integer.MAX_VALUE;
                } else {
                    ci.displaySize = ci.bufferSize;
                }
                ci.precision = ci.displaySize;
                break;                   
        }

        // Set default displaySize and precision
        switch (types[ci.tdsType].precision) {
            case 0:
                // Already set
                break;
            case -1:
                ci.precision = ci.bufferSize;
                ci.displaySize = ci.precision;
                break;
            case -2:
                ci.precision = ci.bufferSize / 2;
                ci.displaySize = ci.precision;
                break;
            case -3:
                ci.precision = ci.bufferSize;
                ci.displaySize = ci.precision * 2;
                break;
            default: 
                ci.precision   = types[type].precision;
                ci.displaySize = types[type].displaySize;
                break;
        }

        // For numeric types add 'identity' for auto inc data type
        if (ci.isIdentity) {
            ci.sqlType += " identity";
        }

        // Fine tune SQL Server 7+ datatypes
        if (tdsVersion >= TdsCore.TDS70) {
            switch (ci.userType) {
                case UDT_TIMESTAMP:
                    ci.sqlType = "timestamp";
                    ci.displaySize = ci.bufferSize * 2;
                    ci.jdbcType    = java.sql.Types.BINARY;
                    break;
                case UDT_NEWSYSNAME:
                    ci.sqlType = "sysname";
                    ci.jdbcType    = java.sql.Types.VARCHAR;
                    break;
            }
        }
        
        return bytesRead;
    }

    /**
     * Read the TDS data item from the Response Stream.
     * <p> The data size is either implicit in the type for example
     * fixed size integers, or a count field precedes the actual data.
     * The size of the count field varies with the data type.
     *
     * @param ci The ColInfo column descriptor object.
     * @return The data item Object or null.
     * @throws IOException
     */
    private Object readData(final ColInfo ci) throws IOException, SQLException {
        int len;

        switch (ci.tdsType) {
            case SYBINTN:
                switch (in.read()) {
                    case 1:
                        return new Integer(in.read() & 0xFF);
                    case 2:
                        return new Integer(in.readShort());
                    case 4:
                        return new Integer(in.readInt());
                    case 8:
                        return new Long(in.readLong());
                }

                break;

            case SYBINT1:
                return new Integer(in.read() & 0xFF);

            case SYBINT2:
                return new Integer(in.readShort());

            case SYBINT4:
                return new Integer(in.readInt());

            // SQL Server bigint
            case SYBINT8:
                return new Long(in.readLong());

            case SYBIMAGE:
                len = in.read();

                if (len > 0) {
                    in.skip(24); // Skip textptr and timestamp
                    int dataLen = in.readInt();
                    return new BlobImpl(this.connection, in.getInputStream(dataLen), dataLen);
                }

                break;

            case SYBTEXT:
                len = in.read();

                if (len > 0) {
                    in.skip(24); // Skip textptr and timestamp
                    int dataLen = in.readInt();
                    return new ClobImpl(this.connection, 
                            new InputStreamReader(in.getInputStream(dataLen), ci.charset), dataLen);
                }

                break;

            case SYBNTEXT:
                len = in.read();

                if (len > 0) {
                    in.skip(24); // Skip textptr and timestamp
                    int dataLen = in.readInt();
                    return new ClobImpl(this.connection, in.getInputStream(dataLen), dataLen);
                }

                break;

            case SYBCHAR:
            case SYBVARCHAR:
                len = in.read();

                if (len > 0) {
                    String value = in.readString(len, ci.charset);
                    return value;
                }

                break;

            case SYBNVARCHAR:
                len = in.read();

                if (len > 0) {
                    return in.readUnicode(len / 2);
                }

                break;

            case XSYBCHAR:
            case XSYBVARCHAR:
                 // This is a TDS 7+ long string
                 if (ci.bufferSize == -1 && this.tdsVersion >= TdsCore.TDS90) {
                     // SQL 2005 varchar(max)
                     return getVarcharMax(ci);
                 }
                 len = in.readShort();
                 if (len != -1) {
                     return in.readString(len, ci.charset);
                 }
                 break;

            case XSYBNCHAR:
            case XSYBNVARCHAR:
                if (ci.bufferSize == -1 && this.tdsVersion >= TdsCore.TDS90) {
                    // SQL 2005 hvarchar(max)
                    return getNvarcharMax();
                }
                len = in.readShort();

                if (len != -1) {
                    return in.readUnicode(len / 2);
                }
                break;

            case SYBVARBINARY:
            case SYBBINARY:
                len = in.read();

                if (len > 0) {
                    byte[] bytes = new byte[len];

                    in.read(bytes);

                    return bytes;
                }

                break;
                
            case SYBMSXML:
                // SQL 2005 XML data type (treat as NVARCHAR)
                return getNvarcharMax();

            case SYBMSUDT: // Treat SQL 2005 UDT as varbinary
                return getVarbinaryMax();
                
            case XSYBVARBINARY:
            case XSYBBINARY:
                if (ci.bufferSize == -1 && this.tdsVersion >= TdsCore.TDS90) {
                    // SQL 2005 varbinary(max)
                    return getVarbinaryMax();
                }
                len = in.readShort();

                if (len != -1) {
                    byte[] bytes = new byte[len];

                    in.read(bytes);

                    return bytes;
                }
                break;

            case SYBMONEY4:
                return in.readMoney(4);
            case SYBMONEY:
                return in.readMoney(8);
            case SYBMONEYN:
                return in.readMoney(in.read());

            case SYBDATETIME4:
                return in.readDatetime(4);
            case SYBDATETIMN:
                return in.readDatetime(in.read());
            case SYBDATETIME:
                return in.readDatetime(8);

            case SYBBIT:
                return (in.read() != 0) ? Boolean.TRUE : Boolean.FALSE;

            case SYBBITN:
                len = in.read();

                if (len > 0) {
                    return (in.read() != 0) ? Boolean.TRUE : Boolean.FALSE;
                }

                break;

            case SYBREAL:
                return new Float(Float.intBitsToFloat(in.readInt()));

            case SYBFLT8:
                return new Double(Double.longBitsToDouble(in.readLong()));

            case SYBFLTN:
                len = in.read();

                if (len == 4) {
                    return new Float(Float.intBitsToFloat(in.readInt()));
                } else if (len == 8) {
                    return new Double(Double.longBitsToDouble(in.readLong()));
                }

                break;

            case SYBUNIQUE:
                len = in.read();

                if (len > 0) {
                    byte[] bytes = new byte[len];

                    in.read(bytes);

                    return new UniqueIdentifier(bytes);
                }

                break;

            case SYBNUMERIC:
            case SYBDECIMAL:
                len = in.read();

                if (len > 0) {
                    int sign = in.read();

                    len--;
                    byte[] bytes = new byte[len];
                    BigInteger bi;

                    while (len-- > 0) {
                        bytes[len] = (byte)in.read();
                    }

                    bi = new BigInteger((sign == 0) ? -1 : 1, bytes);
 
                    return new BigDecimal(bi, ci.scale);
                }

                break;

            case SYBVARIANT:
                return getVariant();

            default:
                throw new IllegalStateException("Unsupported TDS data type 0x" + 
                                        Integer.toHexString(ci.tdsType & 0xFF));
        }

        return null;
    }

    /**
     * Read a SQL 2005 nvarchar(max) (or XML) value from the wire.
     * <p/>The value consists of a long length field (which may have
     * the special value of -1 for null or -2 for length unknown) and
     * zero or more data blocks each preceeded by an integer length. 
     * The last block has a length of 0.
     * 
     * @return The data item as a <code>Clob</code> or null.
     * @throws IOException
     */
    private Clob getNvarcharMax() throws IOException
    {
        long len = in.readLong();
        if (len == -1) {
            // -1 indicates value is null
            return null;
        }
        return new ClobImpl(this.connection, in.getTDS90InputStream(), (int)len);
    }
    
    /**
     * Read a SQL 2005 varbinary(max) value from the wire.
     * <p/>The value connsists of a long length field (which may have
     * the special value of -1 for null or -2 for length unknown) and
     * zero or more data blocks each preceeded by an integer length. 
     * The last block has a length of 0.
     * 
     * @return The data item as a <code>Blob</code> or null.
     * @throws IOException
     */
    private Blob getVarbinaryMax() throws IOException
    {
        long len = in.readLong();
        if (len == -1) {
            // -1 indicates value is null
            return null;
        }
        return new BlobImpl(this.connection, in.getTDS90InputStream(), (int)len);
    }

    /**
     * Read a SQL 2005 varchar(max) value from the wire.
     * <p/>The value connsists of a long length field (which may have
     * the special value of -1 for null or -2 for length unknown) and
     * zero or more data blocks each preceeded by an integer length. 
     * The last block has a length of 0.
     * 
     * @param ci The ColInfo column descriptor object.
     * @return The data item as a <code>Clob</code> or null.
     * @throws IOException
     */
    private Clob getVarcharMax(final ColInfo ci) throws IOException
    {
        long len = in.readLong();
        if (len == -1) {
            // -1 indicates value is null
            return null;
        }
        return new ClobImpl(this.connection, 
                    new InputStreamReader(in.getTDS90InputStream(), ci.charset),(int)len);
    }

    /**
     * Set the TDS native type code for the parameter.
     *
     * @param pi         the parameter descriptor
     */
    void setNativeType(final ParamInfo pi) throws SQLException 
    {    
        try {
            int jdbcType = pi.jdbcType;

            if (jdbcType == java.sql.Types.OTHER) {
                jdbcType = Support.getJdbcType(pi.value);
            }

            switch (jdbcType) {
                case java.sql.Types.CHAR:
                case java.sql.Types.CLOB:
                case java.sql.Types.VARCHAR:
                case java.sql.Types.LONGVARCHAR:
                    switch (this.tdsVersion) {
                        case TdsCore.TDS70:
                        case TdsCore.TDS80:
                        case TdsCore.TDS81:
                            getTds7080Varchar(pi);
                            break;
                        case TdsCore.TDS90:
                            getTds90Varchar(pi);
                            break;
                        default:
                            throw new IllegalStateException(
                                            "Unknown TDS version " + 
                                            this.tdsVersion);
                    }
                    if (pi.isOutput 
                        && (pi.sqlType.equals("text") 
                        || pi.sqlType.equals("ntext"))) {
                        throw new SQLException(
                                    Messages.get("error.textoutparam"), "HY000");
                    }
                    break;

                case java.sql.Types.TINYINT:
                case java.sql.Types.SMALLINT:
                case java.sql.Types.INTEGER:
                    pi.tdsType = SYBINTN;
                    pi.sqlType = "int";
                    break;

                case java.sql.Types.BOOLEAN:
                case java.sql.Types.BIT:
                    pi.tdsType = SYBBITN;
                    pi.sqlType = "bit";
                    break;

                case java.sql.Types.REAL:
                    pi.tdsType = SYBFLTN;
                    pi.sqlType = "real";
                    break;

                case java.sql.Types.FLOAT:
                case java.sql.Types.DOUBLE:
                    pi.tdsType = SYBFLTN;
                    pi.sqlType = "float";
                    break;

                case java.sql.Types.TIME:
                case java.sql.Types.DATE:
                case java.sql.Types.TIMESTAMP:
                    pi.tdsType = SYBDATETIMN;
                    pi.sqlType = "datetime";
                    break;

                case java.sql.Types.BLOB:
                case java.sql.Types.BINARY:
                case java.sql.Types.VARBINARY:
                case java.sql.Types.LONGVARBINARY:
                    switch (this.tdsVersion) {
                        case TdsCore.TDS70:
                        case TdsCore.TDS80:
                        case TdsCore.TDS81:
                            getTds7080Varbinary(pi);
                            break;
                        case TdsCore.TDS90:
                            getTds90Varbinary(pi);
                            break;
                        default:
                            throw new IllegalStateException(
                                        "Unknown TDS version " + 
                                        this.tdsVersion);
                    }
                    if (pi.isOutput && (pi.sqlType.equals("image"))) {
                        throw new SQLException(
                                    Messages.get("error.textoutparam"), "HY000");
                    }
                    break;

                case java.sql.Types.BIGINT:
                    if (this.tdsVersion >= TdsCore.TDS80) {
                        pi.tdsType = SYBINTN;
                        pi.sqlType = "bigint";
                    } else {
                        // int8 not supported send as a decimal field
                        pi.tdsType  = SYBDECIMAL;
                        pi.sqlType = "decimal(" + connection.getMaxPrecision() + ')';
                        pi.scale = 0;
                    }

                    break;

                case java.sql.Types.DECIMAL:
                case java.sql.Types.NUMERIC:
                    pi.tdsType  = SYBDECIMAL;
                    int prec = connection.getMaxPrecision();
                    int scale = ConnectionImpl.DEFAULT_SCALE;
                    if (pi.value instanceof BigDecimal) {
                        scale = ((BigDecimal)pi.value).scale();
                    } else if (pi.scale >= 0 && pi.scale <= prec) {
                        scale = pi.scale;
                    }
                    pi.sqlType = "decimal(" + prec + ',' + scale + ')';

                    break;

                case java.sql.Types.OTHER:
                case java.sql.Types.NULL:
                    // Send a null String in the absence of anything better
                    pi.tdsType = XSYBVARCHAR;
                    pi.sqlType = "varchar(255)";
                    break;
               
                case StatementImpl.SQLXML:
                    if (this.tdsVersion >= TdsCore.TDS90) {
                        pi.tdsType = SYBMSXML;
                        pi.sqlType = "xml";
                    }
                    break;

                default:
                    throw new SQLException(Messages.get(
                            "error.baddatatype",
                            Integer.toString(pi.jdbcType)), "HY000");
            }
        } catch (IOException e) {
            throw new SQLException(
                            Messages.get("error.generic.ioerror", e.getMessage()), "HY000");
        }
    }
    
    /**
     * Get the TDS 7.0 / 8.0 specific varchar native datatype.
     * 
     * @param pi         the parameter descriptor
     * @throws SQLException
     * @throws IOException
     */
    private void getTds7080Varchar(final ParamInfo pi) 
    throws SQLException, IOException  {
        if (pi.isUnicode) {
            if (pi.getCharLength(this.connection) <= MS_LONGVAR_MAX / 2) {
                pi.tdsType = XSYBNVARCHAR;
                pi.sqlType = "nvarchar(4000)";
            } else {
                pi.tdsType = SYBNTEXT;
                pi.sqlType = "ntext";
            }    
        } else {
            if (pi.getAnsiLength(this.connection) <= MS_LONGVAR_MAX) {
                // Check for unicode required?
                if (pi.isConvertable(this.connection)) {
                    pi.tdsType = XSYBVARCHAR;
                    pi.sqlType = "varchar(8000)";
                } else {
                    pi.isUnicode = true;
                    if (pi.getCharLength(this.connection) <= MS_LONGVAR_MAX / 2) {
                        pi.tdsType = XSYBNVARCHAR;
                        pi.sqlType = "nvarchar(4000)";
                    } else {
                        pi.tdsType = SYBNTEXT;
                        pi.sqlType = "ntext";
                    }
                }
            } else {
                // Send as unicode anyway as text may not convert and 
                // text fields cannot be indexed.
                pi.isUnicode = true;
                pi.tdsType = SYBNTEXT;
                pi.sqlType = "ntext";
            }
        }
    }
    
    /**
     * Get the TDS 7.0 or 8.0 specific varbinary native datatype.
     * 
     * @param pi         the parameter descriptor
     * @throws SQLException
     * @throws IOException
     */
    private void getTds7080Varbinary(final ParamInfo pi) 
    throws SQLException, IOException{
        if (pi.length <= MS_LONGVAR_MAX) {
            pi.tdsType = XSYBVARBINARY;
            pi.sqlType = "varbinary(8000)";
        } else {
            pi.tdsType = SYBIMAGE;
            pi.sqlType = "image";
        }
    }
    
    /**
     * Get the TDS 9.0 (SQL 2005) specific varchar native datatype.
     * 
     * @param pi         the parameter descriptor
     * @throws SQLException
     * @throws IOException
     */
    private void getTds90Varchar(final ParamInfo pi) 
    throws SQLException, IOException {
        if (pi.isUnicode) {
            pi.tdsType = XSYBNVARCHAR;
            if (pi.getCharLength(this.connection) > MS_LONGVAR_MAX / 2) {
                pi.sqlType = "nvarchar(max)";
            } else {
                pi.sqlType = "nvarchar(4000)";
            }
        } else {
            if (pi.getAnsiLength(this.connection) > MS_LONGVAR_MAX) {
                // Send as Unicode anyway as it may not convert
                // and varchar(max) would be a poor choice for an index
                pi.isUnicode = true;
                pi.tdsType = XSYBNVARCHAR;
                pi.sqlType = "nvarchar(max)";
            } else {
                // Check for unicode required?
                if (pi.isConvertable(this.connection)) {
                    pi.tdsType = XSYBVARCHAR;
                    pi.sqlType = "varchar(8000)";
                } else {
                    pi.isUnicode = true;
                    if (pi.getCharLength(this.connection) <= MS_LONGVAR_MAX / 2) {
                        pi.tdsType = XSYBNVARCHAR;
                        pi.sqlType = "nvarchar(4000)";
                    } else {
                        pi.tdsType = SYBNTEXT;
                        pi.sqlType = "ntext";
                    }
                }
            }
        }
    }

    /**
     * Get the TDS 9.0 (SQL 2005) specific varbinary native datatype.
     * 
     * @param pi         the parameter descriptor
     * @throws SQLException
     * @throws IOException
     */
    private void getTds90Varbinary(final ParamInfo pi) 
    throws SQLException, IOException {
        pi.tdsType = XSYBVARBINARY;
        if (pi.length > MS_LONGVAR_MAX) {
            pi.sqlType = "varbinary(max)";
        } else {
            pi.sqlType = "varbinary(8000)";
        }
    }

    /**
     * Write a parameter to the server request stream.
     *
     * @param pi          the parameter descriptor
     */
    private void writeParam(final ParamInfo pi)
            throws IOException {
        int len;
        boolean isTds8 = tdsVersion >= TdsCore.TDS80;
        boolean isTds9 = tdsVersion >= TdsCore.TDS90;

        switch (pi.tdsType) {

            // 
            // TDS 7+ varchar(8000) format
            //    0xA7 max_size [collation] actual_size data..
            //    actual_size = -1 means value is null
            // TDS 9+ varchar(max) format
            //    0xA7 -1 [collation] total_size frag_size data.. 0
            //
            case XSYBVARCHAR:
                len = pi.getAnsiLength(this.connection);
                out.write((byte) pi.tdsType);
                if (isTds9 && ((len > MS_LONGVAR_MAX) 
                        || (pi.isOutput && pi.jdbcType == Types.LONGVARCHAR))) {
                    out.write((short) -1);
                    if (isTds8) {
                        out.write(this.connection.getCollation());
                    }
                    if (pi.value == null) {
                        out.write((long) -1);
                    } else {
                        out.write((long)len);
                        out.write((int)len);
                        pi.writeAnsi(out, this.connection);
                        out.write((int)0);
                    }
                } else {
                    out.write((short) MS_LONGVAR_MAX);
                    if (isTds8) {
                        out.write(this.connection.getCollation());
                    }
                    if (pi.value == null) {
                        out.write((short) -1);
                    } else {
                        out.write((short) len);
                        pi.writeAnsi(out, this.connection);
                    }
                }
                break;
                // 
                // TDS 7+ nvarchar(4000) format
                //    0xE7 max_size [collation] actual_size data..
                //    actual_size = -1 means value is null
                // TDS 9+ varchar(max) format
                //    0xE7 -1 [collation] total_size frag_size data.. 0
                //
            case XSYBNVARCHAR:
                len = pi.getCharLength(this.connection);
                out.write((byte) pi.tdsType);
                if (isTds9 && ((len > MS_LONGVAR_MAX / 2) 
                      || (pi.isOutput && pi.jdbcType == Types.LONGVARCHAR))) {
                    out.write((short) -1);
                    if (isTds8) {
                        out.write(this.connection.getCollation());
                    }
                    if (pi.value == null) {
                        out.write((long) -1);
                    } else {
                        out.write((long)(len * 2));
                        out.write((int)(len * 2));
                        pi.writeUnicode(out, this.connection);
                        out.write((int)0);
                    }
                } else {
                    out.write((short) MS_LONGVAR_MAX);
                    if (isTds8) {
                        out.write(this.connection.getCollation());
                    }
                    if (pi.value == null) {
                        out.write((short) -1);
                    } else {
                        out.write((short)(len * 2));
                        pi.writeUnicode(out, this.connection);
                    }
                }
                break;

            case SYBTEXT:
                if (pi.value == null) {
                    len = 0;
                } else {
                    len = pi.getAnsiLength(this.connection);
                }

                out.write((byte) pi.tdsType);

                if (len > 0) {
                    out.write((int) len);
                    if (isTds8) {
                        out.write(this.connection.getCollation());
                    }
                    out.write((int) len);
                    pi.writeAnsi(out, this.connection);
                } else {
                    out.write((int) len); // Zero length

                    if (isTds8) {
                        out.write(this.connection.getCollation());
                    }

                    out.write((int)len);
                }

                break;

            case SYBNTEXT:
                
                len = pi.getCharLength(this.connection);

                out.write((byte)pi.tdsType);

                if (len > 0) {
                    out.write((int) len * 2);

                    if (isTds8) {
                        out.write(this.connection.getCollation());
                    }

                    out.write((int) len * 2);
                    pi.writeUnicode(out, this.connection);
                } else {
                    out.write((int) len);

                    if (isTds8) {
                        out.write(this.connection.getCollation());
                    }

                    out.write((int) len);
                }

                break;

                // 
                // TDS 7+ varbinary(8000) format
                //    0xA5 max_size actual_size data..
                //    actual_size = -1 means value is null
                // TDS 9+ varbinary(max) format
                //    0xA5 -1 total_size frag_size data.. 0
                //
            case XSYBVARBINARY:
                len = pi.length;
                out.write((byte) pi.tdsType);
                if (isTds9 && ((len > MS_LONGVAR_MAX) 
                        || (pi.isOutput && pi.jdbcType == Types.LONGVARBINARY))) {
                    out.write((short) -1);
                    if (pi.value == null) {
                        out.write((long) -1);
                    } else {
                        out.write((long)len);
                        out.write((int)len);
                        pi.writeBytes(out, this.connection);
                        out.write((int)0);
                    }
                } else {
                    out.write((short) MS_LONGVAR_MAX);
                    if (pi.value == null) {
                        out.write((short) -1);
                    } else {
                        out.write((short) len);
                        pi.writeBytes(out, this.connection);
                    }
                }
                break;

            case SYBIMAGE:
                if (pi.value == null) {
                    len = 0;
                } else {
                    len = pi.length;
                }

                out.write((byte) pi.tdsType);

                if (len > 0) {
                    out.write((int) len);
                    out.write((int) len);
                    pi.writeBytes(out, this.connection);
                } else {
                    out.write((int) len);
                    out.write((int) len);
                }

                break;

            case SYBINTN:
                out.write((byte) pi.tdsType);

                if (pi.value == null) {
                    out.write((pi.sqlType.equals("bigint"))? (byte)8: (byte)4);
                    out.write((byte) 0);
                } else {
                    if (pi.sqlType.equals("bigint")) {
                        out.write((byte) 8);
                        out.write((byte) 8);
                        out.write((long) ((Number) pi.value).longValue());
                    } else {
                        out.write((byte) 4);
                        out.write((byte) 4);
                        out.write((int) ((Number) pi.value).intValue());
                    }
                }

                break;

            case SYBFLTN:
                out.write((byte) pi.tdsType);
                if (pi.value instanceof Float) {
                    out.write((byte) 4);
                    out.write((byte) 4);
                    out.write(((Number) pi.value).floatValue());
                } else {
                    out.write((byte) 8);
                    if (pi.value == null) {
                        out.write((byte) 0);
                    } else {
                        out.write((byte) 8);
                        out.write(((Number) pi.value).doubleValue());
                    }
                }

                break;

            case SYBDATETIMN:
                out.write((byte) SYBDATETIMN);
                out.write((byte) 8);
                out.write((DateTime) pi.value);
                break;

            case SYBBIT:
                out.write((byte) pi.tdsType);

                if (pi.value == null) {
                    out.write((byte) 0);
                } else {
                    out.write((byte) (((Boolean) pi.value).booleanValue() ? 1 : 0));
                }

                break;

            case SYBBITN:
                out.write((byte) SYBBITN);
                out.write((byte) 1);

                if (pi.value == null) {
                    out.write((byte) 0);
                } else {
                    out.write((byte) 1);
                    out.write((byte) (((Boolean) pi.value).booleanValue() ? 1 : 0));
                }

                break;

            case SYBNUMERIC:
            case SYBDECIMAL:
                out.write((byte) pi.tdsType);
                BigDecimal value = null;
                int prec = this.connection.getMaxPrecision();
                int scale;

                if (pi.value == null) {
                    if (pi.jdbcType == java.sql.Types.BIGINT) {
                        scale = 0;
                    } else {
                        if (pi.scale >= 0 && pi.scale <= prec) {
                            scale = pi.scale;
                        } else {
                            scale = ConnectionImpl.DEFAULT_SCALE;
                        }
                    }
                } else {
                    if (pi.value instanceof Long) {
                        value = new BigDecimal(((Long) pi.value).toString());
                        scale = 0;
                    } else {
                        value = (BigDecimal) pi.value;
                        scale = value.scale();
                    }
                }
                
                out.write((byte) ((prec <= ConnectionImpl.DEFAULT_PRECISION_28) ? 13 : 17));
                out.write((byte) prec);
                out.write((byte) scale);
                out.write(value, TdsCore.SQLSERVER);
                break;
                
            case SYBMSXML:
                len = pi.length;
                out.write((byte)pi.tdsType);
                out.write((byte)0);
                if (pi.value == null) {
                    out.write((long) -1);
                } else {
                    out.write((long)len);
                    out.write((int)len);
                    pi.writeBytes(out, this.connection);
                    out.write((int)0);
                }
                break;
                
            default:
                throw new IllegalStateException("Unsupported output TDS type "
                        + Integer.toHexString(pi.tdsType));
        }
    }
//
// ---------------------- Private methods from here -----------------------
//
    
    /**
     * Read a MSQL 2000 sql_variant data value from the input stream.
     * <p>SQL_VARIANT has the following structure:
     * <ol>
     * <li>INT4 total size of data
     * <li>INT1 TDS data type (text/image/ntext/sql_variant not allowed)
     * <li>INT1 Length of extra type descriptor information
     * <li>Optional additional type info required by some types
     * <li>byte[0...n] the actual data
     * </ol>
     *
     * @return the SQL_VARIANT data
     */
    private Object getVariant()
            throws IOException, SQLException {
        byte[] bytes;
        int len = in.readInt();

        if (len == 0) {
            // Length of zero means item is null
            return null;
        }

        ColInfo ci = new ColInfo();
        len -= 2;
        ci.tdsType = in.read(); // TDS Type
        len -= in.read(); // Size of descriptor

        switch (ci.tdsType) {
            case SYBINT1:
                return new Integer(in.read() & 0xFF);

            case SYBINT2:
                return new Integer(in.readShort());

            case SYBINT4:
                return new Integer(in.readInt());

            case SYBINT8:
                return new Long(in.readLong());

            case XSYBCHAR:
            case XSYBVARCHAR:
                // Read TDS8 collation info
                try {
                    setColumnCharset(in, ci);
                } catch (IOException ex) {
                    // Skip the buffer size and value
                    in.skip(2 + len);
                    throw ex;
                }

                in.skip(2); // Skip buffer size
                return in.readString(len, ci.charset);

            case XSYBNCHAR:
            case XSYBNVARCHAR:
                // XXX Why do we need collation for Unicode strings?
                // Read TDS8 collation info
                in.skip(COLLATION_SIZE);
                in.skip(2); // Skip buffer size

                return in.readUnicode(len / 2);

            case XSYBVARBINARY:
            case XSYBBINARY:
                in.skip(2); // Skip buffer size
                bytes = new byte[len];
                in.read(bytes);

                return bytes;

            case SYBMONEY4:
                return in.readMoney(4);
            case SYBMONEY:
                return in.readMoney(8);

            case SYBDATETIME4:
                return in.readDatetime(4);
            case SYBDATETIME:
                return in.readDatetime(8);

            case SYBBIT:
                return (in.read() != 0) ? Boolean.TRUE : Boolean.FALSE;

            case SYBREAL:
                return new Float(Float.intBitsToFloat(in.readInt()));

            case SYBFLT8:
                return new Double(Double.longBitsToDouble(in.readLong()));

            case SYBUNIQUE:
                bytes = new byte[len];
                in.read(bytes);

                return new UniqueIdentifier(bytes);

            case SYBNUMERIC:
            case SYBDECIMAL:
                ci.precision = in.read();
                ci.scale = in.read();
                int sign = in.read();
                len--;
                bytes = new byte[len];
                BigInteger bi;

                while (len-- > 0) {
                    bytes[len] = (byte)in.read();
                }

                bi = new BigInteger((sign == 0) ? -1 : 1, bytes);

                return new BigDecimal(bi, ci.scale);

            default:
                throw new IOException("Unsupported TDS data type 0x"
                                            + Integer.toHexString(ci.tdsType)
                                            + " in sql_variant");
        }
        //
        // For compatibility with the MS driver convert to String.
        // Change the data type for sql_variant from OTHER to VARCHAR
        // Without this code the actual Object type can be retrieved
        // by using getObject(n).
        //
//        try {
//            value = Support.convert(value, java.sql.Types.VARCHAR, in.getCharset());
//        } catch (SQLException e) {
//            // Conversion failed just try toString();
//            value = value.toString();
//        }
    }

    /**
     * For SQL 2005 This routine will modify the meta data to allow the
     * caller to distinguish between varchar(max) and text or varbinary(max)
     * and image or nvarchar(max) and ntext.
     *
     * @param typeName the SQL type returned by sp_columns
     * @param tdsType the TDS type returned by sp_columns
     * @return the (possibly) modified SQL type name as a <code>String</code>
     */
    static String getMSTypeName(final String typeName, final int tdsType) {
        if (typeName.equalsIgnoreCase("text") && tdsType != SYBTEXT) {
            return "varchar";
        } else if (typeName.equalsIgnoreCase("ntext") && tdsType != SYBTEXT) {
            return "nvarchar";
        } else if (typeName.equalsIgnoreCase("image") && tdsType != SYBIMAGE) {
            return "varbinary";
        } else {
            return typeName;
        }
    }
}
