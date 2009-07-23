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
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.sql.*;

import java.util.ArrayList;

import net.sourceforge.jtds.jdbc.TdsCore;
import net.sourceforge.jtds.util.Logger;

/**
 * This class implements the Sybase / Microsoft TDS 4.2 protocol.
 * <p>
 *
 * @author Mike Hutchinson
 * @author Matt Brinkley
 * @author Alin Sinpalean
 * @author FreeTDS project
 * @version $Id: TdsCore42.java,v 1.3 2009-07-23 19:35:35 ickzon Exp $
 */
class TdsCore42 extends TdsCore {
    //
    // Sybase / SQL Server 6.5 Login database security error message codes
    //
    /** Error 916: Server user id ? is not a valid user in database '?'.*/
    static final int ERR_INVALID_USER   = 916;
    /** Error 10351: Server user id ? is not a valid user in database '?'.*/
    static final int ERR_INVALID_USER_2 = 10351;
    /** Error 4001: Cannot open default database '?'.*/
    static final int ERR_NO_DEFAULT_DB  = 4001;
    
    /*
     * Constants for variable length data types
     */
    private static final int VAR_MAX               = 255;
    
    /**
     * Static block to initialise TDS 4.2 data type descriptors.
     */
    static {//                             SQL Type       Size Prec scale DS signed TDS8 Col java Type
        types[SYBCHAR]      = new TypeInfo("char",          -1, -1, 0, 0, java.sql.Types.CHAR);
        types[SYBVARCHAR]   = new TypeInfo("varchar",       -1, -1, 0, 0, java.sql.Types.VARCHAR);
        types[SYBINTN]      = new TypeInfo("int",           -1, 10, 0,11, java.sql.Types.INTEGER);
        types[SYBINT1]      = new TypeInfo("tinyint",        1,  3, 0, 4, java.sql.Types.TINYINT);
        types[SYBINT2]      = new TypeInfo("smallint",       2,  5, 0, 6, java.sql.Types.SMALLINT);
        types[SYBINT4]      = new TypeInfo("int",            4, 10, 0,11, java.sql.Types.INTEGER);
        types[SYBFLT8]      = new TypeInfo("float",          8, 15, 0,24, java.sql.Types.DOUBLE);
        types[SYBDATETIME]  = new TypeInfo("datetime",       8, 23, 3,23, java.sql.Types.TIMESTAMP);
        types[SYBBIT]       = new TypeInfo("bit",            1,  1, 0, 1, java.sql.Types.BIT);
        types[SYBTEXT]      = new TypeInfo("text",          -4,  0, 0, 0, java.sql.Types.CLOB);
        types[SYBIMAGE]     = new TypeInfo("image",         -4,  0, 0, 0, java.sql.Types.BLOB);
        types[SYBMONEY4]    = new TypeInfo("smallmoney",     4, 10, 4,12, java.sql.Types.DECIMAL);
        types[SYBMONEY]     = new TypeInfo("money",          8, 19, 4,21, java.sql.Types.DECIMAL);
        types[SYBDATETIME4] = new TypeInfo("smalldatetime",  4, 16, 0,19, java.sql.Types.TIMESTAMP);
        types[SYBREAL]      = new TypeInfo("real",           4,  7, 0,14, java.sql.Types.REAL);
        types[SYBBINARY]    = new TypeInfo("binary",        -1, -3, 0, 0, java.sql.Types.BINARY);
        types[SYBVOID]      = new TypeInfo("void",          -1,  1, 0, 1, 0);
        types[SYBVARBINARY] = new TypeInfo("varbinary",     -1, -3, 0, 0, java.sql.Types.VARBINARY);
        types[SYBNUMERIC]   = new TypeInfo("numeric",       -1,  0, 0, 0, java.sql.Types.NUMERIC);
        types[SYBDECIMAL]   = new TypeInfo("decimal",       -1,  0, 0, 0, java.sql.Types.DECIMAL);
        types[SYBFLTN]      = new TypeInfo("float",         -1, 15, 0,24, java.sql.Types.DOUBLE);
        types[SYBMONEYN]    = new TypeInfo("money",         -1, 19, 4,21, java.sql.Types.DECIMAL);
        types[SYBDATETIMN]  = new TypeInfo("datetime",      -1, 23, 3,23, java.sql.Types.TIMESTAMP);
    }
    
    
    /**
     * Construct a TdsCore object.
     *
     * @param connection The connection which owns this object.
     * @param socket The TDS socket instance.
     * @param serverType The appropriate server type constant.
     */
    TdsCore42(final ConnectionImpl connection,
              final TdsSocket socket,
              final int serverType) {
        super(connection, socket, serverType, TDS42);
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
        // Need to ensure that the current database is included in the key
        // as procedures are database specific.
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
            sendLoginPkt(serverName, database, user, password,
                         charset, appName, progName, 
                         (wsid.length() == 0)? getHostName(): wsid,
                         language, packetSize);
            endOfResponse = false;
            nextToken(cx);

            while (!endOfResponse) {
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
     * @return name of the procedure or prepared statement handle.
     * @exception SQLException
     */
    ProcEntry prepare(final StatementImpl cx,
                      final String sql,
                      final ParamInfo[] params,
                      final boolean needCursor,
                      final int resultSetType,
                      final int resultSetConcurrency,
                      final boolean returnKeys)
            throws SQLException 
    {

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
                pe.setType(ProcEntry.PROCEDURE);
                pe.setName(procName);
                return pe;
            } catch (SQLException e) {
                if ("08S01".equals(e.getSQLState())) {
                    // Serious (I/O) error, rethrow
                    throw e;
                }

                // This exception probably caused by failure to prepare
                // Add a warning
                SQLException sqle = new SQLWarning(
                        Messages.get("error.prepare.prepfailed",
                                e.getMessage()),
                        e.getSQLState(), e.getErrorCode());
                sqle.initCause(e);
                throw sqle;
            }

        } 
        return null;
    }

    /**
     * Read the next TDS token from the response stream.
     *
     * @param cx  the StatementImpl owning this prepare.
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
                case TDS_COLNAME_TOKEN:
                    tds4ColNamesToken(cx);
                    break;
                case TDS_COLFMT_TOKEN:
                    tds4ColFormatToken(cx);
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



//  ---------------------- Private Methods from here ---------------------

     /**
      * TDS 4.2 Login Packet.
      *
      * @param serverName server host name
      * @param database   required database
      * @param user       user name
      * @param password   user password
      * @param charset    required server character set
      * @param appName    application name
      * @param progName   program name
      * @param wsid       workstation ID
      * @param language   server language for messages
      * @param packetSize required network packet size
      * @throws IOException if an I/O error occurs
      */
     private void sendLoginPkt(final String serverName,
                               final String database,
                               final String user,
                               final String password,
                               final String charset,
                               final String appName,
                               final String progName,
                               final String wsid,
                               final String language,
                               final int packetSize)
         throws IOException {
         final byte[] empty = new byte[0];

         out.setPacketType(LOGIN_PKT);
         putLoginString(wsid, 30);           // Host name
         putLoginString(user, 30);           // user name
         putLoginString(password, 30);       // password
         putLoginString("00000123", 30);     // hostproc (offset 93 0x5d)

         out.write((byte) 3); // type of int2
         out.write((byte) 1); // type of int4
         out.write((byte) 6); // type of char
         out.write((byte) 10);// type of flt
         out.write((byte) 9); // type of date
         out.write((byte) 1); // notify of use db
         out.write((byte) 1); // disallow dump/load and bulk insert
         out.write((byte) 0); // sql interface type
         out.write((byte) 0); // type of network connection

         out.write(empty, 0, 7);

         putLoginString(appName, 30);  // appname

         if (this.serverType == TdsCore.ANYWHERE) {
             putLoginString(database, 30); // database name
         } else {
             putLoginString(serverName, 30); // server name
         }

         out.write((byte)0); // remote passwords
         ByteBuffer bb = connection.getCharset().encode(password);
         byte buf[] = new byte[bb.remaining()];
         bb.get(buf);
         out.write((byte)buf.length);
         out.write(buf, 0, 253);
         out.write((byte) (buf.length + 2));

         out.write((byte) 4);  // tds version
         out.write((byte) 2);

         out.write((byte) 0);
         out.write((byte) 0);
         putLoginString(progName, 10); // prog name

         out.write((byte) 6);  // prog version
         out.write((byte) 0);
         out.write((byte) 0);
         out.write((byte) 0);

         out.write((byte) 0);  // auto convert short
         out.write((byte) 0x0D); // type of flt4
         out.write((byte) 0x11); // type of date4

         putLoginString(language, 30);  // language

         out.write((byte) 1);  // notify on lang change
         out.write((short) 0);  // security label hierachy
         out.write((byte) 0);  // security encrypted
         out.write(empty, 0, 8);  // security components
         out.write((short) 0);  // security spare

         putLoginString(charset, 30); // Character set

         out.write((byte) 1);  // notify on charset change
         putLoginString(String.valueOf(packetSize), 6); // length of tds packets

         out.write(empty, 0, 8);  // pad out to a longword

         out.flush(); // Send the packet
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
     * Process a TDS 4.2 column names token.
     * <p>
     * Note: Will be followed by a COL_FMT token.
     *
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tds4ColNamesToken(final StatementImpl cx) throws IOException 
    {
        ArrayList<ColInfo> colList = new ArrayList<ColInfo>();

        final int pktLen = in.readShort();
        this.tables = null;
        int bytesRead = 0;

        while (bytesRead < pktLen) {
            ColInfo col = new ColInfo();
            int nameLen = in.read();
            String name = in.readString(nameLen, connection.getCharset());

            bytesRead = bytesRead + 1 + nameLen;
            col.realName  = name;
            col.name = name;

            colList.add(col);
        }

        int colCnt  = colList.size();
        cx.setColumns(colList.toArray(new ColInfo[colCnt]));
    }

    /**
     * Process a TDS 4.2 column format token.
     *
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tds4ColFormatToken(final StatementImpl cx) throws IOException {
        final int pktLen = in.readShort();
        ColInfo[] columns = cx.getColumns();
        int bytesRead = 0;
        int numColumns = 0;
        while (bytesRead < pktLen) {
            if (numColumns > columns.length) {
                throw new IOException("Too many columns in TDS_COL_FMT packet");
            }
            ColInfo col = columns[numColumns];

            if (serverType == SQLSERVER) {
                col.userType = in.readShort();

                int flags = in.readShort();

                col.nullable = ((flags & 0x01) != 0)?
                                    ResultSetMetaData.columnNullable:
                                       ResultSetMetaData.columnNoNulls;
                col.isCaseSensitive = (flags & 0x02) != 0;
                col.isWriteable = (flags & 0x0C) != 0;
                col.isIdentity = (flags & 0x10) != 0;
            } else {
                // Sybase does not send column flags
                col.isCaseSensitive = false;
                col.isWriteable = true;

                if (col.nullable == ResultSetMetaData.columnNoNulls) {
                    col.nullable = ResultSetMetaData.columnNullableUnknown;
                }

                col.userType = in.readInt();
            }
            bytesRead += 4;

            bytesRead += readType(col);

            numColumns++;
        }

        if (numColumns != columns.length) {
            throw new IOException("Too few columns in TDS_COL_FMT packet");
        }

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
            // TDS 4.2 or TDS 5.0
            nameLen = in.read();
            bytesRead++;
            if (nameLen == 0) {
                continue; // Sybase/SQL 6.5 use a zero length name to terminate list
            }
            tabName = in.readString(nameLen, connection.getCharset());
            bytesRead += nameLen;
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
                final String colName = in.readString(nameLen, connection.getCharset());
                bytesRead += nameLen;
                col.realName = colName;
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
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tdsErrorToken(final StatementImpl cx)
        throws IOException
    {
        int pktLen = in.readShort(); // Packet length
        int sizeSoFar = 6;
        int number = in.readInt();
        in.read(); // state
        int severity = in.read();
        int msgLen = in.readShort();
        String message = in.readString(msgLen, connection.getCharset());
        sizeSoFar += 2 + msgLen;
        final int srvNameLen = in.read();
        in.readString(srvNameLen, connection.getCharset()); // server name
        sizeSoFar += 1 + srvNameLen;

        final int procNameLen = in.read();
        in.readString(procNameLen, connection.getCharset()); // proc name
        sizeSoFar += 1 + procNameLen;

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
        throws IOException, SQLException 
    {
        in.readShort(); // Packet length
        String name = in.readString(in.read(), connection.getCharset()); // Column Name
        // Next byte indicates if output parameter or return value
        // 1 = normal output param, 2 = function or stored proc return
        in.read();
        // Next byte is the parameter type that we supplied which
        // may not be the same as the parameter definition
        /* int inputTdsType = */ in.read();
        // Not sure what these bytes are (they always seem to be zero).
        in.skip(3);
        ColInfo col = new ColInfo();
        readType(col);
        Object value = readData(col);

        //
        // Real output parameters will either be unnamed or will have a valid
        // parameter name beginning with '@'. Ignore any other spurious parameters
        // such as those returned from calls to writetext in the proc.
        //
        if (name.length() == 0 || name.startsWith("@")) {
            // Set next output parameter in list
            cx.setNextOutputParam(value, col);
        }
    }

    /**
     * Process a login acknowledgement packet.
     *
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tdsLoginAckToken(final StatementImpl cx) throws IOException 
    {
        String product;
        int major, minor, build = 0;
        in.readShort(); // Packet length

        int ack = in.read(); // Ack TDS 5 = 5 for OK 6 for fail, 1/0 for the others

        //
        // Discard TDS Version information (must be 4.2)
        //
        in.read();
        in.read();
        in.read();
        in.read();

        product = in.readString(in.read(), connection.getCharset());

        if (product.toLowerCase().startsWith("microsoft")) {
            in.skip(1);
            major = in.read();
            minor = in.read();
        } else if (product.toLowerCase().contains("anywhere")) {
            // ASA  9 and below : 'Adaptive Server Anywhere',
            // ASA 10 and higher: 'SQL Anywhere'
            this.serverType = ANYWHERE;
            major = in.read();
            minor = in.read();
            in.skip(1);
        } else {
            this.serverType = SYBASE;
            major = in.read();
            if (major < 10) {
                major += 10; // Correct for Sybase 11.03
            }
            minor = in.read() * 10;
            minor += in.read();
        }
        in.skip(1);

        if (product.length() > 1 && -1 != product.indexOf('\0')) {
            product = product.substring(0, product.indexOf('\0'));
        }

        connection.setDBServerInfo(product, major, minor, build, this.serverType);

        if (ack != 5) {
            // Login rejected by server create SQLException
            cx.getMessages().addDiagnostic(4002, 14, "Login failed");
            this.token = TDS_ERROR_TOKEN;
        } else {
            // MJH 2005-11-02
            // If we get this far we are logged in OK so convert
            // any database security exceptions into warnings. 
            // Any exceptions are likely to be caused by problems in 
            // accessing the default database for this login id for 
            // SQL 6.5 and Sybase ASE. 
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
    private void tdsRowToken(final StatementImpl cx) throws IOException {
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
                    final String newDb = in.readString(clen, connection.getCharset());
                    clen = in.read();
                    final String oldDb = in.readString(clen, connection.getCharset());
                    connection.setDatabase(newDb, oldDb);
                    break;
                }

            case TDS_ENV_LANG:
                {
                    int clen = in.read();
                    String language = in.readString(clen, connection.getCharset());
                    clen = in.read();
                    String oldLang = in.readString(clen, connection.getCharset());
                    if (Logger.isActive()) {
                        Logger.println("Language changed from " + oldLang + " to " + language);
                    }
                    break;
                }

            case TDS_ENV_CHARSET:
                {
                    final int clen = in.read();
                    final String charset = in.readString(clen, connection.getCharset());
                    in.skip(len - 2 - clen);
                    connection.setServerCharset(charset);
                    break;
                }

            case TDS_ENV_PACKSIZE:
                    {
                        final int blocksize;
                        final int clen = in.read();
                        blocksize = Integer.parseInt(in.readString(clen, connection.getCharset()));
                        in.skip(len - 2 - clen);
                        out.setBufferSize(blocksize);
                        if (Logger.isActive()) {
                            Logger.println("Changed blocksize to " + blocksize);
                        }
                    }
                    break;

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
     * @param  cx the StatementImpl instance that owns this request.
     * @throws IOException
     */
    private void tdsDoneToken(final StatementImpl cx) throws IOException {
        this.doneStatus = (byte)in.read();
        in.skip(1);
        byte operation = (byte)in.read();
        in.skip(1);
        this.doneCount = in.readInt();
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

        if (serverType == SQLSERVER) {
            //
            // MS SQL Server provides additional information we
            // can use to return special row counts for DDL etc.
            //
            if (operation == (byte) 0xC1) {
                // For select supress row counts
                this.doneStatus &= ~DONE_ROW_COUNT;
            }
        }
    }

    /**
     * Execute SQL using TDS 4.2 protocol.
     *
     * @param cx the StatementImpl instance that owns this request.
     * @param sql The SQL statement to execute.
     * @param procName Stored procedure to execute or null.
     * @param parameters Parameters for call or null.
     * @param noMetaData Suppress meta data for cursor calls.
     * @throws SQLException
     */
    protected void localExecuteSQL(final StatementImpl cx,
                                   String sql,
                                   String procName,
                                   ParamInfo[] parameters,
                                   final boolean noMetaData,
                                   final boolean sendNow)
            throws IOException, SQLException 
    {
        if (procName != null) {
            Logger.printRPC(procName);
            // RPC call
            out.setPacketType(RPC_PKT);
            ByteBuffer bb = connection.getCharset().encode(procName);
            out.write((byte)bb.remaining());
            out.write(bb);
            out.write((short) (noMetaData ? 2 : 0));

            if (parameters != null) {
                for (int i = cx.getParamIndex() + 1; i < parameters.length; i++) {
                    if (parameters[i].name != null) {
                       bb = connection.getCharset().encode(parameters[i].name);
                       out.write((byte) bb.remaining());
                       out.write(bb);
                    } else {
                       out.write((byte) 0);
                    }

                    out.write((byte) (parameters[i].isOutput ? 1 : 0));
                    writeParam(parameters[i]);
                }
            }
            if (!sendNow) {
                // Send end of packet byte to batch RPC
                out.write((byte) BATCH_SEPARATOR);
            }
        } else if (sql.length() > 0) {
            if (parameters != null) {
                sql = Support.substituteParameters(sql, parameters, connection);
            }
            Logger.printSql(sql);
            out.setPacketType(QUERY_PKT);
            out.write(sql, connection.getCharset());
            if (!sendNow) {
                // Batch SQL statements
                out.write(" ", connection.getCharset());
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
    int readType(final ColInfo ci) throws IOException {
        int bytesRead = 1;
        // Get the TDS data type code
        int type = in.read();

        ci.tdsType     = type;
        ci.jdbcType    = types[type].jdbcType;
        ci.scale       = types[type].scale;
        ci.sqlType     = types[type].sqlType;
        ci.charset     = connection.getCharset();
        
        // Now get the buffersize if required
        switch (types[type].size) {

            case -4:
                // text or image
                ci.bufferSize = in.readInt();
                int lenName = in.readShort();

                ci.tableName = in.readString(lenName, connection.getCharset());
                bytesRead += 6 + lenName;
                break;

            case -3:
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

        // Fine tune Sybase or SQL 6.5 data types
        switch (ci.userType) {
            case  UDT_CHAR:
                ci.sqlType      = "char";
                ci.jdbcType    = java.sql.Types.CHAR;
                break;
            case  UDT_VARCHAR:
                ci.sqlType     = "varchar";
                ci.jdbcType    = java.sql.Types.VARCHAR;
                break;
            case  UDT_BINARY:
                ci.sqlType     = "binary";
                ci.displaySize = ci.bufferSize * 2;
                ci.jdbcType    = java.sql.Types.BINARY;
                break;
            case  UDT_VARBINARY:
                ci.sqlType     = "varbinary";
                ci.displaySize = ci.bufferSize * 2;
                ci.jdbcType    = java.sql.Types.VARBINARY;
                break;
            case UDT_SYSNAME:
                ci.sqlType     = "sysname";
                ci.jdbcType    = java.sql.Types.VARCHAR;
                break;
            case UDT_TIMESTAMP:
                ci.sqlType     = "timestamp";
                ci.displaySize = ci.bufferSize * 2;
                ci.jdbcType    = java.sql.Types.VARBINARY;
                break;
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
    Object readData(final ColInfo ci) throws IOException {
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

            case SYBCHAR:
            case SYBVARCHAR:
                len = in.read();

                if (len > 0) {
                    String value = in.readString(len, ci.charset);

                    if (len == 1 && ci.tdsType == SYBVARCHAR) {
                        // In TDS 4/5 zero length varchars are stored as a
                        // single space to distinguish them from nulls.
                        return (value.equals(" ")) ? "" : value;
                    }

                    return value;
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

            case SYBNUMERIC:
            case SYBDECIMAL:
                len = in.read();

                if (len > 0) {
                    int sign = in.read();

                    len--;
                    byte[] bytes = new byte[len];
                    BigInteger bi;

                    if (this.serverType == TdsCore.SYBASE) {
                        // Sybase order is MSB first!
                        for (int i = 0; i < len; i++) {
                            bytes[i] = (byte) in.read();
                        }

                        bi = new BigInteger((sign == 0) ? 1 : -1, bytes);
                    } else {
                        while (len-- > 0) {
                            bytes[len] = (byte)in.read();
                        }

                        bi = new BigInteger((sign == 0) ? -1 : 1, bytes);
                    }

                    return new BigDecimal(bi, ci.scale);
                }

                break;

            default:
                throw new IllegalStateException("Unsupported TDS data type 0x" + 
                                        Integer.toHexString(ci.tdsType & 0xFF));
        }

        return null;
    }

    /**
     * Retrieve the TDS native type code for the parameter.
     *
     * @param pi         the parameter descriptor
     */
    void setNativeType(final ParamInfo pi) throws SQLException {
        
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
                    if (pi.getAnsiLength(connection) <= VAR_MAX) {
                        pi.tdsType = SYBVARCHAR;
                        pi.sqlType = "varchar(255)";
                    } else {
                        pi.tdsType = SYBTEXT;
                        pi.sqlType = "text";
                    }
                    if (pi.isOutput && pi.sqlType.equals("text")) {
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
                    pi.tdsType = SYBBIT;
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
                    if (pi.length <= VAR_MAX) {
                        pi.tdsType = SYBVARBINARY;
                        pi.sqlType = "varbinary(255)";
                    } else {
                        pi.tdsType = SYBIMAGE;
                        pi.sqlType = "image";
                    } 
                    if (pi.isOutput && (pi.sqlType.equals("image"))) {
                        throw new SQLException(
                                    Messages.get("error.textoutparam"), "HY000");
                    }
                    break;

                case java.sql.Types.BIGINT:
                    // int8 not supported send as a decimal field
                    pi.tdsType  = SYBDECIMAL;
                    pi.sqlType = "decimal(" + connection.getMaxPrecision() + ')';
                    pi.scale = 0;

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
                    pi.tdsType = SYBVARCHAR;
                    pi.sqlType = "varchar(255)";
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
     * Write a parameter to the server request stream.
     *
     * @param pi          the parameter descriptor
     */
    private void writeParam(final ParamInfo pi) throws IOException {
        int len;

        switch (pi.tdsType) {
            //
            // TDS 4.2 varchar(255) format
            // 0x27 max_size actual_size data...
            // actualsize = 0 means value is null
            //
            case SYBVARCHAR:
                out.write((byte) pi.tdsType);
                out.write((byte) VAR_MAX);
                len = pi.getAnsiLength(this.connection);
                if (pi.value != null && len == 0) {
                    // SQL 6.5 does not allow zero length binary
                    pi.value  = " ";
                    pi.length = len = 1;
                }
                out.write((byte)len);
                pi.writeAnsi(out, this.connection);

                break;

            case SYBTEXT:
                len = pi.getAnsiLength(this.connection);
                if (pi.value != null && len == 0) {
                    // SQL 6.5 does not allow zero length binary
                    pi.value  = " ";
                    pi.length = len = 1;
                }

                out.write((byte) pi.tdsType);

                out.write((int) len);
                out.write((int) len);
                pi.writeAnsi(out, this.connection);

                break;

            case SYBVARBINARY:
                out.write((byte) pi.tdsType);
                out.write((byte) VAR_MAX);
                if (pi.value != null && pi.length == 0) {
                    // SQL 6.5 does not allow zero length binary
                    pi.value = new byte[1];
                    pi.length = 1;
                }
                out.write((byte) pi.length);
                pi.writeBytes(out, connection);

                break;

            case SYBIMAGE:
                if (pi.value != null && pi.length == 0) {
                    // Sybase and SQL 6.5 do not allow zero length binary
                    pi.value =  new byte[1];
                    pi.length = 1;
                }
                out.write((byte) pi.tdsType);
                out.write((int) pi.length);
                out.write((int) pi.length);
                pi.writeBytes(out, this.connection);

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

            case SYBNUMERIC:
            case SYBDECIMAL:
                out.write((byte) pi.tdsType);
                BigDecimal value = null;
                int prec = connection.getMaxPrecision();
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
                out.write(value, this.serverType);
                break;
                
            default:
                throw new IllegalStateException("Unsupported output TDS type "
                        + Integer.toHexString(pi.tdsType));
        }
    }
}
