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

import static net.sourceforge.jtds.jdbc.TdsCore.ANYWHERE;

import java.util.WeakHashMap;
import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Struct;
import java.sql.Types;
import java.sql.ResultSet;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Semaphore;

import javax.transaction.xa.XAException;
import javax.transaction.xa.XAResource;
import javax.transaction.xa.Xid;

import net.sourceforge.jtds.util.Logger;
import net.sourceforge.jtds.util.MSSqlServerInfo;

/**
 * jTDS implementation of the java.sql.Connection interface.
 * <p>
 * Implementation notes:
 * <ol>
 * <li>Environment setting code carried over from old jTDS otherwise
 *     generally a new implementation of Connection.
 * <li>Connection properties and SQLException text messages are loaded from
 *     a properties file.
 * <li>Character set handling is via java.nio.charset.
 * <li>Prepared SQL statements are converted to procedures in the prepareSQL method.
 * <li>Use of Stored procedures is optional and controlled via connection property.
 * <li>This Connection object maintains a table of weak references to associated
 *     statements. This allows the connection object to control the statements (for
 *     example to close them) but without preventing them being garbage collected in
 *     a pooled environment.
 * <li>Although this class extends the serializable ConnectionProperties class, this 
 * class does not support serializable.
 * </ol>
 *
 * @author Mike Hutchinson
 * @author Alin Sinpalean
 * @version $Id: ConnectionImpl.java,v 1.9 2009-11-14 13:49:43 ickzon Exp $
 */
public class ConnectionImpl implements java.sql.Connection {
    /** Constant for SNAPSHOT isolation on MS SQL Server 2005.*/
    public final static int TRANSACTION_SNAPSHOT = 4096;
    /**
     * SQL query to determine the server charset on Sybase.
     */
    private static final String SYBASE_SERVER_CHARSET_QUERY
            = "select name from master.dbo.syscharsets where id ="
            + " (select value from master.dbo.sysconfigures where config=131)";

    /**
     * SQL query to determine the server charset on Sybase ASA.
     */
    private static final String ANYWHERE_SERVER_CHARSET_QUERY
            = "SELECT DB_PROPERTY ( 'CharSet' )";

    /**
     * SQL query to determine the server charset on MS SQL Server 6.5.
     */
    private static final String SQL_SERVER_65_CHARSET_QUERY
            = "select name from master.dbo.syscharsets where id ="
            + " (select csid from master.dbo.syscharsets, master.dbo.sysconfigures"
            + " where config=1123 and id = value)";

    /** Sybase initial connection string. */
    private static String SYBASE_INITIAL_SQL    = "SET TRANSACTION ISOLATION LEVEL 1\r\n" +
                                            "SET CHAINED OFF\r\n" +
                                            "SET QUOTED_IDENTIFIER ON\r\n"+
                                            "SET TEXTSIZE 2147483647";
    /**
     * SQL Server initial connection string. Also contains a
     * <code>SELECT @@MAX_PRECISION</code> query to retrieve
     * the maximum precision for DECIMAL/NUMERIC data.
     */
    private static String SQL_SERVER_INITIAL_SQL = "SELECT @@MAX_PRECISION\r\n" +
                                            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED\r\n" +
                                            "SET IMPLICIT_TRANSACTIONS OFF\r\n" +
                                            "SET QUOTED_IDENTIFIER ON\r\n"+
                                            "SET TEXTSIZE 2147483647";
    
    /** SQL Server 2000 default collation. */
    private static byte defaultCollation[] = {0x00, 0x00, 0x00, 0x00, 0x00};
    /** URL prefix used by the driver (i.e <code>jdbc:jtds:</code>). */
    static String URL_PREFIX = "jdbc:jtds:";
    /** Driver major version. */
    static final int MAJOR_VERSION = 2;
    /** Driver minor version. */
    static final int MINOR_VERSION = 0;
    /** Driver version miscellanea (e.g "-rc2", ".1" or <code>null</code>). */
    static final String MISC_VERSION = "";    
    /** Default name for resource bundle containing the messages. */
    static final String DEFAULT_RESOURCE = "net.sourceforge.jtds.jdbc.Messages";
    /** Default Decimal Scale. */
    public static final int DEFAULT_SCALE = 10;
    /** Default precision for SQL Server 6.5 and 7. */
    public static final int DEFAULT_PRECISION_28 = 28;
    /** Default precision for Sybase and SQL Server 2000 and newer. */
    public static final int DEFAULT_PRECISION_38 = 38;

    /*
     * Conection properties
     */
    /** The orginal connection URL. */
    private final String url;
    /** The server protocol version. */
    private int tdsVersion;
    /** The blob buffer size. */
    private long lobBuffer;
    /** The use lobs option. */
    private boolean useLOBs;
    /*
     * Connection JDBC properties
     */
    /** Default auto commit state. */
    private boolean autoCommit;
    /** saved auto commit state. */
    private boolean saveAutoCommit;
    /** True if this connection is closed. */
    private volatile boolean closed;
    /** The current database name. */
    private String currentDatabase;
    /** True if this connection is read only. */
    private boolean readOnly;
    /** Default transaction isolation level. */
    private int transactionIsolation;
    /*
     * Database specific information
     */
    /** SQL Server 2000 collation. */
    private byte collation[] = defaultCollation;
    /** True if user specifies an explicit charset. */
    private boolean charsetSpecified;
    /** The database product name eg SQL SERVER. */
    private String databaseProductName;
    /** The product version eg 11.92. */
    private String databaseProductVersion;
    /** The major version number eg 11. */
    private int databaseMajorVersion;
    /** The minor version number eg 92. */
    private int databaseMinorVersion;
    /** Maximum decimal precision. */
    private int maxPrecision = DEFAULT_PRECISION_38; // Sybase default
    /** Java charset for encoding. */
    private Charset charset;
    /** Indicates multi byte charset. */
    private boolean wideCharset;
    /** Actual charset for this server. */
    private String charsetName;
    
    /*
     * instance variables
     */
    /** Statement cache.*/
    private StatementCache statementCache;
    /** List of statements associated with this connection. */
    private final WeakHashMap<Statement, Object> statements = new WeakHashMap<Statement, Object>(100);
    /** The network TCP/IP socket. */
    protected TdsSocket socket;
    /** The cored TDS protocol object. */
    private TdsCore baseTds;
    /** Cursor unique ID number. */
    private int cursorSequenceNo = 1;
    /** Procedures in this transaction. */
    private final ArrayList<String> procInTran = new ArrayList<String>();
    /** True if running distributed transaction. */
    private boolean xaTransaction;
    /** Dummy type map for get/set type map. */
    private Map<String,Class<?>> typeMap = new HashMap<String,Class<?>>();
    /** Cached instance of JtdsDatabaseMetaData. */
    private DatabaseMetaData databaseMetaData;
    /** The connection StatementImpl object. */
    StatementImpl baseStmt;
    /** The list of savepoints. */
    private final ArrayList<Savepoint> savepoints = new ArrayList<Savepoint>();
    /** Maps each savepoint to a list of tmep procedures created since the savepoint */
    private final Map<Savepoint, List<String>> savepointProcInTran = new HashMap<Savepoint, List<String>>();
    /** Counter for generating unique savepoint identifiers */
    private volatile int savepointId;
    /** User name for this connection. */
    private String user;
    /** Password for this connection. */
    private String password;
    /** DataSource with connection properties. */
    private CommonDataSource ds;
    /** Global login timeout flag. */
    boolean timedOut = false;
    /** Local copy of the serverType connection property. */
    private int serverType = TdsCore.SQLSERVER;
    /** Local copy of the prepareSql connection property. */
    private int prepareSql;
    /** Local copy of the sendStringParametersAsUnicode property. */
    private boolean sendUnicode;
    /** Connection timer thread. */
    private Timer timer;
    /** A dummy Resource Manager ID allocated by jTDS for emulation mode. */
    private static final int XA_CONNID   = 1;
    /** XA Switch constant for OPEN.     */
    private static final int XA_OPEN     = 1;
    /** XA Switch constant for Close.    */
    private static final int XA_CLOSE    = 2;
    /** XA Switch constant for START.    */
    private static final int XA_START    = 3;
    /** XA Switch constant for END.      */
    private static final int XA_END      = 4;
    /** XA Switch constant for ROLLBACK. */
    private static final int XA_ROLLBACK = 5;
    /** XA Switch constant for PREPARE.  */
    private static final int XA_PREPARE  = 6;
    /** XA Switch constant for COMMIT.   */
    private static final int XA_COMMIT   = 7;
    /** XA Switch constant for RECOVER.  */
    private static final int XA_RECOVER  = 8;
    /** XA Switch constant for FORGET.   */
    private static final int XA_FORGET   = 9;
    /** Internal version number for SQL Server 2000. */
    private static final int SQL_2000_VERSION = 8;
    /** Dummy transaction cookie used in emulation mode. */
    private static final byte[] dummyCookie = new byte[1];
    /** Default transaction timeout (10 minutes). */
    static final int DEFAULT_XA_TIMEOUT = 600;
    /** Set this field to 1 to enable tracing in the DLL. */
    private static final int XA_TRACE = 1;
    //
    // XA State variables
    //
    /** The XID currently active on this connection. */
    private Xid activeXid;
    /** Distributed transactions are being emulated. */
    private boolean isEmulated;
    /** xa_start has been called. */
    private boolean isStarted;
    /** xa_end has been called. */
    private boolean isEnded;
    /** xa_prepare has been called. */
    private boolean isPrepared;
    /** 2PC Emulation warning issued. */ 
    private boolean isWarningIssued;
    /** The connection ID allocated by the server. */
    private int connId;

    /**
     * Global list of active transactions.
     * <p/>NB. can include entries for more than one RM (server) but
     * in this case the XID's will differ.
     */
    private static final HashSet<ConnectionImpl> txList = new HashSet<ConnectionImpl>();

    /**
     * Construct a new database connection.
     * @param ds the dataSource instance with connection properties.
     * @param user the user name for this connection.
     * @param password the password for this connection.
     * @throws SQLException
     */
    ConnectionImpl(final CommonDataSource ds, 
                   final String user, 
                   final String password) throws SQLException 
    {
        Logger.initialize(ds);
        if (Logger.isTraceActive()) {
            String pTmp = (password == null)? null: "****";
            Logger.printMethod(this, null, new Object[]{user, pTmp});
        }
        this.user     = user;
        this.password = password;
        this.ds       = ds;
        this.url      = "";
        // guess server type based on connection string - in case of ASA
        // this might not be correct but will then be changed during login
        if (ds.getServerType().equalsIgnoreCase("sybase")) {
            serverType = TdsCore.SYBASE;
        } else if (ds.getServerType().equalsIgnoreCase("anywhere")) {
            serverType = TdsCore.ANYWHERE;
        }
        charsetName = ds.getCharset();
        prepareSql  = ds.getPrepareSql();
        isEmulated  = ds.getXaEmulation();
        lobBuffer   = ds.getLobBuffer();
        useLOBs     = ds.getUseLOBs();
        sendUnicode = ds.getSendStringParametersAsUnicode();
    }
    
    /**
     * Retrieve the actual server type.
     * </p> one of TdsCore.SQLSERVER or TdsCore.SYBASE
     * @return the server type as a <code>String</code>.
     */
    int getServerType() {
        return serverType;
    }
    
    /**
     * Local copy of the prepareSQL connection property.
     * @return the prepareSQL connection property as a <code>int</code>.
     */
    int getPrepareSql() {
        return prepareSql;
    }

    /**
     * Retrieve the connection timer thread.
     * @return the <code>Timer</code> instance.
     */
    synchronized Timer getTimer() {
        if (timer == null) {
            timer = new Timer("jTDS Timer", true);
        }
        return timer;
    }
    
    /**
     * Open the database connection.
     * <p/>This function used to be included in the constructor in previous versions
     * of the driver. Having a separate open method may facilitate reusing the
     * connection instance to implement fail over support. 
     * @throws SQLException
     */
    void open()  throws SQLException {
        Logger.printTrace("ConnectionImpl.open() invoked.");
        if (ds.getServerName().length() == 0) {
            throw (SQLException)Logger.logException(new SQLException(Messages.get("error.connection.nohost"), "08001"));
        }
        //
        // Initialize various instance variables ready for connection
        //
        String tds = ds.getTds();
        if (tds.equals("4.2")) {
            tdsVersion = TdsCore.TDS42;
        } else 
        if (tds.equals("5.0")) {
            tdsVersion = TdsCore.TDS50;
        } else 
        if (tds.equals("7.0")) {
            tdsVersion = TdsCore.TDS70;
        } else {
            tdsVersion = TdsCore.TDS80;
        }
        statementCache = new StatementCache(ds.getMaxStatements());
        procInTran.clear();
        statements.clear();
        autoCommit = true;
        saveAutoCommit = true;
        transactionIsolation = java.sql.Connection.TRANSACTION_READ_COMMITTED;
        charsetSpecified = ds.isPropertySet("charset");
        int portNumber = ds.getPortNumber();
        //
        // Get the instance port, if it is specified.
        // Named pipes use instance names differently.
        //
        if (ds.getInstance().length() > 0 && !ds.getNetworkProtocol().equalsIgnoreCase("namedpipes")) {
            final MSSqlServerInfo msInfo = new MSSqlServerInfo(ds.getServerName());

            portNumber = msInfo.getPortForInstance(ds.getInstance());

            if (portNumber == -1) {
                throw (SQLException)Logger.logException(new SQLException(
                                      Messages.get("error.msinfo.badinst", 
                                              ds.getServerName(), ds.getInstance()),
                                      "08003"));
            }
        }

        SQLWarning warn = null;

        try {
            boolean retry = false;
            //
            // Allow connection to retry if server rejects prelogin packets.
            // This is the same approach that the newer ODBC drivers seem to
            // take.
            //
            do {
                retry = false;
                timedOut = false;
                Timer t = null;
                TimerTask tt = null;
                if (ds.getLoginTimeout() > 0) {
                    // Start a login timer
                    t = getTimer();
                    tt = new TimerTask() {
                        public void run() {
                            if (ConnectionImpl.this.socket != null) {
                                ConnectionImpl.this.timedOut = true;
                                try {
                                    ConnectionImpl.this.socket.close();
                                } catch (Exception e) {
                                    // Ignore
                                }
                            }
                        }
                    };
                    t.schedule(tt, ds.getLoginTimeout() * 1000);
                }

                socket = TdsSocket.getInstance(ds, ds.getServerName(), portNumber);

                if (tt != null && timedOut) {
                    // If the timer has expired during the connection phase, close
                    // the socket and throw an exception
                    socket.close();
                    throw (SQLException)Logger.logException(new SQLException(Messages.get("error.connection.timeout"), 
                                    "HYT01"));
                }

                if (charsetSpecified) {
                    loadCharset(ds.getCharset());
                } else {
                    // Need a default charset to process login packets for TDS 4.2/5.0
                    // Will discover the actual serverCharset later
                    loadCharset("iso_1");
                    charsetName = null; // Means we will know if server sets name
                }
                //
                // Create TDS protocol object
                //
                if (serverType == ANYWHERE) {
                    baseTds = new TdsCoreASA(this, socket, getServerType());
                } else
                if (tdsVersion == TdsCore.TDS42) {
                    baseTds = new TdsCore42(this, socket, getServerType());
                } else 
                if (tdsVersion == TdsCore.TDS50) {
                    baseTds = new TdsCore50(this, socket, getServerType());
                } else {
                    baseTds = new TdsCore70(this, socket, tdsVersion);
                }
                //
                // Create base context object
                //
                baseStmt = new StatementImpl(this, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);

                //
                // Negotiate SSL connection and protocol level if required
                //
                if (tdsVersion >= TdsCore.TDS80) {
                    try {
                        String ssl = ds.getNetworkProtocol().equalsIgnoreCase("namedpipes")? "off": ds.getSsl();
                       baseTds.negotiateSSL(ds.getInstance(), ssl);
                    } catch (IOException e) {
                        if (e.getMessage().equals(Messages.get("error.io.serverclose"))) {
                            // Probably connecting to SQL Server 7, drop protocol
                            // level and retry
                            tdsVersion = TdsCore.TDS70;
                            retry = true;
                            Logger.println("Server rejected prelogin packets. Retry as TDS=7.0");
                            continue;
                        }
                        if (e.getMessage().equals(Messages.get("error.io.noprelogin"))) {
                            // Probably connecting to SQL Server 6.5, drop protocol
                            // level and connection and retry
                            socket.close();
                            tdsVersion = TdsCore.TDS42;
                            retry = true;
                            Logger.println("Server rejected prelogin packets. Retry as TDS=4.2");
                            continue;
                        }
                        
                        // Some unforeseen IOException
                        throw e;
                    }
                }

                int type = getServerType();

                try {
                    //
                    // Now try to login
                    //
                    baseTds.login(baseStmt,
                                  ds.getServerName(),
                                  ds.getDatabaseName(),
                                  user,
                                  password,
                                  ds.getDomain(),
                                  ds.getCharset(),
                                  ds.getAppName(),
                                  ds.getProgName(),
                                  ds.getWsid(),
                                  ds.getLanguage(),
                                  ds.getMacAddress(),
                                  ds.getPacketSize());

                } catch (SQLException e) {
                    // server type may have been changed during login
                    if (type != getServerType()) {
                        socket.close();
                        retry = true;
                        Logger.println("Assumed wrong server type, retry.");
                        continue;
                    } else {
                        throw e;
                    }
                }
                
                if (tt != null) {
                    // Cancel loginTimer
                    tt.cancel();
                }

                //
                // Save any login warnings so that they will not be overwritten by
                // the internal configuration SQL statements e.g. setCatalog() etc.
                //
                warn = baseStmt.getMessages().getWarnings();

                // Update the tdsVersion with the value in baseTds. baseTds sets
                // the TDS version for the socket and there are no other objects
                // with cached TDS versions at this point.
                tdsVersion =baseTds.getTdsVersion();
                if (tdsVersion < TdsCore.TDS70 && ds.getDatabaseName().length() > 0) {
                    // Need to select the default database
                    setCatalog(ds.getDatabaseName());
                }

                // ASA already opened database during login
                if (serverType == TdsCore.ANYWHERE) {
                    String db = ds.getDatabaseName();

                    if (db == null || db.length() == 0) {
                        ResultSet rs = null;
                        try {
                            rs = baseStmt.executeQuery("SELECT db_name()");
                            if (rs.next()) {
                               db = rs.getString(1);
                            }
                        } finally {
                            if (rs != null)
                                rs.close();
                        }
                        ds.setDatabaseName(db);
                    }
                    currentDatabase = db;
                }

                // Will retry if using TDS8 and attempting to connect to SQL Server 7 or 6.5
            } while (retry);
            //
        } catch (UnknownHostException e) {
            SQLException sqle =  (SQLException)Logger.logException(new SQLException(Messages.get("error.connection.badhost",
                            e.getMessage()), "08S03"));
            sqle.initCause(e);
            throw sqle;
        } catch (SocketTimeoutException e) {
            SQLException sqle = (SQLException)Logger.logException(new SQLException(Messages.get("error.connection.timeout"), 
                            "HYT01"));
            sqle.initCause(e);
            throw sqle;
        } catch (IOException e) {
            SQLException sqle = (SQLException)Logger.logException(new SQLException(Messages.get("error.connection.ioerror",
                            e.getMessage()), "08S01"));
            sqle.initCause(e);
            throw sqle;
        } catch (SQLException e) {
            if (ds.getLoginTimeout() > 0 && e.getMessage().indexOf("socket closed") >= 0) {
                SQLException sqle = new SQLException(Messages.get("error.connection.timeout"), "HYT01");
                sqle.initCause(e);
                throw sqle;
            }
            throw e;
        }
        //
        // Adjust the maximum prepareSQL level to correspond to protocol.
        //
        if ((tdsVersion == TdsCore.TDS42 || tdsVersion == TdsCore.TDS50) &&
            (prepareSql == TdsCore.PREPARE || prepareSql == TdsCore.EXECUTE_SQL)) {
            prepareSql = TdsCore.TEMPORARY_STORED_PROCEDURES;
        }
        // If charset is still unknown and the collation is not set either,
        // determine the charset by querying (we're using Sybase or SQL Server
        // 6.5)
        if (charsetName == null || charsetName.length() == 0) {
            loadCharset(determineServerCharset());
        }
        //
        // Set the optimised mapping for charsets
        //
        baseTds.setCharset(charset);
        //
        // Initial database settings.
        // Sets: auto commit mode  = true
        //       transaction isolation = read committed.
        if (ds.getServerType().equals("sybase") ||
            ds.getServerType().equals("anywhere")) {
            baseStmt.submitSQL(SYBASE_INITIAL_SQL);
        } else {
            // Also discover the maximum decimal precision:  28 (default)
            // or 38 for MS SQL Server 6.5/7, or 38 for 2000 and later.
            ResultSet rs = baseStmt.executeQuery(SQL_SERVER_INITIAL_SQL);

            if (rs.next()) {
                maxPrecision = rs.getByte(1);
            }

            rs.close();
        }

        baseStmt.getMessages().clearWarnings();
        //
        // Restore any login warnings so that the user can retrieve them
        // by calling Connection.getWarnings()
        //
        if (warn != null) {
            baseStmt.getMessages().addWarning(warn);
        }
        Logger.printTrace("ConnectionImpl.open() successful.");
    }
    
    /**
     * Retrieve the DataSource hosting the connection properties.
     * @return the <code>DataSource</code> instance.
     */
    CommonDataSource getDataSource()
    {
        return ds;
    }

    /**
     * Retrieve the TDS protocol version.
     *
     * @return The TDS version as an <code>int</code>.
     */
    int getTdsVersion() {
        return tdsVersion;
    }

    /**
     * Retrieves the next unique cursor name.
     *
     * @return the next cursor name as a <code>String</code>
     */
    synchronized String getCursorName() {
        String seq = "000000" + Integer.toHexString(cursorSequenceNo++).toUpperCase();

        return "_jtds" + seq.substring(seq.length() - 6, seq.length());
    }
    
    /**
     * Try to convert the SQL statement into a statement prepare.
     * <p>This method does not need to be synchronized as it is called 
     * from PreparedStatement.execute() etc only after the global connection
     * lock has been aquired.
     *
     * @param pstmt        the target prepared statement
     * @param sql          the SQL statement to prepare
     * @param params       the parameters
     * @param returnKeys   indicates whether the statement will return
     *                     generated keys
     * @param cursorNeeded indicates whether a cursor prepare is needed
     * @return the SQL procedure name as a <code>String</code> or null if the
     *         SQL cannot be prepared
     */
    String prepareSQL(final PreparedStatementImpl pstmt,
                      final String sql,
                      final ParamInfo[] params,
                      final boolean returnKeys,
                      final boolean cursorNeeded)
            throws SQLException {

        if (getPrepareSql() == TdsCore.UNPREPARED
                || getPrepareSql() == TdsCore.EXECUTE_SQL) {
            return null; // User selected not to use severside prepares
        }
        //
        // Check all parameters set
        //
        for (int i = 0; i < params.length; i++) {
            if (!params[i].isSet) {
                throw (SQLException)Logger.logException(new SQLException(Messages.get("error.prepare.paramnotset",
                                                    Integer.toString(i+1)),
                                       "07000"));
            }
        }       
        //
        // Create the unique statement key
        //
        String key =baseTds.getStatementKey(sql, params, 
                                            getCatalog(), 
                                            autoCommit, cursorNeeded);
        //
        // See if we have already built this one
        //
        ProcEntry proc = (ProcEntry) statementCache.get(key);

        if (proc != null) {
            //
            // Yes found in cache OK
            //

            // If already used by the statement, decrement use count
            Collection handles = pstmt.getStatementHandles();
            if (handles != null && handles.contains(proc)) {
                proc.release();
            }

            pstmt.setColMetaData(proc.getColMetaData());
            pstmt.setParamMetaData(proc.getParamMetaData());
        } else {
            //
            // No, so create the stored procedure now
            //
            proc =baseTds.prepare(pstmt,
                                   sql, params, cursorNeeded,
                                   pstmt.getResultSetType(),
                                   pstmt.getResultSetConcurrency(),
                                   returnKeys);

            if (proc == null) {
                proc = new ProcEntry();
                proc.setType(ProcEntry.PREP_FAILED);
            } else {
                // Meta data may be returned by sp_prepare
                proc.setColMetaData(pstmt.getColumns());
                pstmt.setColMetaData(proc.getColMetaData());
            }
            // OK we have built a proc so add it to the cache.
            addCachedProcedure(key, proc);
        }
        // Add the handle to the prepared statement so that the handles
        // can be used to clean up the statement cache properly when the
        // prepared statement is closed.
        pstmt.getStatementHandles().add(proc);

        // Give the user the name, will be null if prepare failed
        return proc.toString();
    }

    /**
     * Add a stored procedure to the statememt cache.
     * <p/>Also adds any stored procedure names to the cache used to track 
     * procedures created in the current transaction so that they can be
     * recreated if lost due to a rollback.
     * <p/>Not explicitly synchronized because it's only called by 
     * synchronized methods.
     *
     * @param key The signature of the procedure to cache.
     * @param proc The stored procedure descriptor.
     */
    void addCachedProcedure(final String key, final ProcEntry proc) {
        statementCache.put(key, proc);

        if (!autoCommit
                && proc.getType() == ProcEntry.PROCEDURE
                && getServerType() == TdsCore.SQLSERVER) {
            synchronized (procInTran) {
                procInTran.add(key);
            }
        }
        if (getServerType() == TdsCore.SQLSERVER
                && proc.getType() == ProcEntry.PROCEDURE
                && savepointId > 0) {
            // Only need to track SQL Server temp stored procs
            addCachedProcedure(key);
        }
    }

    /**
     * Remove a stored procedure from the cache.
     * <p>
     * Not explicitly synchronized because it's only called by synchronized
     * methods.
     *
     * @param key The signature of the procedure to remove from the cache.
     */
    void removeCachedProcedure(final String key) {
        statementCache.remove(key);

        if (!autoCommit) {
            procInTran.remove(key);
        }
    }

    /**
     * Retrieves the maximum decimal precision.
     *
     * @return the precision as an <code>int</code>
     */
    int getMaxPrecision() {
        return maxPrecision;
    }

    /**
     * Retrieve the multibyte status of the current character set.
     *
     * @return <code>boolean</code> true if a multi byte character set
     */
    boolean isWideChar() {
        return wideCharset;
    }

    /**
     * Retrieve the <code>CharsetInfo</code> instance used by this connection.
     *
     * @return the default <code>CharsetInfo</code> for this connection
     */
    Charset getCharset() {
        return charset;
    }

    /**
     * Called by the protocol to change the current character set.
     * </p>Not synchronized as only called from TdsCore 
     * during the initial login phase.
     *
     * @param charsetName the server character set name
     */
    void setServerCharset(final String charsetName) throws SQLException {
        // If the user specified a charset, ignore environment changes
        if (isCharsetSpecified()) {
            Logger.println("Server charset " + charsetName +
                    ". Ignoring as user requested " + ds.getCharset() + '.');
            return;
        }

        if (this.charsetName == null || !this.charsetName.equals(charsetName)) {
            loadCharset(charsetName);

            if (Logger.isActive()) {
                Logger.println("Set charset to " + charsetName + '/'
                        + charset.toString());
            }
        }
    }
    
    /**
     * Set the java character set.
     * @param cs the character set.
     */
    void setCharset(final Charset cs) {
        charset = cs;
        wideCharset = cs.newEncoder().maxBytesPerChar() > 1.0;
        charsetName = cs.name();
    }

    /**
     * Retrieve the LOB buffer size.
     * <p/>This value is cached to speed access over the datasource
     * getLobBuffer() call which uses a property lookup.
     * @return the LOB buffer size as a <code>long</code>.
     */
    long getLobBuffer()
    {
        return lobBuffer;
    }
    
    /**
     * Retrieve the use LOBs option flag.
     * <p/>This value is cached to speed access over the datasource
     * getLOBs() call which uses a property lookup.
     * @return the LOB buffer size as a <code>long</code>.
     */
    boolean getUseLOBs()
    {
        return useLOBs;
    }

    /**
     * Retrieve the use sendStringParametersAsUnicode option flag.
     * <p/>This value is cached to speed access over the datasource
     * call which uses a property lookup.
     * @return <code>boolean</code> true is strings should be sent as 
     * unicode.
     */
    boolean getSendUnicode()
    {
        return sendUnicode;
    }

    /**
     * Load the Java charset to match the server character set.
     *
     * @param charsetName the server character set
     */
    private void loadCharset(final String charsetName) throws SQLException {
        // MS SQL Server's iso_1 is Cp1252 not ISO-8859-1!
        if (getServerType() == TdsCore.SQLSERVER
                && charsetName.equalsIgnoreCase("iso_1")) {
            this.charsetName = "Cp1252";
        } else {
            this.charsetName = charsetName;
        }
        // Do not default to any charset; if the charset is not found we want
        // to know about it
        setCharset(CharsetUtil.getCharset(this.charsetName));
    }

    /**
     * Discovers the server charset for server versions that do not send
     * <code>ENVCHANGE</code> packets on login ack, by executing a DB
     * vendor/version specific query.
     * <p>
     * Will throw an <code>SQLException</code> if used on SQL Server 7.0 or
     * 2000; the idea is that the charset should already be determined from
     * <code>ENVCHANGE</code> packets for these DB servers.
     * <p>
     * Should only be called from the constructor.
     *
     * @return the default server charset
     * @throws SQLException if an error condition occurs
     */
    private String determineServerCharset() throws SQLException {
        String queryStr = null;

        switch (getServerType()) {
            case TdsCore.SQLSERVER:
                if (databaseProductVersion.indexOf("6.5") >= 0) {
                    queryStr = SQL_SERVER_65_CHARSET_QUERY;
                } else {
                    // This will never happen. Versions 7.0 and 2000 of SQL
                    // Server always send ENVCHANGE packets, even over TDS 4.2.
                    throw (SQLException)Logger.logException(new SQLException(
                            "Please use TDS protocol version 7.0 or higher"));
                }
                break;
            case TdsCore.ANYWHERE:
                // known to work for ASA 9 to 11
                queryStr = ANYWHERE_SERVER_CHARSET_QUERY;
                break;
            case TdsCore.SYBASE:
                // There's no need to check for versions here
                queryStr = SYBASE_SERVER_CHARSET_QUERY;
                break;
        }

        ResultSet rs = baseStmt.executeQuery(queryStr);
        rs.next();
        String name = rs.getString(1);
        rs.close();

        return name;
    }

    /**
     * Set the default collation for this connection.
     * <p>
     * Set by a SQL Server 2000 environment change packet. The collation
     * consists of the following fields:
     * <ul>
     * <li>bits 0-19  - The locale eg 0x0409 for US English which maps to code
     *                  page 1252 (Latin1_General).
     * <li>bits 20-31 - Reserved.
     * <li>bits 32-39 - Sort order (csid from syscharsets)
     * </ul>
     * If the sort order is non-zero it determines the character set, otherwise
     * the character set is determined by the locale id.
     * <p/>Does not need to be synchronized as only called from TdsCore when
     * processing an environment change packet during the initial login phase.
     *
     * @param collation The new collation.
     */
    void setCollation(final byte[] collation) throws SQLException {
        String strCollation = "0x" + Support.toHex(collation);
        // If the user specified a charset, ignore environment changes
        if (isCharsetSpecified()) {
            Logger.println("Server collation " + strCollation +
                    ". Ignoring as user requested " + ds.getCharset() + '.');
            return;
        }
        setCharset(CharsetUtil.getCharset(collation));
        
        if (Logger.isActive()) {
            Logger.println("Set collation to " + strCollation + '/'
                    + charset.toString());
        }
    }

    /**
     * Retrieve the SQL Server 2000 default collation.
     *
     * @return The collation as a <code>byte[5]</code>.
     */
    byte[] getCollation() {
        return collation;
    }

    /**
     * Retrieves whether a specific charset was requested on creation. If this
     * is the case, all character data should be encoded/decoded using that
     * charset.
     */
    boolean isCharsetSpecified() {
        return charsetSpecified;
    }

    /**
     * Called by the protcol to change the current database context.
     * </p>Not synchronized as only called by TdsCore in response to 
     * an environment change packet in the currently active context.
     * It is theoretically possible that one thread calling getCatalog()
     * may get an obsolete database name if another thread is calling 
     * setCatalog() at the same time. Two threads calling setCatalog 
     * on the same connection will be serialised by the connection lock.
     * @param newDb The new database selected on the server.
     * @param oldDb The old database as known by the server.
     * @throws SQLException
     */
    void setDatabase(final String newDb, final String oldDb)
            throws SQLException {
        if (currentDatabase != null && !oldDb.equalsIgnoreCase(currentDatabase)) {
            throw (SQLException)Logger.logException(new SQLException(Messages.get("error.connection.dbmismatch",
                                                      oldDb, currentDatabase),
                                   "HY096"));
        }

        currentDatabase = newDb;

        if (Logger.isActive()) {
            Logger.println("Changed database from " + oldDb + " to " + newDb);
        }
    }

    /**
     * Update the connection instance with information about the server.
     * </p>Not synchronized as only called from TdsCore 
     * during the initial login phase.
     *
     * @param databaseProductName The server name eg SQL Server.
     * @param databaseMajorVersion The major version eg 11
     * @param databaseMinorVersion The minor version eg 92
     * @param buildNumber The server build number.
     * @param serverType the server type (SYBASE, ANYWHERE or SQLSERVER).
     */
    void setDBServerInfo(final String databaseProductName,
                         final int databaseMajorVersion,
                         final int databaseMinorVersion,
                         final int buildNumber,
                         final int serverType) 
    {
        this.databaseProductName  = databaseProductName;
        this.databaseMajorVersion = databaseMajorVersion;
        this.databaseMinorVersion = databaseMinorVersion;
        this.serverType           = serverType;
        
        if (tdsVersion >= TdsCore.TDS70) {
            StringBuffer buf = new StringBuffer(10);

            if (databaseMajorVersion < 10) {
                buf.append('0');
            }

            buf.append(databaseMajorVersion).append('.');

            if (databaseMinorVersion < 10) {
                buf.append('0');
            }

            buf.append(databaseMinorVersion).append('.');
            buf.append(buildNumber);

            while (buf.length() < 10) {
                buf.insert(6, '0');
            }

            databaseProductVersion = buf.toString();
        } else {
            databaseProductVersion =
            databaseMajorVersion + "." + databaseMinorVersion;
        }
    }

    /**
     * Removes a statement object from the list maintained by the connection
     * and cleans up the statement cache if necessary.
     * <p>This method is not synchronized except where it accesses the 
     * statement list.
     *
     * @param statement the statement to remove
     */
    void removeStatement(final StatementImpl statement)
            throws SQLException {
        Logger.printTrace("ConnectionImpl.removeStatement() invoked.");
        // Remove the JtdsStatement from the statement list
        synchronized (statements) {
            statements.remove(statement);
        }

        if (statement instanceof PreparedStatementImpl && !closed) {
            // Clean up the prepared statement cache; getObsoleteHandles will
            // decrement the usage count for the set of used handles
            // statement cache methods are synchronized and the list of obsolete
            // statements will only be returned once.
            Collection handles = statementCache.getObsoleteHandles(
                                          ((PreparedStatementImpl) statement).getStatementHandles());

            if (handles != null) {
                if (getServerType() == TdsCore.SQLSERVER) {
                    // SQL Server unprepare
                    StringBuffer cleanupSql = new StringBuffer(handles.size() * 32);
                    for (Iterator iterator = handles.iterator(); iterator.hasNext(); ) {
                        ProcEntry pe = (ProcEntry) iterator.next();
                        // Could get put back if in a transaction that is
                        // rolled back
                        pe.appendDropSQL(cleanupSql);
                    }
                    Semaphore connectionLock = null;
                    try {
                        connectionLock = baseStmt.lockConnection();
                        if (cleanupSql.length() > 0) {
                            baseStmt.tdsExecute(cleanupSql.toString(), null, null, false, 0,
                                            -1, -1, true);
                        }
                    } finally {
                        baseStmt.freeConnection(connectionLock);
                    }
                } else {
                    // Sybase unprepare
                    Semaphore connectionLock = null;
                    try {
                        connectionLock = baseStmt.lockConnection();
                        for (Iterator iterator = handles.iterator(); iterator.hasNext(); ) {
                            ProcEntry pe = (ProcEntry)iterator.next();
                            if (pe.toString() != null) {
                                // Remove the Sybase light weight proc
                               baseTds.unPrepare(baseStmt, pe.toString());
                            }
                        }
                    } finally {
                        baseStmt.freeConnection(connectionLock);
                    }
                }
            }
        }
    }

    /**
     * Adds a statement object to the list maintained by the connection.
     * <p/>
     * WeakReferences are used so that statements can still be closed and
     * garbage collected even if not explicitly closed by the connection.
     *
     * @param statement statement to add
     */
    void addStatement(final StatementImpl statement) {
        Logger.printTrace("ConnectionImpl.addStatement() invoked.");
        synchronized (statements) {
            statements.put(statement, null);
        }
    }

    /**
     * Checks that the connection is still open.
     *
     * @throws SQLException if the connection is closed
     */
    void checkOpen() throws SQLException {
        if (closed) {
            throw (SQLException)Logger.logException(new SQLException(
                   Messages.get("error.generic.closed", "Connection"), "HY010"));
        }
    }

    /**
     * Forces the closed status on the statement if an I/O error has occurred.
     */
    void setClosed() {
        Logger.println("Connection force closed by a serious error.");
        closed = true;

        // Make sure we release the socket and all data buffered at the socket
        // level
        try {
            socket.close();
        } catch (IOException e) {
            // Ignore; shouldn't happen anyway
        }
    }

    /**
     * Checks that this connection is in local transaction mode.
     *
     * @param method the method name being tested
     * @throws SQLException if in XA distributed transaction mode
     */
    void checkLocal(final String method) throws SQLException {
        if (xaTransaction) {
            throw (SQLException)Logger.logException(new SQLException(
                    Messages.get("error.connection.badxaop", method), "HY010"));
        }
    }

    /**
     * Retrieve the XA transaction status.
     * @return <code>boolean</code> true if an XA transaction is active.
     */
    boolean isXaTransaction()
    {
        return xaTransaction;
    }
    
    /**
     * Reports that user tried to call a method which has not been implemented.
     *
     * @param method the method name to report in the error message
     * @throws SQLException always, with the not implemented message
     */
    static void notImplemented(final String method) throws SQLException {
        throw (SQLException)Logger.logException(new SQLException(
                Messages.get("error.generic.notimp", method), "HYC00"));
    }

    /**
     * Invokes the <code>xp_jtdsxa</code> extended stored procedure on the
     * server.
     * <p/>This method is not synchronized as simultaneous invocations will wait
     * on the lockConnection method.
     * 
     * @param args the arguments eg cmd, rmid, flags etc.
     * @param data option byte data eg open string xid etc.
     * @return optional byte data eg OLE cookie
     * @throws SQLException if an error condition occurs
     */
     byte[][] sendXaPacket(final int args[], final byte[] data)
            throws SQLException {
        ParamInfo params[] = new ParamInfo[6];
        params[0] = new ParamInfo(Types.INTEGER, null, ParamInfo.RETVAL);
        params[1] = new ParamInfo(Types.INTEGER, new Integer(args[1]), ParamInfo.INPUT);
        params[2] = new ParamInfo(Types.INTEGER, new Integer(args[2]), ParamInfo.INPUT);
        params[3] = new ParamInfo(Types.INTEGER, new Integer(args[3]), ParamInfo.INPUT);
        params[4] = new ParamInfo(Types.INTEGER, new Integer(args[4]), ParamInfo.INPUT);
        params[5] = new ParamInfo(Types.VARBINARY, data, ParamInfo.OUTPUT);

        Semaphore connectionLock = null;
        try {
            connectionLock = baseStmt.lockConnection();
            //
            // Execute our extended stored procedure (let's hope it is installed!).
            //
            baseStmt.tdsExecute(null, "master..xp_jtdsxa", params, false, 0, -1, -1, true);
            //
            // Now process results
            //
            ArrayList<byte[]> xids = null;
            baseStmt.processResults(true);
            ResultSet rs = baseStmt.getTdsResultSet();
            if (rs != null) {
                xids = new ArrayList<byte[]>();
                while (rs.next()) {
                    xids.add(rs.getBytes(1));
                }
            }
            baseStmt.getMessages().checkErrors();
            if (params[0].getOutValue() instanceof Integer) {
                // Should be return code from XA command
                args[0] = ((Integer)params[0].getOutValue()).intValue();
            } else {
                args[0] = -7; // XAException.XAER_RMFAIL
            }
            if (xids != null) {
                // List of XIDs from xa_recover
                byte list[][] = new byte[xids.size()][];
                for (int i = 0; i < xids.size(); i++) {
                    list[i] = xids.get(i);
                }
                return list;
            } else
            if (params[5].getOutValue() instanceof byte[]) {
                // xa_open  the xa connection ID
                // xa_start OLE Transaction cookie
                byte cookie[][] = new byte[1][];
                cookie[0] = (byte[])params[5].getOutValue();
                return cookie;
            } else {
                // All other cases
                return null;
            }
        } finally {
            baseStmt.freeConnection(connectionLock);
        }
    }

    /**
     * Enlists the current connection in a distributed transaction.
     * <p/>This method is not synchronized as multiple threads should
     * not be trying to enlist the same connection at the same time as
     * one thread can only belong to one XA transaction at a time. 
     * In practice this method is thread safe when using real XA support
     * via the MSDTC.
     * 
     * @param oleTranID the OLE transaction cookie or null to delist
     * @throws SQLException if an error condition occurs
     */
    void enlistConnection(final byte[] oleTranID, final boolean commit)
    throws SQLException 
    {
        //
        //      Check for internal error in driver
        //
        if (oleTranID != null && xaTransaction) {
            throw new IllegalStateException(
                          "Connection already enlisted in an XA Transaction");
        }
        if (ds.getXaEmulation()) {
            //
            // Emulate XA Support using local transactions
            //
            if (oleTranID == null) {
                xaTransaction = false;
                if (!commit) {
                    rollback();
                }
                // setAutoCommit will also commit the transaction.
                setAutoCommit(saveAutoCommit);
            } else {
                saveAutoCommit = autoCommit;
                setAutoCommit(false);
                xaTransaction = true;
            }
        } else {
            //
            // Real XA support available with SQL Server
            //
            Semaphore connectionLock = null;
            try {
                connectionLock = baseStmt.lockConnection();
                if (oleTranID != null) {
                    if (getPrepareSql() == TdsCore.TEMPORARY_STORED_PROCEDURES) {
                        // Can't handle roll backs for temp stored procs
                        // default to sp_executesql instead.
                        prepareSql = TdsCore.EXECUTE_SQL;
                    }
                    // 
                    // Send the OLE cookie to the server to enlist the session
                    // in the distributed transaction.
                    //
                   baseTds.enlistConnection(baseStmt, 1, oleTranID);
                   xaTransaction = true;
                } else {
                    //
                    // delist the session from a transaction.
                    // NB. May have already been delisted by XA abort.
                    //
                    if (xaTransaction) {
                       baseTds.enlistConnection(baseStmt, 1, null);
                       xaTransaction = false;
                    }
                }
            } finally {
                baseStmt.freeConnection(connectionLock);
            }
        }
    }

    /**
     * Retrieves the cached <code>TdsCore</code> or <code>null</code> if
     * nothing is cached and resets the cache (sets it to <code>null</code>).
     *
     * @return the cached TDS instance.
     * @todo Should probably synchronize on another object
     */
    TdsCore getBaseTds() {
        return baseTds;
    }

    /**
     * Retrieve the minor database version.
     * The database version as an <code>int</code>.
     */
    int getDatabaseMinorVersion()
    {
        return databaseMinorVersion;
    }
    
    /**
     * Retrieve the minor database version.
     * The database version as an <code>int</code>.
     */
    int getDatabaseMajorVersion()
    {
        return databaseMajorVersion;
    }

    /**
     * Add a savepoint to the list maintained by this connection.
     *
     * @param savepoint The savepoint object to add.
     * @throws SQLException
     */
    private void setSavepoint(final SavepointImpl savepoint) throws SQLException {
        Semaphore connectionLock = null;
        try {
            connectionLock = baseStmt.lockConnection();
            if (serverType == TdsCore.ANYWHERE) {
                baseStmt.submitSQL("BEGIN TRAN SAVE TRANSACTION jtds"
                        + savepoint.getId());
            } else {
                baseStmt.submitSQL("IF @@TRANCOUNT=0 BEGIN "
                        + "SET IMPLICIT_TRANSACTIONS OFF; BEGIN TRAN; " // Fix for bug []Patch: in SET IMPLICIT_TRANSACTIONS ON
                        + "SET IMPLICIT_TRANSACTIONS ON; END "          // mode BEGIN TRAN actually starts two transactions!
                        + "SAVE TRAN jtds" + savepoint.getId());
            }
        } finally {
            baseStmt.freeConnection(connectionLock);
        }
        synchronized (savepoint) {
            savepoints.add(savepoint);
        }
    }

    /**
     * Releases all savepoints. Used internally when committing or rolling back
     * a transaction.
     */
    void clearSavepoints() {
        synchronized (savepoints) {
            savepoints.clear();

            if (savepointProcInTran != null) {
                savepointProcInTran.clear();
            }

            savepointId = 0;
        }
    }

    //
    // ------------------- java.sql.Connection interface methods -------------------
    //

    public int getHoldability() throws SQLException {
        checkOpen();

        return ResultSet.HOLD_CURSORS_OVER_COMMIT;
    }

    public int getTransactionIsolation() throws SQLException {
        checkOpen();

        return transactionIsolation;
    }

    public void clearWarnings() throws SQLException {
        checkOpen();
        baseStmt.getMessages().clearWarnings();
    }

    /**
     * Releases this <code>Connection</code> object's database and JDBC
     * resources immediately instead of waiting for them to be automatically
     * released.
     * <p>
     * Calling the method close on a <code>Connection</code> object that is
     * already closed is a no-op.
     * <p>
     * <b>Note:</b> A <code>Connection</code> object is automatically closed
     * when it is garbage collected. Certain fatal errors also close a
     * <code>Connection</code> object.
     * <p>
     * Synchronized because it accesses the statement list and the
     * <code>baseTds</code>.
     *
     * @throws SQLException if a database access error occurs
     */
    synchronized public void close() throws SQLException {
        if (!closed) {
            Logger.printMethod(this, "close", null);
            try {
                //
                // Close any open statements
                //
                Object stmtList[] = null;

                synchronized (statements) {
                    stmtList = statements.keySet().toArray();
                }
                
                for (int i = stmtList.length-1; i >= 0; i--) {
                    Statement stmt = (Statement)stmtList[i];
                    try {
                        stmt.close();
                    } catch (SQLException ex) {
                        // Ignore
                    }
                }
                try {
                    // Close network connection
                    if (baseTds != null) {
                        baseTds.close(baseStmt);
                    }
                } catch (SQLException ex) {
                    // Ignore
                }
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException e) {
                // Ignore
            } finally {
                closed = true;
            }
            Logger.println("Physical database connection closed");
        }
    }

    //
    // This method is not synchronized as it has to aquire the global connection 
    // before it can proceed.
    //
    public void commit() throws SQLException {
        checkOpen();
        checkLocal("commit");

        if (getAutoCommit()) {
            throw (SQLException)Logger.logException(new SQLException(
                    Messages.get("error.connection.autocommit", "commit"),
                    "25000"));
        }
        
        Semaphore connectionLock = null;
        try {
            connectionLock = baseStmt.lockConnection();

            switch (getServerType()) {
                case TdsCore.SQLSERVER:
                    baseStmt.submitSQL("IF @@TRANCOUNT > 0 COMMIT TRAN");
                    if (getPrepareSql() == TdsCore.TEMPORARY_STORED_PROCEDURES) {
                        // Remove list of temp procedure created in this transaction
                        // as they are now committed.
                        synchronized (procInTran) {
                            procInTran.clear();
                        }
                    }
                    break;

                case TdsCore.SYBASE:
                    baseStmt.submitSQL("IF @@TRANCOUNT > 0 COMMIT TRAN");
                    break;

                case TdsCore.ANYWHERE:
                    // cannot rely on variable @@TRANCOUNT, ASA doesn't increment
                    // @@TRANCOUNT when a transaction is started implicitly
                    baseStmt.submitSQL("COMMIT TRAN");
                    break;
            }

            clearSavepoints();
        } finally {
            baseStmt.freeConnection(connectionLock);
        }
    }

    //
    // This method is not synchronized as it has to aquire the global connection 
    // before it can proceed.
    //
    public void rollback() throws SQLException {
        checkOpen();
        checkLocal("rollback");
        if (getAutoCommit()) {
            throw (SQLException)Logger.logException(new SQLException(
                    Messages.get("error.connection.autocommit", "rollback"),
                    "25000"));
        }

        Semaphore connectionLock = null;
        try {
            connectionLock = baseStmt.lockConnection();

            if (getPrepareSql() == TdsCore.TEMPORARY_STORED_PROCEDURES
                    && getServerType() == TdsCore.SQLSERVER) {
                synchronized (procInTran) {
                    // Remove any stored procs created in this transaction
                    // as they have now been dropped
                    for (int i = 0; i < procInTran.size(); i++) {
                        String key = procInTran.get(i);
                        if (key != null) {
                            statementCache.remove(key);
                        }
                    }
                    procInTran.clear();
                }
            }
            
            clearSavepoints();

            switch (getServerType()) {
                case TdsCore.SQLSERVER:
                    // fall through

                    case TdsCore.SYBASE:
                    baseStmt.submitSQL("IF @@TRANCOUNT > 0 ROLLBACK TRAN");
                    break;

                case TdsCore.ANYWHERE:
                    // cannot rely on variable @@TRANCOUNT, ASA doesn't increment
                    // @@TRANCOUNT when a transaction is started implicitly
                    baseStmt.submitSQL("ROLLBACK TRAN");
                    break;
            }
        } finally {
            baseStmt.freeConnection(connectionLock);
        }
    }

    public boolean getAutoCommit() throws SQLException {
        checkOpen();
        if (xaTransaction) {
            return false;
        }
        return autoCommit;
    }

    public boolean isClosed() throws SQLException {
        return closed;
    }

    public boolean isReadOnly() throws SQLException {
        checkOpen();

        return readOnly;
    }

    public void setHoldability(int holdability) throws SQLException {
        checkOpen();
        switch (holdability) {
            case ResultSet.HOLD_CURSORS_OVER_COMMIT:
                break;
            case ResultSet.CLOSE_CURSORS_AT_COMMIT:
                throw (SQLException)Logger.logException(new SQLException(
                        Messages.get("error.generic.optvalue",
                                "CLOSE_CURSORS_AT_COMMIT",
                                "setHoldability"),
                        "HY092"));
            default:
                throw (SQLException)Logger.logException(new SQLException(
                        Messages.get("error.generic.badoption",
                                Integer.toString(holdability),
                                "holdability"),
                        "HY092"));
        }
    }

    //
    // This method is not synchronized as it has to aquire the global connection 
    // before it can proceed to change the isolation level.
    //
    public void setTransactionIsolation(int level) throws SQLException {
        checkOpen();

        if (transactionIsolation == level) {
            // No need to submit a request
            return;
        }

        String sql = "SET TRANSACTION ISOLATION LEVEL ";
        boolean sybase = getServerType() == TdsCore.SYBASE ||
                         getServerType() == TdsCore.ANYWHERE;

        switch (level) {
            case java.sql.Connection.TRANSACTION_READ_UNCOMMITTED:
                sql += (sybase) ? "0" : "READ UNCOMMITTED";
                break;
            case java.sql.Connection.TRANSACTION_READ_COMMITTED:
                sql += (sybase) ? "1" : "READ COMMITTED";
                break;
            case java.sql.Connection.TRANSACTION_REPEATABLE_READ:
                sql += (sybase) ? "2" : "REPEATABLE READ";
                break;
            case java.sql.Connection.TRANSACTION_SERIALIZABLE:
                sql += (sybase) ? "3" : "SERIALIZABLE";
                break;
            case TRANSACTION_SNAPSHOT:
                if (sybase) {
                    throw (SQLException)Logger.logException(new SQLException(
                            Messages.get("error.generic.optvalue",
                                    "TRANSACTION_SNAPSHOT",
                                    "setTransactionIsolation"),
                            "HY024"));
                }
                sql += "SNAPSHOT";
                break;
            case java.sql.Connection.TRANSACTION_NONE:
                throw (SQLException)Logger.logException(new SQLException(
                        Messages.get("error.generic.optvalue",
                                "TRANSACTION_NONE",
                                "setTransactionIsolation"),
                        "HY024"));
            default:
                throw (SQLException)Logger.logException(new SQLException(
                        Messages.get("error.generic.badoption",
                                Integer.toString(level),
                                "level"),
                        "HY092"));
        }
        Semaphore connectionLock = null;
        try {
            connectionLock = baseStmt.lockConnection();
            baseStmt.submitSQL(sql);

            transactionIsolation = level;
        } finally {
            baseStmt.freeConnection(connectionLock);
        }
    }

    //
    // This method is not synchronized as it has to aquire the global connection 
    // before it can proceed to change the transaction mode.
    //
    public void setAutoCommit(boolean autoCommit) throws SQLException {
        checkOpen();
        checkLocal("setAutoCommit");

        if (this.autoCommit == autoCommit) {
            // If we don't need to change the current auto commit mode, don't
            // submit a request and don't commit either. Section 10.1.1 of the
            // JDBC 3.0 spec states that the transaction should be committed
            // only "if the value of auto-commit is _changed_ in the middle of
            // a transaction". This takes precedence over the API docs, which
            // states that "if this method is called during a transaction, the
            // transaction is committed".
            return;
        }

        StringBuffer sql = new StringBuffer(70);
        //
        if (!this.autoCommit) {
            // If we're in manual commit mode the spec requires that we commit
            // the transaction when setAutoCommit() is called
            switch (getServerType()) {
                case TdsCore.SQLSERVER:
                    // fall through

                case TdsCore.SYBASE:
                    baseStmt.submitSQL("IF @@TRANCOUNT > 0 COMMIT TRAN\r\n");
                    break;

                case TdsCore.ANYWHERE:
                    // cannot rely on variable @@TRANCOUNT, ASA doesn't increment
                    // @@TRANCOUNT when a transaction is started implicitly
                    baseStmt.submitSQL("COMMIT TRAN\r\n");
                    break;
            }            
        }

        switch (getServerType()) {
            case TdsCore.SQLSERVER:
                if (autoCommit) {
                    sql.append("SET IMPLICIT_TRANSACTIONS OFF");
                } else {
                    sql.append("SET IMPLICIT_TRANSACTIONS ON");
                }
                break;

            case TdsCore.SYBASE:
                // fall through

            case TdsCore.ANYWHERE:
                if (autoCommit) {
                    sql.append("SET CHAINED OFF");
                } else {
                    sql.append("SET CHAINED ON");
                }
                break;
        }
        Semaphore connectionLock = null;
        try {
            connectionLock = baseStmt.lockConnection();
            baseStmt.submitSQL(sql.toString());
            this.autoCommit = autoCommit;
        } finally {
            baseStmt.freeConnection(connectionLock);
        }
    }

    public void setReadOnly(boolean readOnly) throws SQLException {
        checkOpen();
        if (!autoCommit || xaTransaction) {
            // Throw an exception if in a transaction
            throw (SQLException)Logger.logException(new SQLException(Messages.get("error.connection.noreadonly"), "25000"));
        }
        this.readOnly = readOnly;
    }

    public String getCatalog() throws SQLException {
        checkOpen();

        return currentDatabase;
    }

    //
    // This method is not synchronized as it has to aquire the global connection 
    // before it can proceed to change the database. 
    //
    public void setCatalog(String catalog) throws SQLException {
        checkOpen();

        if (currentDatabase != null && currentDatabase.equals(catalog)) {
            return;
        }

        int maxlength = tdsVersion >= TdsCore.TDS70 ? 128 : 30;
        
        if (catalog.length() > maxlength || catalog.length() < 1) {
            throw (SQLException)Logger.logException(new SQLException(
                    Messages.get("error.generic.badparam",
                            catalog,
                            "catalog"),
                    "3D000"));
        }

        String sql = tdsVersion >= TdsCore.TDS70
                ? ("use [" + catalog + ']') : "use " + catalog;
        Semaphore connectionLock = null;        
        try {
            connectionLock = baseStmt.lockConnection();
            baseStmt.submitSQL(sql);
        } finally {
            baseStmt.freeConnection(connectionLock);
        }
    }

    public DatabaseMetaData getMetaData() throws SQLException {
        checkOpen();
        if (databaseMetaData == null) {
            if (serverType == ANYWHERE) {
                databaseMetaData = new DatabaseMetaDataImplASA(this,
                                                                databaseProductName,
                                                                databaseProductVersion,
                                                                databaseMajorVersion,
                                                                databaseMinorVersion,
                                                                url);
            } else {
                databaseMetaData = new DatabaseMetaDataImpl(this,
                                                            databaseProductName,
                                                            databaseProductVersion,
                                                            databaseMajorVersion,
                                                            databaseMinorVersion,
                                                            url);
            }
        }
        return databaseMetaData;
    }

    public SQLWarning getWarnings() throws SQLException {
        checkOpen();

        return baseStmt.getMessages().getWarnings();
    }

    public Statement createStatement() throws SQLException {
        checkOpen();

        return createStatement(java.sql.ResultSet.TYPE_FORWARD_ONLY,
                               java.sql.ResultSet.CONCUR_READ_ONLY);
    }

    public Statement createStatement(int type, int concurrency)
            throws SQLException {
        checkOpen();

        StatementImpl stmt = new StatementImpl(this, type, concurrency);
        addStatement(stmt);

        return stmt;
    }

    public Statement createStatement(int type, int concurrency, int holdability)
            throws SQLException {
        checkOpen();
        setHoldability(holdability);

        return createStatement(type, concurrency);
    }

    public Map<String,Class<?>> getTypeMap() throws SQLException {
        checkOpen();

        return typeMap;
    }

    public void setTypeMap(Map<String,Class<?>> map) throws SQLException {
        checkOpen();
        // Some applications (e.g. the Sun RowSet classes) call 
        // this method with an empty type map by default.
        // Provided the map is empty we permit this to avoid 
        // generating an exception.
        if (map.size() != 0) {
            notImplemented("Connection.setTypeMap(Map)");
        }
        // Save the map so that we can give the caller the same 
        // map instance back if requested.
        typeMap = map;
    }

    public String nativeSQL(String sql) throws SQLException {
        checkOpen();

        if (sql == null || sql.length() == 0) {
            throw (SQLException)Logger.logException(new SQLException(Messages.get("error.generic.nosql"), "HY000"));
        }

        String[] result = SQLParser.parse(sql, new ArrayList<ParamInfo>(), this, false);

        return result[0];
    }

    public CallableStatement prepareCall(String sql) throws SQLException {
        checkOpen();

        return prepareCall(sql,
                           java.sql.ResultSet.TYPE_FORWARD_ONLY,
                           java.sql.ResultSet.CONCUR_READ_ONLY);
    }

    public CallableStatement prepareCall(String sql, int type,
                                                      int concurrency)
            throws SQLException {
        checkOpen();

        if (sql == null || sql.length() == 0) {
            throw (SQLException)Logger.logException(new SQLException(Messages.get("error.generic.nosql"), "HY000"));
        }

        CallableStatementImpl stmt = new CallableStatementImpl(this,
                                                               sql,
                                                               type,
                                                               concurrency);
        addStatement(stmt);

        return stmt;
    }

    public CallableStatement prepareCall(
                                        String sql,
                                        int type,
                                        int concurrency,
                                        int holdability)
    throws SQLException {
        checkOpen();
        setHoldability(holdability);
        return prepareCall(sql, type, concurrency);
    }

    public PreparedStatement prepareStatement(String sql)
            throws SQLException {
        checkOpen();

        return prepareStatement(sql,
                                java.sql.ResultSet.TYPE_FORWARD_ONLY,
                                java.sql.ResultSet.CONCUR_READ_ONLY);
    }

    public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys)
            throws SQLException {
        checkOpen();

        if (sql == null || sql.length() == 0) {
            throw (SQLException)Logger.logException(new SQLException(Messages.get("error.generic.nosql"), "HY000"));
        }

        if (autoGeneratedKeys != Statement.RETURN_GENERATED_KEYS &&
            autoGeneratedKeys != Statement.NO_GENERATED_KEYS) {
            throw (SQLException)Logger.logException(new SQLException(
                    Messages.get("error.generic.badoption",
                            Integer.toString(autoGeneratedKeys),
                            "autoGeneratedKeys"),
                    "HY092"));
        }

        PreparedStatementImpl stmt = new PreparedStatementImpl(this,
                sql,
                java.sql.ResultSet.TYPE_FORWARD_ONLY,
                java.sql.ResultSet.CONCUR_READ_ONLY,
                autoGeneratedKeys == Statement.RETURN_GENERATED_KEYS);
        addStatement(stmt);

        return stmt;
    }

    public PreparedStatement prepareStatement(String sql,
                                              int type,
                                              int concurrency)
            throws SQLException {
        checkOpen();

        if (sql == null || sql.length() == 0) {
            throw (SQLException)Logger.logException(new SQLException(Messages.get("error.generic.nosql"), "HY000"));
        }

        PreparedStatementImpl stmt = new PreparedStatementImpl(this,
                                                               sql,
                                                               type,
                                                               concurrency,
                                                               false);
        addStatement(stmt);

        return stmt;
    }

    public PreparedStatement prepareStatement(
                                             String sql,
                                             int type,
                                             int concurrency,
                                             int holdability)
    throws SQLException {
        checkOpen();
        setHoldability(holdability);

        return prepareStatement(sql, type, concurrency);
    }

    public PreparedStatement prepareStatement(String sql, int[] columnIndexes)
            throws SQLException {
        if (columnIndexes == null) {
            throw (SQLException)Logger.logException(new SQLException(
                                  Messages.get("error.generic.nullparam", "prepareStatement"),"HY092"));
        } else if (columnIndexes.length != 1) {
            throw (SQLException)Logger.logException(new SQLException(
                                  Messages.get("error.generic.needcolindex", "prepareStatement"),"HY092"));
        }

        return prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
    }
    
    public PreparedStatement prepareStatement(String sql, String[] columnNames)
            throws SQLException {
        if (columnNames == null) {
            throw (SQLException)Logger.logException(new SQLException(
                                  Messages.get("error.generic.nullparam", "prepareStatement"),"HY092"));
        } else if (columnNames.length != 1) {
            throw (SQLException)Logger.logException(new SQLException(
                                  Messages.get("error.generic.needcolname", "prepareStatement"),"HY092"));
        }

        return prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
    }

    public void releaseSavepoint(Savepoint savepoint)
        throws SQLException {
        checkOpen();
        synchronized (savepoints) {
            int index = savepoints.indexOf(savepoint);

            if (index == -1) {
                throw (SQLException)Logger.logException(new SQLException(
                        Messages.get("error.connection.badsavep"), "25000"));
            }

            Object tmpSavepoint = savepoints.remove(index);

            if (index != 0) {
                // If this wasn't the outermost savepoint, move all procedures
                // to the "wrapping" savepoint's list; when and if that
                // savepoint will be rolled back it will clear these procedures
                // too
                List<String> keys = savepointProcInTran.get(savepoint);

                if (keys != null) {
                    Savepoint wrapping = savepoints.get(index - 1);
                    List<String> wrappingKeys =
                        savepointProcInTran.get(wrapping);
                    if (wrappingKeys == null) {
                        wrappingKeys = new ArrayList<String>();
                    }
                    wrappingKeys.addAll(keys);
                    savepointProcInTran.put(wrapping, wrappingKeys);
                }
            }

            // If this was the outermost savepoint, just drop references to
            // all procedures; they will be managed by the connection
            savepointProcInTran.remove(tmpSavepoint);
        }
    }

    public void rollback(Savepoint savepoint) throws SQLException {
        checkOpen();
        checkLocal("rollback");

        synchronized (savepoints) {
            int index = savepoints.indexOf(savepoint);
    
            if (index == -1) {
                throw (SQLException)Logger.logException(new SQLException(
                        Messages.get("error.connection.badsavep"), "25000"));
            } else if (getAutoCommit()) {
                throw (SQLException)Logger.logException(new SQLException(
                        Messages.get("error.connection.savenorollback"), "25000"));
            }

            int size = savepoints.size();

            for (int i = size - 1; i >= index; i--) {
                Object tmpSavepoint = savepoints.remove(i);

                List keys = savepointProcInTran.get(tmpSavepoint);

                if (keys == null) {
                    continue;
                }

                for (Iterator iterator = keys.iterator(); iterator.hasNext();) {
                    String key = (String) iterator.next();

                    removeCachedProcedure(key);
                }
            }
        }
        Semaphore connectionLock = null;
        try {
            connectionLock = baseStmt.lockConnection();
            baseStmt.submitSQL("ROLLBACK TRAN jtds" + ((SavepointImpl) savepoint).getId());
        } finally {
            baseStmt.freeConnection(connectionLock);
        }

        // recreate savepoint
        setSavepoint((SavepointImpl) savepoint);
    }

    public Savepoint setSavepoint() throws SQLException {
        checkOpen();
        checkLocal("setSavepoint");

        if (getAutoCommit()) {
            throw (SQLException)Logger.logException(new SQLException(
                    Messages.get("error.connection.savenoset"), "25000"));
        }

        SavepointImpl savepoint = new SavepointImpl(getNextSavepointId());

        setSavepoint(savepoint);

        return savepoint;
    }

    public Savepoint setSavepoint(String name) throws SQLException {
        checkOpen();
        checkLocal("setSavepoint");

        if (getAutoCommit()) {
            throw (SQLException)Logger.logException(new SQLException(
                    Messages.get("error.connection.savenoset"), "25000"));
        } else if (name == null) {
            throw (SQLException)Logger.logException(new SQLException(
                    Messages.get("error.connection.savenullname", "savepoint"),
            "25000"));
        }

        SavepointImpl savepoint = new SavepointImpl(getNextSavepointId(), name);

        setSavepoint(savepoint);

        return savepoint;
    }

    /**
     * Returns the next savepoint identifier.
     *
     * @return the next savepoint identifier
     */
    private int getNextSavepointId() {
        synchronized (savepoints) {
            return ++savepointId;
        }
    }


    /**
     * Add a stored procedure to the savepoint cache.
     *
     * @param key The signature of the procedure to cache.
     */
    void addCachedProcedure(final String key) {
        synchronized (savepoints) {
            if (savepoints.size() == 0) {
                return;
            }

            // Retrieve the current savepoint
            Savepoint savepoint = savepoints.get(savepoints.size() - 1);
    
            List<String> keys = savepointProcInTran.get(savepoint);

            if (keys == null) {
                keys = new ArrayList<String>();
            }

            keys.add(key);

            savepointProcInTran.put(savepoint, keys);
        }
    }
    //
    //  ----- XA support routines -----
    //
    /**
     * Invoke the xa_open routine on the SQL Server.
     */
    void xa_open()
            throws SQLException {

        if (isEmulated) {
            //
            // Emulate xa_open method
            //
            Logger.println("xa_open: emulating distributed transaction support");
            connId = XA_CONNID;
            return;
        }
        //
        // Execute xa_open via MSDTC
        //
        // Check that we are using SQL Server 2000+
        //
        int dbVersion = getMetaData().getDatabaseMajorVersion();
        if (serverType != TdsCore.SQLSERVER || dbVersion < SQL_2000_VERSION) {
            throw (SQLException)Logger.logException(new SQLException(Messages.get("error.xasupport.nodist"), "HY000"));
        }
        Logger.println("xa_open: Using SQL2000 MSDTC to support distributed transactions");
        //
        // OK Now invoke extended stored procedure to register this connection.
        //
        int args[] = new int[5];
        args[1] = XA_OPEN;
        args[2] = XA_TRACE;
        args[3] = dbVersion;
        args[4] = XAResource.TMNOFLAGS;
        byte[][] id;
        id = sendXaPacket(args, null);
        if (args[0] != XAResource.XA_OK
                || id == null
                || id[0] == null
                || id[0].length != 4) {
            throw (SQLException)Logger.logException(new SQLException(
                            Messages.get("error.xasupport.badopen"), "HY000"));
        }
        //
        // The resource manager (ie the MSTDC proxy) allocates a unique 
        // Resource manager ID to use for this connection.
        //
        connId = (id[0][0] & 0xFF) |
                     ((id[0][1] & 0xFF) << 8) |
                     ((id[0][2] & 0xFF) << 16) |
                     ((id[0][3] & 0xFF) << 24);

        return;
    }

    /**
     * Invoke the xa_close routine on the SQL Server.
     */
    void xa_close() throws SQLException {

        //
        Logger.printMethod(this, "xa_close", null);
        //
        if (isEmulated) {
            //
            // Emulate xa_close method
            //
            if (isPrepared || isEnded) {
                enlistConnection(null, false);
            }
            if (activeXid != null) {
                activeXid = null;
                throw (SQLException)Logger.logException(new SQLException(
                        Messages.get("error.xasupport.activetran", "xa_close"),
                                        "HY000"));
            }
            return;
        }
        //
        // Execute xa_close via MSDTC
        //
        int args[] = new int[5];
        args[1] = XA_CLOSE;
        args[2] = connId;
        args[3] = 0;
        args[4] = XAResource.TMNOFLAGS;
        sendXaPacket(args, null);
    }

    /**
     * Invoke the xa_start routine on the SQL Server.
     *
     * @param xid   The XA Transaction ID object.
     * @param flags XA Flags for start command
     * @param timeout the XA transaction timeout.
     * @exception javax.transaction.xa.XAException
     *             if an error condition occurs
     */
    void xa_start(final Xid xid, final int flags, final int timeout)
            throws XAException {

        XidImpl lxid = new XidImpl(xid);

        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "xa_start", 
                    new Object[]{lxid, new Integer(flags), new Integer(timeout)});
        }

        if (isEmulated) {
            //
            // Emulate xa_start method
            //
            if (flags != XAResource.TMNOFLAGS) {
                // TMJOIN and TMRESUME cannot be supported
                raiseXAException(XAException.XAER_INVAL);
            }
            if (activeXid != null) {
                if (activeXid.equals(lxid)) {
                    raiseXAException(XAException.XAER_DUPID);
                } else {
                    raiseXAException(XAException.XAER_PROTO);
                }
            }
            
            try {
                enlistConnection(dummyCookie, false);
            } catch (SQLException e) {
                raiseXAException(XAException.XAER_RMERR);
            }
            activeXid = lxid;
            isStarted = true;
            return;
        }
        //
        // Execute xa_start via MSDTC
        //
        int args[] = new int[5];
        args[1] = XA_START;
        args[2] = connId;
        args[3] = timeout * 1000;
        args[4] = flags;
        byte[][] cookie;
        try {
            cookie = sendXaPacket(args, lxid.toBytes());
            if (args[0] == XAResource.XA_OK && cookie != null) {
                enlistConnection(cookie[0], false);
            }
        } catch (SQLException e) {
            raiseXAException(e);
        }
        if (args[0] != XAResource.XA_OK) {
            raiseXAException(args[0]);
        }
        activeXid = lxid;
        isStarted = true;
        //
        // Add to global transaction list so that we can generate xa_end
        // commands if the server does not pair start and end correctly.
        //
        synchronized (txList) {
            txList.add(this);
        }
    }

    /**
     * Invoke the xa_end routine on the SQL Server.
     *
     * @param xid   The XA Transaction ID object.
     * @param flags XA Flags for start command
     * @exception javax.transaction.xa.XAException
     *             if an error condition occurs
     */
    void xa_end(final Xid xid, final int flags)
            throws XAException {

        XidImpl lxid = new XidImpl(xid);
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "xa_end", new Object[]{lxid, new Integer(flags)});
        }
        if (isEmulated) {
            //
            // Emulate xa_end method
            //
            if (!isStarted) {
                // Connection not started
                raiseXAException(XAException.XAER_PROTO);
            }
            isStarted = false;
            isEnded   = true;
            if (activeXid == null || !activeXid.equals(lxid)) {
                raiseXAException(XAException.XAER_NOTA);
            }
            if (flags != XAResource.TMSUCCESS &&
                flags != XAResource.TMFAIL) {
                // TMSUSPEND and TMMIGRATE cannot be supported
                raiseXAException(XAException.XAER_INVAL);
            }
            return;
        }
        //
        // Execute xa_end via MSDTC
        //
        isStarted = false;
        int args[] = new int[5];
        args[0] = XAResource.XA_OK;
        args[1] = XA_END;
        args[2] = connId;
        args[3] = 0;
        args[4] = flags;
        try {
            sendXaPacket(args, lxid.toBytes());
        } catch (SQLException e) {
            raiseXAException(e);
        }
        //
        // OK to remove this transaction from the global list now.
        //
        synchronized (txList) {
            txList.remove(this);
        }
        try {
            // Delist the connection.
            enlistConnection(null, false);
        } catch (SQLException e) {
            raiseXAException(e);
        }
        if (args[0] != XAResource.XA_OK) {
            raiseXAException(args[0]);
        }
    }

    /**
     * Invoke the xa_prepare routine on the SQL Server.
     *
     * @param xid   The XA Transaction ID object.
     * @return prepare status (XA_OK or XA_RDONLY) as an <code>int</code>.
     * @exception javax.transaction.xa.XAException
     *             if an error condition occurs
     */
    int xa_prepare(final Xid xid)
            throws XAException {

        //
        XidImpl lxid = new XidImpl(xid);

        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "xa_prepare", new Object[]{lxid});
        }

        if (isEmulated) {
            //
            // Emulate xa_prepare method
            // In emulation mode this is essentially a noop as we
            // are not able to offer true two phase commit.
            //
            if (!isEnded) {
                // Connection not ended
                raiseXAException(XAException.XAER_PROTO);
            }
            isEnded = false;
            isPrepared = true;
            if (activeXid == null || !activeXid.equals(lxid)) {
                raiseXAException(XAException.XAER_NOTA);
            }
            if (!isWarningIssued) {
                Logger.println("xa_prepare: Warning: Two phase commit not reliable in XA emulation mode.");
                isWarningIssued = true;
            }
            isPrepared = true;
            return XAResource.XA_OK;
        }
        //
        // End any open sessions for this XID
        //
        endTransaction(lxid);
        //
        // Execute xa_prepare via MSDTC
        //
        int args[] = new int[5];
        args[1] = XA_PREPARE;
        args[2] = connId;
        args[3] = 0;
        args[4] = XAResource.TMNOFLAGS;
        try {
            sendXaPacket(args, lxid.toBytes());
        } catch (SQLException e) {
            raiseXAException(e);
        }
        if (args[0] != XAResource.XA_OK && args[0] != XAResource.XA_RDONLY) {
            raiseXAException(args[0]);
        }
        isPrepared = true;
        return args[0];
    }

    /**
     * Invoke the xa_commit routine on the SQL Server.
     *
     * @param xid        The XA Transaction ID object.
     * @param onePhase   <code>true</code> if single phase commit required
     * @exception javax.transaction.xa.XAException
     *             if an error condition occurs
     */
     void xa_commit(final Xid xid, final boolean onePhase)
            throws XAException {

        XidImpl lxid = new XidImpl(xid);
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "xa_commit", new Object[]{lxid, new Boolean(onePhase)});
        }

        if (isEmulated) {
            //
            // Emulate xa_commit method
            //
            if (!isEnded && !isPrepared) {
                // Connection not ended or prepared
                raiseXAException(XAException.XAER_PROTO);
            }
            isPrepared = false;
            isEnded = false;
            if (activeXid == null || !activeXid.equals(lxid)) {
                raiseXAException(XAException.XAER_NOTA);
            }
            activeXid = null;
            try {
                enlistConnection(null, true);
            } catch (SQLException e) {
                raiseXAException(XAException.XAER_RMERR);
            }
            return;
        }
        //
        // end any open sessions for this XID
        //
        endTransaction(lxid);
        activeXid = null;
        //
        // Execute xa_commit via MSDTC
        //
        int args[] = new int[5];
        args[1] = XA_COMMIT;
        args[2] = connId;
        args[3] = 0;
        args[4] = (onePhase) ? XAResource.TMONEPHASE : XAResource.TMNOFLAGS;
        try {
            sendXaPacket(args, lxid.toBytes());
        } catch (SQLException e) {
            raiseXAException(e);
        }
    }

    /**
     * Invoke the xa_rollback routine on the SQL Server.
     *
     * @param xid   The XA Transaction ID object.
     * @exception javax.transaction.xa.XAException
     *             if an error condition occurs
     */
    void xa_rollback(final Xid xid)
            throws XAException {

        XidImpl lxid = new XidImpl(xid);
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "xa_rollback", new Object[]{lxid});
        }

        if (isEmulated) {
            //
            // Emulate xa_rollback method
            //
            if (!isEnded && !isPrepared) {
                // Connection not ended or prepared
                raiseXAException(XAException.XAER_PROTO);
            }
            isPrepared = false;
            isEnded = false;
            if (activeXid == null || !activeXid.equals(lxid)) {
                raiseXAException(XAException.XAER_NOTA);
            }
            activeXid = null;
            try {
                enlistConnection(null, false);
            } catch (SQLException e) {
                raiseXAException(XAException.XAER_RMERR);
            }
            return;
        }
        //
        // end any open sessions for this XID
        //
        endTransaction(lxid);
        activeXid = null;
        //
        // Execute xa_rollback via MSDTC
        //
        int args[] = new int[5];
        args[1] = XA_ROLLBACK;
        args[2] = connId;
        args[3] = 0;
        args[4] = XAResource.TMNOFLAGS;
        try {
            sendXaPacket(args, lxid.toBytes());
        } catch (SQLException e) {
            raiseXAException(e);
        }
    }

    /**
     * Invoke the xa_recover routine on the SQL Server.
     * <p/>
     * This version of xa_recover will return all XIDs on the first call.
     *
     * @param flags      XA Flags for start command
     * @return transactions to recover as a <code>Xid[]</code>
     * @exception javax.transaction.xa.XAException
     *             if an error condition occurs
     */
    Xid[] xa_recover(final int flags)
            throws XAException {

        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "xa_recover", new Object[]{Integer.toString(flags)});
        }
        if (isEmulated) {
            //
            // Emulate xa_recover method
            //
            // In a genuine recovery situation there is no state available 
            // all uncommited transactions will have been rolled back by the server.
            // It is possible that the container might call this method after prepare
            // but before commit/rollback without crashing and without closing 
            // the connection in which case we can return the current xid.
            if (flags != XAResource.TMSTARTRSCAN &&
                flags != XAResource.TMENDRSCAN &&
                flags != XAResource.TMNOFLAGS) {
                raiseXAException(XAException.XAER_INVAL);
            }
            if (isPrepared && activeXid != null) {
                Xid xids[] = new XidImpl[1];
                xids[0] = activeXid;
                return xids;
            }
            return new XidImpl[0];
        }
        //
        // Execute xa_recover via MSDTC
        //
        int args[] = new int[5];
        args[1] = XA_RECOVER;
        args[2] = connId;
        args[3] = 0;
        args[4] = XAResource.TMNOFLAGS;
        Xid[] list = null;

        if (flags != XAResource.TMSTARTRSCAN) {
            return new XidImpl[0];
        }

        try {
            byte[][] buffer = sendXaPacket(args, null);
            if (args[0] >= 0 && buffer != null) {
                int n = buffer.length;
                list = new XidImpl[n];
                for (int i = 0; i < n; i++) {
                    list[i] = new XidImpl(buffer[i], 0);
                }
            }
        } catch (SQLException e) {
            raiseXAException(e);
        }
        if (args[0] < 0) {
            raiseXAException(args[0]);
        }
        if (list == null) {
            list = new XidImpl[0];
        }
        return list;
    }

    /**
     * Invoke the xa_forget routine on the SQL Server.
     *
     * @param xid   The XA Transaction ID object.
     * @exception javax.transaction.xa.XAException
     *             if an error condition occurs
     */
    void xa_forget(final Xid xid)
            throws XAException {

        XidImpl lxid = new XidImpl(xid);
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "xa_forget", new Object[]{lxid});
        }
        if (isEmulated) {
            //
            // Emulate xa_forget method
            //
            if (activeXid == null || !activeXid.equals(lxid)) {
                raiseXAException(XAException.XAER_NOTA);
            }
            if (!isPrepared && !isEnded) {
               // Connection not ended or prepared
               raiseXAException(XAException.XAER_PROTO);
            }
            isEnded = false;
            isPrepared = false;
            activeXid = null;
            try {
                enlistConnection(null, false);
            } catch (SQLException e) {
                raiseXAException(XAException.XAER_RMERR);
            }
            return;
        }
        //
        // end any open sessions for this XID
        //
        endTransaction(lxid);
        activeXid = null;
        //
        // Execute xa_forget via MSDTC
        //
        int args[] = new int[5];
        args[1] = XA_FORGET;
        args[2] = connId;
        args[3] = 0;
        args[4] = XAResource.TMNOFLAGS;
        try {
            sendXaPacket(args, lxid.toBytes());
        } catch (SQLException e) {
            raiseXAException(e);
        }
        if (args[0] != XAResource.XA_OK) {
            raiseXAException(args[0]);
        }
    }

    /**
     * Construct and throw an <code>XAException</code> with an explanatory message derived from the
     * <code>SQLException</code> and the XA error code set to <code>XAER_RMFAIL</code>.
     *
     * @param sqle The SQLException.
     * @exception javax.transaction.xa.XAException
     *             exception derived from the code>SQLException</code>
     */
    static void raiseXAException(final SQLException sqle)
            throws XAException {
        XAException e = new XAException(sqle.getMessage());
        e.errorCode = XAException.XAER_RMFAIL;
        Logger.logException(e);
        throw e;
    }

    /**
     * Construct and throw an <code>XAException</code> with an explanatory message and the XA error code set.
     *
     * @param errorCode the XA Error code
     * @exception javax.transaction.xa.XAException
     *             the constructed exception
     */
    static void raiseXAException(final int errorCode)
            throws XAException {
        String err = "xaerunknown";
        switch (errorCode) {
            case XAException.XA_RBROLLBACK:
                err = "xarbrollback";
                break;
            case XAException.XA_RBCOMMFAIL:
                err = "xarbcommfail";
                break;
            case XAException.XA_RBDEADLOCK:
                err = "xarbdeadlock";
                break;
            case XAException.XA_RBINTEGRITY:
                err = "xarbintegrity";
                break;
            case XAException.XA_RBOTHER:
                err = "xarbother";
                break;
            case XAException.XA_RBPROTO:
                err = "xarbproto";
                break;
            case XAException.XA_RBTIMEOUT:
                err = "xarbtimeout";
                break;
            case XAException.XA_RBTRANSIENT:
                err = "xarbtransient";
                break;
            case XAException.XA_NOMIGRATE:
                err = "xanomigrate";
                break;
            case XAException.XA_HEURHAZ:
                err = "xaheurhaz";
                break;
            case XAException.XA_HEURCOM:
                err = "xaheurcom";
                break;
            case XAException.XA_HEURRB:
                err = "xaheurrb";
                break;
            case XAException.XA_HEURMIX:
                err = "xaheurmix";
                break;
            case XAException.XA_RETRY:
                err = "xaretry";
                break;
            case XAException.XA_RDONLY:
                err = "xardonly";
                break;
            case XAException.XAER_ASYNC:
                err = "xaerasync";
                break;
            case XAException.XAER_NOTA:
                err = "xaernota";
                break;
            case XAException.XAER_INVAL:
                err = "xaerinval";
                break;
            case XAException.XAER_PROTO:
                err = "xaerproto";
                break;
            case XAException.XAER_RMERR:
                err = "xaerrmerr";
                break;
            case XAException.XAER_RMFAIL:
                err = "xaerrmfail";
                break;
            case XAException.XAER_DUPID:
                err = "xaerdupid";
                break;
            case XAException.XAER_OUTSIDE:
                err = "xaeroutside";
                break;
        }
        XAException e = new XAException(Messages.get("error.xaexception." + err));
        e.errorCode = errorCode;
        Logger.logException(e);
        throw e;
    }
    
    /**
     * Check if two XAResource instances reference the same Resource Manager.
     *<p/>This routine has two uses:
     *<ol>
     *<li>Determine if we can join two sessions into the same transaction</li>
     *<li>Ensure that we only call xa_recover once per resource manager.</li>
     *</ol>
     * @param other the second XAResource to compare.
     * @return <code>boolean</code> if the two XAResource instances reference 
     * the same resource manager.
     */
    boolean isSameRM(final XAResource other) {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, "isSameRM", new Object[]{other});
        }
        //
        // Can only be same RM if both jTDS XA Resources
        //
        if (!(other instanceof XAResourceImpl)) {
            Logger.printTrace("isSameRM returns false");
            return false;
        }
        ConnectionImpl con = ((XAResourceImpl)other).getConnection();
        //
        // If in emulation mode we always return false as TMJOIN is
        // not supported.
        //
        if (isEmulated || con.isEmulated) {
            Logger.printTrace("isSameRM returns false");
            return false;
        }
        //
        // Can only be the same RM if the same server instance.
        // Note we need port as well as host name as there may be
        // more than one SQL server instance on the host. 
        // Also note we should really try and resolve the host address. 
        // For example, localhost and 127.0.0.1 are the same. 
        // For now we rely on the user supplying the same host name.
        // Finally we need to see if both connections currently point to the 
        // same database as SQL server cannot join separate sessions across
        // databases they must be different branches enrolled in the same
        // global transaction.
        //
        try {
            if (socket.getHost().equals(con.socket.getHost())
                && socket.getPort() == con.socket.getPort()
                && getCatalog().equals(con.getCatalog())) {
                Logger.printTrace("isSameRM returns true");
                return true;
            }
        } catch (SQLException e) {
            // Ignore any exception
        }
        Logger.printTrace("isSameRM returns false");
        return false;
    }
    
    // ------------- Private methods  ---------

    /**
     * Some servers (Sun Application server 8.1 and Resin 3.0 for example) do 
     * not call xa_end on all sessions joined into one transaction before 
     * calling rollback. This behaviour can leave SQL Server and the MSDTC 
     * in an inconsistant state. To fix the problem we maintain a global list 
     * of active XID's and call xa_end on any that are still active when 
     * xa_rollback, xa_prepare, xa_commit or xa_forget is called. 
     * 
     * @param xid the XID of the transaction being rolled back or committed.
     */
    private void endTransaction(final Xid xid) {
        ArrayList<ConnectionImpl> list = null;
        //
        // Copy the revelant items from the global list while we have exclusive access
        //
        synchronized (txList) {
            for (Iterator<ConnectionImpl> i = txList.iterator(); i.hasNext(); ) {
                ConnectionImpl entry = i.next();
                if (entry.activeXid.equals(xid)) {
                    if (list == null) {
                        // Lazy allocation of array as not normally needed
                        list = new ArrayList<ConnectionImpl>();
                    }
                    list.add(entry);
                }
            }
        }
        if (list != null) {
            //
            // Now process the items (xa_end will actually remove them from 
            // the global list).
            //
            for (Iterator<ConnectionImpl> i = list.iterator(); i.hasNext(); ) {
                try {
                    ConnectionImpl entry = i.next();
                    Logger.println("Forcibly ending a transaction");
                    entry.xa_end(entry.activeXid, XAResource.TMSUCCESS);
                 } catch (XAException e) {
                     Logger.logException(e);
                 }
             }
        }
    }    

    /**
     * jTDS implementation of the <code>Xid</code> interface.
     *
     * @version $Id: ConnectionImpl.java,v 1.9 2009-11-14 13:49:43 ickzon Exp $
     */
    private static class XidImpl implements Xid {
        /** The size of an XID in bytes. */
        public static final int XID_SIZE = 140;

        /** The global transaction ID. */
        private final byte gtran[];
        /** The branch qualifier ID. */
        private final byte bqual[];
        /** The format ID. */
        private final int fmtId;
        /** Precalculated hash value. */
        private int hash;
        /** True if hash has been calculated. */
        private boolean isHashed; 

        /**
         * Construct an XID using an offset into a byte buffer.
         *
         * @param buf the byte buffer
         * @param pos the offset
         */
        XidImpl(final byte[] buf, final int pos) {
            fmtId = (buf[pos] & 0xFF) |
                    ((buf[pos+1] & 0xFF) << 8) |
                    ((buf[pos+2] & 0xFF) << 16) |
                    ((buf[pos+3] & 0xFF) << 24);
            int t = buf[pos+4];
            int b = buf[pos+8];
            gtran = new byte[t];
            bqual = new byte[b];
            System.arraycopy(buf, 12+pos, gtran, 0, t);
            System.arraycopy(buf, 12+t+pos, bqual, 0, b);
        }

        /**
         * Construct an XID using two byte arrays.
         *
         * @param global the global transaction id
         * @param branch the transaction branch
         */
        XidImpl(final byte[] global, final byte[] branch) {
            fmtId = 0;
            gtran = global;
            bqual = branch;
        }

        /**
         * Construct an XID as a clone of another XID.
         */
        XidImpl(final Xid xid) throws XAException {
            if (xid == null) {
                XAException e = new XAException(Messages.get("error.xasupport.nullxid"));
                e.errorCode = XAException.XAER_RMFAIL;
                Logger.logException(e);
                throw e;
            }
            fmtId = xid.getFormatId();
            gtran = new byte[xid.getGlobalTransactionId().length];
            System.arraycopy(xid.getGlobalTransactionId(), 0, gtran, 0, gtran.length);
            bqual = new byte[xid.getBranchQualifier().length];
            System.arraycopy(xid.getBranchQualifier(), 0, bqual, 0, bqual.length);
        }

        /**
         * Get the hash code for this object.
         *
         * @return the hash value of this object as a <code>int</code>
         */
        public int hashCode() {
            if (!isHashed) {
                String x = Integer.toString(fmtId)+ new String(gtran) + new String(bqual);
                hash = x.hashCode();
                isHashed = true;
            }
            return hash;
        }

        /**
         * Test for equality.
         *
         * @param obj the object to test for equality with this
         * @return <code>boolean</code> true if the parameter equals this
         */
        public boolean equals(Object obj) {
            if (obj == this)
                return true;

            if (obj instanceof XidImpl) {
                XidImpl xobj = (XidImpl)obj;

                if (gtran.length + bqual.length == xobj.gtran.length + xobj.bqual.length
                        && fmtId == xobj.fmtId 
                        && Arrays.equals(gtran, xobj.gtran)
                        && Arrays.equals(bqual, xobj.bqual)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Format an XA transaction ID into a 140 byte (maximum) array.
         *
         * @return the formatted ID as a <code>byte[]</code>
         */
        byte[] toBytes() {
            byte[] buffer = new byte[140];
            int fmt = getFormatId();
            buffer[0] = (byte) fmt;
            buffer[1] = (byte) (fmt >> 8);
            buffer[2] = (byte) (fmt >> 16);
            buffer[3] = (byte) (fmt >> 24);
            buffer[4] = (byte) getGlobalTransactionId().length;
            buffer[8] = (byte) getBranchQualifier().length;
            System.arraycopy(getGlobalTransactionId(), 0, buffer, 12, buffer[4]);
            System.arraycopy(getBranchQualifier(), 0, buffer, 12 + buffer[4], buffer[8]);
            return buffer;
        }
        
        //
        // ------------------- javax.transaction.xa.Xid interface methods -------------------
        //

        public int getFormatId() {
            return fmtId;
        }

        public byte[] getBranchQualifier() {
            return bqual;
        }

        public byte[] getGlobalTransactionId() {
            return gtran;
        }

        public String toString() {
            StringBuffer txt = new StringBuffer(256);
            txt.append("XID[Format=").append(fmtId).append(", Global=0x");
            txt.append(Support.toHex(gtran)).append(", Branch=0x");
            txt.append(Support.toHex(bqual)).append(']');
            return txt.toString();
        }
    }

    @Override
    public Array createArrayOf(String typeName, Object[] elements)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Blob createBlob() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Clob createClob() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public NClob createNClob() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public SQLXML createSQLXML() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Struct createStruct(String typeName, Object[] attributes)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Properties getClientInfo() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public String getClientInfo(String name) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public boolean isValid(int timeout) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setClientInfo(Properties properties)
            throws SQLClientInfoException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setClientInfo(String name, String value)
            throws SQLClientInfoException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    //// JDBC4.1 demarcation, do NOT put any JDBC3/4.0 code below this line ////

    @Override
    public void setSchema(String schema) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public String getSchema() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void abort(java.util.concurrent.Executor executor) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setNetworkTimeout(java.util.concurrent.Executor executor, int milliseconds) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public int getNetworkTimeout() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }
}