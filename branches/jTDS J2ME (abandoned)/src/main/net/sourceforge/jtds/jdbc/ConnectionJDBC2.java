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

import java.lang.ref.WeakReference;
import java.sql.CallableStatement;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.Statement;
import java.sql.ResultSet;
import java.net.UnknownHostException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Properties;

import net.sourceforge.jtds.util.*;

/**
 * jTDS implementation of the java.sql.Connection interface.
 * <p>
 * Implementation notes:
 * <ol>
 * <li>Environment setting code carried over from old jTDS otherwise
 *     generally a new implementation of Connection.
 * <li>Connection properties and SQLException text messages are loaded from
 *     a properties file.
 * <li>Character set choices are also loaded from a resource file and the original
 *     Encoder class has gone.
 * <li>Prepared SQL statements are converted to procedures in the prepareSQL method.
 * <li>Use of Stored procedures is optional and controlled via connection property.
 * <li>This Connection object maintains a table of weak references to associated
 *     statements. This allows the connection object to control the statements (for
 *     example to close them) but without preventing them being garbage collected in
 *     a pooled environment.
 * </ol>
 *
 * @author Mike Hutchinson
 * @author Alin Sinpalean
 * @version $Id: ConnectionJDBC2.java,v 1.76.2.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public abstract class ConnectionJDBC2 implements java.sql.Connection {
    /**
     * SQL Server initial connection string. Also contains a <code>SELECT
     * @@MAX_PRECISION</code> query to retrieve the maximum precision for
     * DECIMAL/NUMERIC data. */
    private String SQL_SERVER_INITIAL_SQL = "SELECT @@MAX_PRECISION\r\n" +
                                            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED\r\n" +
                                            "SET IMPLICIT_TRANSACTIONS OFF\r\n" +
                                            "SET QUOTED_IDENTIFIER ON\r\n"+
                                            "SET TEXTSIZE 2147483647";
    /*
     * Conection attributes
     */

    /** The server host name. */
    private String serverName;
    /** The server port number. */
    private int portNumber;
    /** The requested database name. */
    private String databaseName;
    /** The current database name. */
    private String currentDatabase;
    /** The database user ID. */
    private String user;
    /** The user password. */
    private String password;
    /** The server character set. */
    private String serverCharset;
    /** The application name. */
    private String appName;
    /** The program name. */
    private String progName;
    /** Workstation ID. */
    private String wsid;
    /** The server message language. */
    private String language;
    /** The client MAC Address. */
    private String macAddress;
    /** The server protocol version. */
    private int tdsVersion;
    /** The network TCP/IP socket. */
    private SharedSocket socket;
    /** The cored TDS protocol object. */
    private TdsCore baseTds;
    /** The initial network packet size. */
    private int netPacketSize = TdsCore.MIN_PKT_SIZE;
    /** SQL Server 2000 collation. */
    private byte collation[];
    /** True if user specifies an explicit charset. */
    private boolean charsetSpecified = false;
    /** The database product name eg SQL SERVER. */
    private String databaseProductName;
    /** The product version eg 11.92. */
    private String databaseProductVersion;
    /** The major version number eg 11. */
    private int databaseMajorVersion;
    /** The minor version number eg 92. */
    private int databaseMinorVersion;
    /** True if this connection is closed. */
    private boolean closed = false;
    /** True if this connection is read only. */
    private boolean readOnly = false;
    /** List of statements associated with this connection. */
    private ArrayList statements;
    /** Default transaction isolation level. */
    private int transactionIsolation = java.sql.Connection.TRANSACTION_READ_COMMITTED;
    /** Default auto commit state. */
    private boolean autoCommit = true;
    /** Diagnostc messages for this connection. */
    private SQLDiagnostic messages;
    /** Connection's current rowcount limit. */
    private int rowCount = 0;
    /** Connection's current maximum field size limit. */
    private int textSize = 0;
    /** Maximum decimal precision. */
    private int maxPrecision = 38; // Sybase default
    /** Java charset for encoding. */
    private CharsetInfo charsetInfo;
    /** Send parameters as unicode. */
    private boolean useUnicode = true;
    /** Only return the last update count. */
    private boolean lastUpdateCount = false;
    /** TCP_NODELAY */
    private boolean tcpNoDelay = true;
    /** Login timeout value in seconds or 0. */
    private int loginTimeout = 0;
    /** Mutual exclusion lock to control access to connection. */
    private Semaphore mutex = new Semaphore(1);
    /** SSL setting. */
    private String ssl;
    /** The maximum size of a batch. */
    private int batchSize;

    /**
     * Default constructor.
     * <p/>
     * Used for testing.
     */
    protected ConnectionJDBC2() {
    }

    /**
     * Create a new database connection.
     *
     * @param info The additional connection properties.
     * @throws SQLException
     */
    ConnectionJDBC2(Properties info)
            throws SQLException {
        this.statements = new ArrayList();
        //
        // Extract properties into instance variables
        //
        unpackProperties(info);
        this.messages = new SQLDiagnostic();

        try {
            Object timer = null;
            if (loginTimeout > 0) {
                // Start a login timer
                timer = TimerThread.getInstance().setTimer(loginTimeout * 1000,
                        new TimerThread.TimerListener() {
                            public void timerExpired() {
                                if (socket != null) {
                                    socket.forceClose();
                                }
                            }
                        });
            }

            // Use plain TCP/IP socket
            socket = new SharedSocket(serverName, portNumber, tdsVersion,
                    tcpNoDelay);

            if (timer != null && TimerThread.getInstance().hasExpired(timer)) {
                // If the timer has expired during the connection phase, throw
                // an exception
                throw new IOException("Login timed out");
            }

            if ( charsetSpecified ) {
                loadCharset(serverCharset);
            } else {
                // Need a default charset to process login packets for TDS 4.2/5.0
                // Will discover the actual serverCharset later
                loadCharset("iso_1");
                serverCharset = ""; // But don't send charset name to server!
            }

            //
            // Create TDS protocol object
            //
            baseTds = new TdsCore(this, messages);

            //
            // Negotiate SSL connection if required
            //
            if (tdsVersion >= Driver.TDS80) {
                baseTds.negotiateSSL(ssl);
            }

            //
            // Now try and login
            //
            baseTds.login(serverName,
                          databaseName,
                          user,
                          password,
                          serverCharset,
                          appName,
                          progName,
                          wsid,
                          language,
                          macAddress);

            if (timer != null) {
                // Cancel loginTimer
                TimerThread.getInstance().cancelTimer(timer);
            }

            // Update the tdsVersion with the value in baseTds. baseTds sets
            // the TDS version for the socket and there are no other objects
            // with cached TDS versions at this point.
            tdsVersion = baseTds.getTdsVersion();
        } catch (UnknownHostException e) {
            throw Support.linkException(
                    new SQLException(Messages.get("error.connection.badhost",
                            e.getMessage()), "08S03"), e);
        } catch (IOException e) {
            if (loginTimeout > 0 && e.getMessage().indexOf("timed out") >= 0) {
                throw new SQLException(
                        Messages.get("error.connection.timeout"), "HYT01");
            }
            throw Support.linkException(
                    new SQLException(Messages.get("error.connection.ioerror",
                            e.getMessage()), "08S01"), e);
        } catch (SQLException e) {
            if (loginTimeout > 0 && e.getMessage().indexOf("socket closed") >= 0) {
                throw new SQLException(
                        Messages.get("error.connection.timeout"), "HYT01");
            }

            throw e;
        }

        // Initial database settings.
        // Sets: auto commit mode  = true
        //       transaction isolation = read committed.
        // Also discover the maximum decimal precision (28 for MS SQL pre
        // 2000, configurable to 28/38 for 2000 and later)
        Statement stmt = this.createStatement();
        ResultSet rs = stmt.executeQuery(SQL_SERVER_INITIAL_SQL);

        if (rs.next()) {
            maxPrecision = rs.getByte(1);
        }

        rs.close();
        stmt.close();
    }

    /**
     * Retrive the shared socket.
     *
     * @return The <code>SharedSocket</code> object.
     */
    SharedSocket getSocket() {
        return this.socket;
    }

    /**
     * Retrieve the TDS protocol version.
     *
     * @return The TDS version as an <code>int</code>.
     */
    int getTdsVersion() {
        return this.tdsVersion;
    }

    /**
     * Sets the network packet size.
     *
     * @param size the new packet size
     */
    void setNetPacketSize(int size) {
        this.netPacketSize = size;
    }

    /**
     * Retrieves the network packet size.
     *
     * @return the packet size as an <code>int</code>
     */
    int getNetPacketSize() {
        return this.netPacketSize;
    }

    /**
     * Retrieves the current row count on this connection.
     *
     * @return the row count as an <code>int</code>
     */
    int getRowCount() {
        return this.rowCount;
    }

    /**
     * Sets the current row count on this connection.
     *
     * @param count the new row count
     */
    void setRowCount(int count) {
        rowCount = count;
    }

    /**
     * Retrieves the current maximum textsize on this connection.
     *
     * @return the maximum textsize as an <code>int</code>
     */
    public int getTextSize() {
        return textSize;
    }

    /**
     * Sets the current maximum textsize on this connection.
     *
     * @param textSize the new maximum textsize
     */
    public void setTextSize(int textSize) {
        this.textSize = textSize;
    }

    /**
     * Retrieves the status of the lastUpdateCount flag.
     *
     * @return the lastUpdateCount flag as a <code>boolean</code>
     */
    boolean isLastUpdateCount() {
        return this.lastUpdateCount;
    }

    /**
     * Retrieves the maximum decimal precision.
     *
     * @return the precision as an <code>int</code>
     */
    int getMaxPrecision() {
        return this.maxPrecision;
    }

    /**
     * Retrieves the batch size to be used internally.
     *
     * @return the batch size as an <code>int</code>
     */
    int getBatchSize() {
        return this.batchSize;
    }

    /**
     * Transfers the properties to the local instance variables.
     *
     * @param info The connection properties Object.
     * @throws SQLException If an invalid property value is found.
     */
    protected void unpackProperties(Properties info)
            throws SQLException {

        serverName = info.getProperty(Messages.get(Driver.SERVERNAME));
        portNumber = parseIntegerProperty(info, Driver.PORTNUMBER);
        databaseName = info.getProperty(Messages.get(Driver.DATABASENAME));
        user = info.getProperty(Messages.get(Driver.USER));
        password = info.getProperty(Messages.get(Driver.PASSWORD));
        macAddress = info.getProperty(Messages.get(Driver.MACADDRESS));
        appName = info.getProperty(Messages.get(Driver.APPNAME));
        progName = info.getProperty(Messages.get(Driver.PROGNAME));
        wsid = info.getProperty(Messages.get(Driver.WSID));
        serverCharset = info.getProperty(Messages.get(Driver.CHARSET));
        language = info.getProperty(Messages.get(Driver.LANGUAGE));
        lastUpdateCount = "true".equalsIgnoreCase(
                info.getProperty(Messages.get(Driver.LASTUPDATECOUNT)));
        useUnicode = "true".equalsIgnoreCase(
                info.getProperty(Messages.get(Driver.SENDSTRINGPARAMETERSASUNICODE)));
        tcpNoDelay = "true".equalsIgnoreCase(
                info.getProperty(Messages.get(Driver.TCPNODELAY)));
        charsetSpecified = serverCharset.length() > 0;

        Integer parsedTdsVersion =
                DefaultProperties.getTdsVersion(info.getProperty(Messages.get(Driver.TDS)));
        if (parsedTdsVersion == null) {
            throw new SQLException(Messages.get("error.connection.badprop",
                    Messages.get(Driver.TDS)), "08001");
        }
        tdsVersion = parsedTdsVersion.intValue();

        loginTimeout = parseIntegerProperty(info, Driver.LOGINTIMEOUT);

        ssl = info.getProperty(Messages.get(Driver.SSL));

        batchSize = parseIntegerProperty(info, Driver.BATCHSIZE);
        if (batchSize < 0) {
            throw new SQLException(Messages.get("error.connection.badprop",
                    Messages.get(Driver.BATCHSIZE)), "08001");
        }
    }

    /**
     * Parse a string property value into an integer value.
     *
     * @param info The connection properties object.
     * @param key The message key used to retrieve the property name.
     * @return The integer value of the string property value.
     * @throws SQLException If the property value can't be parsed.
     */
    private int parseIntegerProperty(final Properties info, final String key)
            throws SQLException {

        final String propertyName = Messages.get(key);
        try {
            return Integer.parseInt(info.getProperty(propertyName));
        } catch (NumberFormatException e) {
            throw new SQLException(
                    Messages.get("error.connection.badprop", propertyName), "08001");
        }
    }

    /**
     * Retrieve the Java charset to use for encoding.
     *
     * @return the Charset name as a <code>String</code>
     */
    protected String getCharset() {
        return charsetInfo.getCharset();
    }

    /**
     * Retrieve the <code>CharsetInfo</code> instance used by this connection.
     *
     * @return the default <code>CharsetInfo</code> for this connection
     */
    protected CharsetInfo getCharsetInfo() {
        return charsetInfo;
    }

    /**
     * Retrieve the sendParametersAsUnicode flag.
     *
     * @return <code>boolean</code> true if parameters should be sent as unicode.
     */
    protected boolean isUseUnicode() {
        return this.useUnicode;
    }

    /**
     * Called by the protocol to change the current character set.
     *
     * @param charset the server character set name
     */
    protected void setServerCharset(final String charset) throws SQLException {
        // If the user specified a charset, ignore environment changes
        if (charsetSpecified) {
            Logger.println("Server charset " + charset +
                    ". Ignoring as user requested " + serverCharset + '.');
            return;
        }

        if (!charset.equals(serverCharset)) {
            loadCharset(charset);

            if (Logger.isActive()) {
                Logger.println("Set charset to " + serverCharset + '/'
                        + charsetInfo);
            }
        }
    }

    /**
     * Load the Java charset to match the server character set.
     *
     * @param charset the server character set
     */
    private void loadCharset(String charset) throws SQLException {
        // Do not default to any charset; if the charset is not found we want
        // to know about it
        CharsetInfo tmp = CharsetInfo.getCharset(charset);

        if (tmp == null) {
            throw new SQLException(
                    Messages.get("error.charset.nomapping", charset), "2C000");
        }

        loadCharset(tmp, charset);
        serverCharset = charset;
    }

    /**
     * Load the Java charset to match the server character set.
     *
     * @param ci the <code>CharsetInfo</code> to load
     */
    private void loadCharset(CharsetInfo ci, String ref) throws SQLException {
        try {
            "This is a test".getBytes(ci.getCharset());

            charsetInfo = ci;
        } catch (UnsupportedEncodingException ex) {
            throw new SQLException(
                    Messages.get("error.charset.invalid", ref,
                            ci.getCharset()),
                    "2C000");
        }

        socket.setCharsetInfo(charsetInfo);
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
     *
     * @param collation The new collation.
     */
    void setCollation(byte[] collation) throws SQLException {
        String strCollation = "0x" + Support.toHex(collation);
        // If the user specified a charset, ignore environment changes
        if (charsetSpecified) {
            Logger.println("Server collation " + strCollation +
                    ". Ignoring as user requested " + serverCharset + '.');
            return;
        }

        CharsetInfo tmp = CharsetInfo.getCharset(collation);

        loadCharset(tmp, strCollation);
        this.collation = collation;

        if (Logger.isActive()) {
            Logger.println("Set collation to " + strCollation + '/'
                    + charsetInfo);
        }
    }

    /**
     * Retrieve the SQL Server 2000 default collation.
     *
     * @return The collation as a <code>byte[5]</code>.
     */
    byte[] getCollation() {
        return this.collation;
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
     *
     * @param newDb The new database selected on the server.
     * @param oldDb The old database as known by the server.
     * @throws SQLException
     */
    protected void setDatabase(final String newDb, final String oldDb)
            throws SQLException {
        if (currentDatabase != null && !oldDb.equalsIgnoreCase(currentDatabase)) {
            throw new SQLException(Messages.get("error.connection.dbmismatch",
                                                      oldDb, databaseName),
                                   "HY096");
        }

        currentDatabase = newDb;

        if (Logger.isActive()) {
            Logger.println("Changed database from " + oldDb + " to " + newDb);
        }
    }

    /**
     * Update the connection instance with information about the server.
     *
     * @param databaseProductName The server name eg SQL Server.
     * @param databaseMajorVersion The major version eg 11
     * @param databaseMinorVersion The minor version eg 92
     * @param buildNumber The server build number.
     */
    protected void setDBServerInfo(String databaseProductName,
                                   int databaseMajorVersion,
                                   int databaseMinorVersion,
                                   int buildNumber) {
        this.databaseProductName = databaseProductName;
        this.databaseMajorVersion = databaseMajorVersion;
        this.databaseMinorVersion = databaseMinorVersion;

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

        this.databaseProductVersion = buf.toString();
    }

    /**
     * Remove a statement object from the list maintained by the connection and
     * clean up the statement cache if necessary.
     * <p>
     * Synchronized because it accesses the statement list, the statement cache
     * and the <code>baseTds</code>.
     *
     * @param statement the statement to remove
     */
    synchronized void removeStatement(JtdsStatement statement)
            throws SQLException {
        // Remove the JtdsStatement
        for (int i = 0; i < statements.size(); i++) {
            WeakReference wr = (WeakReference) statements.get(i);

            if (wr != null) {
                Statement stmt = (Statement) wr.get();

                if (stmt != null && stmt == statement) {
                    statements.set(i, null);
                }
            }
        }
    }

    /**
     * Add a statement object to the list maintained by the connection.
     * <p>WeakReferences are used so that statements can still be
     * closed and garbage collected even if not explicitly closed
     * by the connection.
     *
     * @param statement The statement to add.
     */
    void addStatement(JtdsStatement statement) {
        synchronized (statements) {
            for (int i = 0; i < statements.size(); i++) {
                WeakReference wr = (WeakReference) statements.get(i);

                if (wr == null) {
                    statements.set(i, new WeakReference(statement));
                    return;
                }
            }

            statements.add(new WeakReference(statement));
        }
    }

    /**
     * Check that this connection is still open.
     *
     * @throws SQLException if connection closed.
     */
    void checkOpen() throws SQLException {
        if (closed) {
            throw new SQLException(
                                  Messages.get("error.generic.closed", "Connection"), "HY010");
        }
    }

    /**
     * Retrieves the DBMS major version.
     *
     * @return The version as an <code>int</code>.
     */
    int getDatabaseMajorVersion() {
        return this.databaseMajorVersion;
    }

    /**
     * Retrieves the DBMS minor version.
     *
     * @return The version as an <code>int</code>.
     */
    int getDatabaseMinorVersion() {
        return this.databaseMinorVersion;
    }

    /**
     * Retrieves the DBMS product name.
     *
     * @return The name as a <code>String</code>.
     */
    String getDatabaseProductName() {
        return this.databaseProductName;
    }

    /**
     * Retrieves the DBMS product version.
     *
     * @return The version as a <code>String</code>.
     */
    String getDatabaseProductVersion() {
        return this.databaseProductVersion;
    }

    /**
     * Used to force the closed status on the statement if an
     * IO error has occurred.
     */
    void setClosed() {
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
     * Retrieve the connection mutex.
     *
     * @return the mutex object as a <code>Semaphore</code>
     */
    Semaphore getMutex() {
        return this.mutex;
    }

    //
    // ------------------- java.sql.Connection interface methods -------------------
    //

    public int getHoldability() throws SQLException {
        checkOpen();

        return JtdsResultSet.HOLD_CURSORS_OVER_COMMIT;
    }

    public int getTransactionIsolation() throws SQLException {
        checkOpen();

        return this.transactionIsolation;
    }

    public void clearWarnings() throws SQLException {
        checkOpen();
        messages.clearWarnings();
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
            try {
                //
                // Close any open statements
                //
                ArrayList tmpList;

                synchronized (statements) {
                    tmpList = new ArrayList(statements);
                }

                for (int i = 0; i < tmpList.size(); i++) {
                    WeakReference wr = (WeakReference)tmpList.get(i);

                    if (wr != null) {
                        Statement stmt = (Statement)wr.get();
                        if (stmt != null) {
                            stmt.close();
                        }
                    }
                }

                //
                // Tell the server the session is ending
                //
                baseTds.closeConnection();
                //
                // Close network connection
                //
                baseTds.close();
                socket.close();
            } catch (IOException e) {
                // Ignore
            } finally {
                closed = true;
            }
        }
    }

    synchronized public void commit() throws SQLException {
        checkOpen();

        if (getAutoCommit()) {
            throw new SQLException(
                    Messages.get("error.connection.autocommit"), "25000");
        }

        baseTds.submitSQL("IF @@TRANCOUNT > 0 COMMIT TRAN");
        clearSavepoints();
    }

    synchronized public void rollback() throws SQLException {
        checkOpen();

        if (getAutoCommit()) {
            throw new SQLException(
                    Messages.get("error.connection.autocommit"), "25000");
        }

        baseTds.submitSQL("IF @@TRANCOUNT > 0 ROLLBACK TRAN");

        clearSavepoints();
    }

    public boolean getAutoCommit() throws SQLException {
        checkOpen();

        return this.autoCommit;
    }

    public boolean isClosed() throws SQLException {
        return closed;
    }

    public boolean isReadOnly() throws SQLException {
        checkOpen();

        return this.readOnly;
    }

    public void setHoldability(int holdability) throws SQLException {
        checkOpen();
        switch (holdability) {
            case JtdsResultSet.HOLD_CURSORS_OVER_COMMIT:
                break;
            case JtdsResultSet.CLOSE_CURSORS_AT_COMMIT:
                throw new SQLException(Messages.get("error.generic.optvalue",
                                                          "CLOSE_CURSORS_AT_COMMIT",
                                                          "setHoldability"), "HY092");
            default:
                throw new SQLException(Messages.get("error.generic.badoption",
                                                          Integer.toString(holdability),
                                                          "setHoldability"), "HY092");
        }
    }

    synchronized public void setTransactionIsolation(int level) throws SQLException {
        checkOpen();

        if (transactionIsolation == level) {
            // No need to submit a request
            return;
        }

        String sql = "SET TRANSACTION ISOLATION LEVEL ";

        switch (level) {
            case java.sql.Connection.TRANSACTION_READ_UNCOMMITTED:
                sql += "READ UNCOMMITTED";
                break;
            case java.sql.Connection.TRANSACTION_READ_COMMITTED:
                sql += "READ COMMITTED";
                break;
            case java.sql.Connection.TRANSACTION_REPEATABLE_READ:
                sql += "REPEATABLE READ";
                break;
            case java.sql.Connection.TRANSACTION_SERIALIZABLE:
                sql += "SERIALIZABLE";
                break;
            case java.sql.Connection.TRANSACTION_NONE:
                throw new SQLException(Messages.get("error.generic.optvalue",
                                                          "TRANSACTION_NONE",
                                                          "setTransactionIsolation"), "HY024");
            default:
                throw new SQLException(Messages.get("error.generic.badoption",
                                                          Integer.toString(level),
                                                          "setTransactionIsolation"), "HY092");
        }

        transactionIsolation = level;
        baseTds.submitSQL(sql);
    }

    synchronized public void setAutoCommit(boolean autoCommit) throws SQLException {
        checkOpen();

        if (!this.autoCommit) {
            // If we're in manual commit mode the spec requires that we commit
            // the transaction when setAutoCommit() is called
            commit();
        }

        if (this.autoCommit == autoCommit) {
            // If we don't need to change the current auto commit mode, don't
            // submit a request
            return;
        }

        String sql;

        if (autoCommit) {
            sql = "SET IMPLICIT_TRANSACTIONS OFF";
        } else {
            sql = "SET IMPLICIT_TRANSACTIONS ON";
        }

        baseTds.submitSQL(sql);
        this.autoCommit = autoCommit;
    }

    public void setReadOnly(boolean readOnly) throws SQLException {
        checkOpen();
        this.readOnly = readOnly;
    }

    public String getCatalog() throws SQLException {
        checkOpen();

        return this.currentDatabase;
    }

    synchronized public void setCatalog(String catalog) throws SQLException {
        checkOpen();

        if (currentDatabase != null && currentDatabase.equals(catalog)) {
            return;
        }

        if (catalog.length() > 32 || catalog.length() < 1) {
            throw new SQLException(
                                  Messages.get("error.generic.badparam",
                                                     catalog, "setCatalog"), "3D000");
        }

        String sql = "use [" + catalog + ']';
        baseTds.submitSQL(sql);
    }

    public DatabaseMetaData getMetaData() throws SQLException {
        checkOpen();

        return new JtdsDatabaseMetaData(this);
    }

    public SQLWarning getWarnings() throws SQLException {
        checkOpen();

        return messages.getWarnings();
    }

    public Statement createStatement() throws SQLException {
        checkOpen();

        return createStatement(java.sql.ResultSet.TYPE_FORWARD_ONLY,
                               java.sql.ResultSet.CONCUR_READ_ONLY);
    }

    public Statement createStatement(int type, int concurrency) throws SQLException {
        checkOpen();

        if (type != ResultSet.TYPE_FORWARD_ONLY) {
            throw new SQLException(Messages.get("error.statement.typenotsupp"));
        }
        if (concurrency != ResultSet.CONCUR_READ_ONLY) {
            throw new SQLException(Messages.get("error.statement.concurnotsupp"));
        }

        JtdsStatement stmt = new JtdsStatement(this);
        addStatement(stmt);

        return stmt;
    }

    public Statement createStatement(int type, int concurrency, int holdability)
    throws SQLException {
        checkOpen();
        setHoldability(holdability);

        return createStatement(type, concurrency);
    }

    public String nativeSQL(String sql) throws SQLException {
        checkOpen();

        if (sql == null || sql.length() == 0) {
            throw new SQLException(Messages.get("error.generic.nosql"), "HY000");
        }

        String[] result = new SQLParser(sql, new ArrayList(), this).parse();

        return result[0];
    }

    public CallableStatement prepareCall(String sql) throws SQLException {
        checkOpen();

        return prepareCall(sql,
                           java.sql.ResultSet.TYPE_FORWARD_ONLY,
                           java.sql.ResultSet.CONCUR_READ_ONLY);
    }

    public CallableStatement prepareCall(String sql, int type, int concurrency)
    throws SQLException {
        checkOpen();

        if (sql == null || sql.length() == 0) {
            throw new SQLException(Messages.get("error.generic.nosql"), "HY000");
        }

        JtdsCallableStatement stmt = new JtdsCallableStatement(this, sql);
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
            throw new SQLException(Messages.get("error.generic.nosql"), "HY000");
        }

        if (autoGeneratedKeys != JtdsStatement.RETURN_GENERATED_KEYS &&
            autoGeneratedKeys != JtdsStatement.NO_GENERATED_KEYS) {
            throw new SQLException(
                    Messages.get("error.generic.badoption",
                            Integer.toString(autoGeneratedKeys),
                            "executeUpdate"),
                    "HY092");
        }

        JtdsPreparedStatement stmt = new JtdsPreparedStatement(this,
                sql,
                autoGeneratedKeys == JtdsStatement.RETURN_GENERATED_KEYS);
        addStatement(stmt);

        return stmt;
    }

    public PreparedStatement prepareStatement(String sql, int type, int concurrency)
    throws SQLException {
        checkOpen();

        if (sql == null || sql.length() == 0) {
            throw new SQLException(Messages.get("error.generic.nosql"), "HY000");
        }

        if (type != ResultSet.TYPE_FORWARD_ONLY) {
            throw new SQLException(Messages.get("error.statement.typenotsupp"));
        }
        if (concurrency != ResultSet.CONCUR_READ_ONLY) {
            throw new SQLException(Messages.get("error.statement.concurnotsupp"));
        }

        JtdsPreparedStatement stmt = new JtdsPreparedStatement(this,
                                                               sql,
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
            throw new SQLException(
                                  Messages.get("error.generic.nullparam", "prepareStatement"),"HY092");
        } else if (columnIndexes.length != 1) {
            throw new SQLException(
                                  Messages.get("error.generic.needcolindex", "prepareStatement"),"HY092");
        }

        return prepareStatement(sql, JtdsStatement.RETURN_GENERATED_KEYS);
    }

    public PreparedStatement prepareStatement(String sql, String[] columnNames)
    throws SQLException {
        if (columnNames == null) {
            throw new SQLException(
                                  Messages.get("error.generic.nullparam", "prepareStatement"),"HY092");
        } else if (columnNames.length != 1) {
            throw new SQLException(
                                  Messages.get("error.generic.needcolname", "prepareStatement"),"HY092");
        }

        return prepareStatement(sql, JtdsStatement.RETURN_GENERATED_KEYS);
    }

    /**
     * Releases all savepoints. Used internally when committing or rolling back
     * a transaction.
     */
    abstract void clearSavepoints();
}
