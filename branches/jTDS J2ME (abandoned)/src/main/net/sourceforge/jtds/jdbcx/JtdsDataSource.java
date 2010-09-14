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
package net.sourceforge.jtds.jdbcx;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;
import javax.sql.DataSource;

import net.sourceforge.jtds.jdbc.Driver;
import net.sourceforge.jtds.jdbc.Messages;
import net.sourceforge.jtds.util.Logger;

/**
 * The jTDS <code>DataSource</code>, <code>ConnectionPoolDataSource</code> and
 * <code>XADataSource</code> implementation.
 *
 * @author Alin Sinplean
 * @since  jTDS 0.3
 * @version $Id: JtdsDataSource.java,v 1.28.2.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public class JtdsDataSource
        implements DataSource, Serializable {
    protected String serverName;
    protected String portNumber;
    protected String databaseName;
    protected String tdsVersion;
    protected String charset;
    protected String language;
    protected String lastUpdateCount;
    protected String sendStringParametersAsUnicode;
    protected String macAddress;
    protected String tcpNoDelay;
    protected String user;
    protected String password;
    protected String loginTimeout;
    protected String appName;
    protected String progName;
    protected String wsid;
    protected String logFile;
    protected String ssl;
    protected String batchSize;

    protected String description;

    /**
     * Driver instance used for obtaining connections.
     */
    private static Driver driver = new Driver();

    /**
     * Constructs a new datasource.
     */
    public JtdsDataSource() {
        // Do not set default property values here. Properties whose default
        // values depend on server type will likely be incorrect unless the
        // user specified them explicitly.
    }

    /**
     * Returns a new database connection.
     *
     * @return a new database connection
     * @throws SQLException if an error occurs
     */
    public Connection getConnection() throws SQLException {
        return getConnection(user, password);
    }

    /**
     * Returns a new database connection for the user and password specified.
     *
     * @param user the user name to connect with
     * @param password the password to connect with
     * @return a new database connection
     * @throws SQLException if an error occurs
     */
    public Connection getConnection(String user, String password)
            throws SQLException {
        Properties props = new Properties();

        if (serverName == null) {
            throw new SQLException(Messages.get("error.connection.nohost"), "08001");
        }

        //
        // This maybe the only way to initialise the logging subsystem
        // with some containers such as JBOSS.
        //
        if (getLogWriter() == null && logFile != null && logFile.length() > 0) {
            // Try to initialise a PrintWriter
            try {
                setLogWriter(new PrintWriter(new FileOutputStream(logFile), true));
            } catch (IOException e) {
                System.err.println("jTDS: Failed to set log file " + e);
            }
        }

        //
        // Set the non-null properties
        //
        props.setProperty(Messages.get(Driver.SERVERNAME), serverName);
        if (portNumber != null) {
            props.setProperty(Messages.get(Driver.PORTNUMBER), portNumber);
        }
        if (databaseName != null) {
            props.setProperty(Messages.get(Driver.DATABASENAME), databaseName);
        }
        if (tdsVersion != null) {
            props.setProperty(Messages.get(Driver.TDS), tdsVersion);
        }
        if (charset != null) {
            props.setProperty(Messages.get(Driver.CHARSET), charset);
        }
        if (language != null) {
            props.setProperty(Messages.get(Driver.LANGUAGE), language);
        }
        if (lastUpdateCount != null) {
            props.setProperty(Messages.get(Driver.LASTUPDATECOUNT), lastUpdateCount);
        }
        if (sendStringParametersAsUnicode != null) {
            props.setProperty(Messages.get(Driver.SENDSTRINGPARAMETERSASUNICODE), sendStringParametersAsUnicode);
        }
        if (macAddress != null) {
            props.setProperty(Messages.get(Driver.MACADDRESS), macAddress);
        }
        if (tcpNoDelay != null) {
            props.setProperty(Messages.get(Driver.TCPNODELAY), tcpNoDelay);
        }
        if (user != null) {
            props.setProperty(Messages.get(Driver.USER), user);
        }
        if (password != null) {
            props.setProperty(Messages.get(Driver.PASSWORD), password);
        }
        if (loginTimeout != null) {
            props.setProperty(Messages.get(Driver.LOGINTIMEOUT), loginTimeout);
        }
        if (appName != null) {
            props.setProperty(Messages.get(Driver.APPNAME), appName);
        }
        if (progName != null) {
            props.setProperty(Messages.get(Driver.PROGNAME), progName);
        }
        if (wsid != null) {
            props.setProperty(Messages.get(Driver.WSID), wsid);
        }
        if (ssl != null) {
            props.setProperty(Messages.get(Driver.SSL), ssl);
        }
        if (batchSize != null) {
            props.setProperty(Messages.get(Driver.BATCHSIZE), batchSize);
        }

        // Connect with the URL stub and set properties. The defaults will be
        // filled in by connect().
        return driver.connect(props);
    }

    //
    // Getters and setters
    //

    public PrintWriter getLogWriter() throws SQLException {
        return Logger.getLogWriter();
    }

    public void setLogWriter(PrintWriter out) throws SQLException {
        Logger.setLogWriter(out);
    }

    public void setLoginTimeout(int loginTimeout) throws SQLException {
        this.loginTimeout = String.valueOf(loginTimeout);
    }

    public int getLoginTimeout() throws SQLException {
        if (loginTimeout == null) {
            return 0;
        }
        return Integer.parseInt(loginTimeout);
    }

    public void setDatabaseName(String databaseName) {
        this.databaseName = databaseName;
    }

    public String getDatabaseName() {
        return databaseName;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public void setPortNumber(int portNumber) {
        this.portNumber = String.valueOf(portNumber);
    }

    public int getPortNumber() {
        if (portNumber == null) {
            return 0;
        }
        return Integer.parseInt(portNumber);
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public String getServerName() {
        return serverName;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getUser() {
        return user;
    }

    public void setTds(String tds) {
        this.tdsVersion = tds;
    }

    public String getTds() {
        return tdsVersion;
    }

    public boolean getSendStringParametersAsUnicode() {
        return Boolean.valueOf(sendStringParametersAsUnicode).booleanValue();
    }

    public void setSendStringParametersAsUnicode(boolean sendStringParametersAsUnicode) {
        this.sendStringParametersAsUnicode = String.valueOf(sendStringParametersAsUnicode);
    }

    public boolean getLastUpdateCount() {
        return Boolean.valueOf(lastUpdateCount).booleanValue();
    }

    public void setLastUpdateCount(boolean lastUpdateCount) {
        this.lastUpdateCount = String.valueOf(lastUpdateCount);
    }

    public String getCharset() {
        return charset;
    }

    public void setCharset(String charset) {
        this.charset = charset;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public boolean getTcpNoDelay() {
        return Boolean.valueOf(tcpNoDelay).booleanValue();
    }

    public void setTcpNoDelay(boolean tcpNoDelay) {
        this.tcpNoDelay = String.valueOf(tcpNoDelay);
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getAppName() {
        return appName;
    }

    public void setProgName(String progName) {
        this.progName = progName;
    }

    public String getProgName() {
        return progName;
    }

    public void setWsid(String wsid) {
        this.wsid = wsid;
    }

    public String getWsid() {
        return wsid;
    }

    public void setLogFile(String logFile) {
        this.logFile = logFile;
    }

    public String getLogFile() {
        return logFile;
    }

    public void setSsl(String ssl) {
        this.ssl = ssl;
    }

    public String getSsl() {
        return ssl;
    }

    public void setBatchSize(int batchSize) {
        this.batchSize = String.valueOf(batchSize);
    }

    public int getBatchSize() {
        if (batchSize == null) {
            return 0;
        }
        return Integer.parseInt(batchSize);
    }
}
