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

import java.util.Properties;

import net.sourceforge.jtds.ssl.Ssl;

/**
 * Container for default property constants.
 * <p/>
 * This class also provides static utility methods for
 * {@link Properties} and <code>Settings</code> objects.
 * <p/>
 * To add new properties to the jTDS driver, do the following:
 * <ol>
 * <li>Add <code>prop.<em>foo</em></code> and <code>prop.desc.<em>foo</em></code>
 *     properties to <code>Messages.properties</code>.</li>
 * <li>Add a <code>static final</code> default field to {@link DefaultProperties}.</li>
 * <li>Update {@link #addDefaultProperties(java.util.Properties)} to set the default.</li>
 * <li>Add a new test to <code>DefaultPropertiesTestLibrary</code> for the new
 *     property.</li>
 * </ol>
 *
 * @author David D. Kilzer
 * @version $Id: DefaultProperties.java,v 1.19.2.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public final class DefaultProperties {

    /** Default <code>appName</code> property. */
    public static final String APP_NAME = "jTDS";
    /** Default <code>batchSize</code> property for SQL Server. */
    public static final String BATCH_SIZE_SQLSERVER = "0";
    /** Default <code>databaseName</code> property. */
    public static final String DATABASE_NAME = "";
    /** Default <code>lastUpdateCount</code> property. */
    public static final String LAST_UPDATE_COUNT = "true";
    /** Default <code>loginTimeout</code> property. */
    public static final String LOGIN_TIMEOUT = "0";
    /** Default <code>macAddress</code> property. */
    public static final String MAC_ADDRESS = "000000000000";
    /** Default <code>password</code> property. */
    public static final String PASSWORD = "";
    /** Default <code>portNumber</code> property for SQL Server. */
    public static final String PORT_NUMBER_SQLSERVER = "1433";
    /** Default <code>charset</code> property. */
    public static final String CHARSET = "";
    /** Default <code>language</code> property. */
    public static final String LANGUAGE = "";
    /** Default <code>progName</code> property. */
    public static final String PROG_NAME = "jTDS";
    /** Default <code>tcpNoDelay</code> property. */
    public static final String TCP_NODELAY = "true";
    /** Default <code>sendStringParametersAsUnicode</code> property. */
    public static final String USE_UNICODE = "true";
    /** Default <code>user</code> property. */
    public static final String USER = "";
    /** Default <code>wsid</code> property. */
    public static final String WSID = "";
    /** Default <code>logfile</code> property. */
    public static final String LOGFILE = "";

    /** Default <code>tds</code> property for TDS 7.0. */
    public static final String TDS_VERSION_70 = "7.0";
    /** Default <code>tds</code> property for TDS 8.0. */
    public static final String TDS_VERSION_80 = "8.0";

    /** Default <code>ssl</code> property. */
    public static final String SSL = Ssl.SSL_OFF;

    /**
     * Add default properties to the <code>props</code> properties object.
     *
     * @param props The properties object.
     * @return The updated <code>props</code> object, or <code>null</code>
     *         if the <code>serverType</code> property is not set.
     */
    public static Properties addDefaultProperties(final Properties props) {
        addDefaultPropertyIfNotSet(props, Driver.TDS, TDS_VERSION_80);

        addDefaultPropertyIfNotSet(props, Driver.PORTNUMBER, PORT_NUMBER_SQLSERVER);

        addDefaultPropertyIfNotSet(props, Driver.USER, USER);
        addDefaultPropertyIfNotSet(props, Driver.PASSWORD, PASSWORD);

        addDefaultPropertyIfNotSet(props, Driver.DATABASENAME, DATABASE_NAME);
        addDefaultPropertyIfNotSet(props, Driver.APPNAME, APP_NAME);
        addDefaultPropertyIfNotSet(props, Driver.PROGNAME, PROG_NAME);
        addDefaultPropertyIfNotSet(props, Driver.WSID, WSID);
        addDefaultPropertyIfNotSet(props, Driver.BATCHSIZE, BATCH_SIZE_SQLSERVER);
        addDefaultPropertyIfNotSet(props, Driver.LASTUPDATECOUNT, LAST_UPDATE_COUNT);
        addDefaultPropertyIfNotSet(props, Driver.LOGINTIMEOUT, LOGIN_TIMEOUT);
        addDefaultPropertyIfNotSet(props, Driver.MACADDRESS, MAC_ADDRESS);
        addDefaultPropertyIfNotSet(props, Driver.CHARSET, CHARSET);
        addDefaultPropertyIfNotSet(props, Driver.LANGUAGE, LANGUAGE);
        addDefaultPropertyIfNotSet(props, Driver.SENDSTRINGPARAMETERSASUNICODE, USE_UNICODE);
        addDefaultPropertyIfNotSet(props, Driver.TCPNODELAY, TCP_NODELAY);
        addDefaultPropertyIfNotSet(props, Driver.LOGFILE, LOGFILE);
        addDefaultPropertyIfNotSet(props, Driver.SSL, SSL);

        return props;
    }

    /**
     * Sets a default property if the property is not already set.
     *
     * @param props The properties object.
     * @param key The message key to set.
     * @param defaultValue The default value to set.
     */
    private static void addDefaultPropertyIfNotSet(
            final Properties props, final String key, final String defaultValue) {
        final String messageKey = Messages.get(key);

        if (props.getProperty(messageKey) == null) {
            props.setProperty(messageKey, defaultValue);
        }
    }

    /**
     * Converts a string TDS version to its integer representation.
     *
     * @param tdsVersion The TDS version as a string.
     * @return The TDS version as an integer if known, or <code>null</code> if unknown.
     */
    public static Integer getTdsVersion(String tdsVersion) {
        if (DefaultProperties.TDS_VERSION_70.equals(tdsVersion)) {
            return new Integer(Driver.TDS70);
        } else if (DefaultProperties.TDS_VERSION_80.equals(tdsVersion)) {
            return new Integer(Driver.TDS80);
        }

        return null;
    }
}
