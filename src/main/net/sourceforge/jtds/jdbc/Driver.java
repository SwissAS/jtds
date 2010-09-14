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

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

/**
 * jTDS implementation of the java.sql.Driver interface.
 * <p>
 * Implementation note:
 * <ol>
 * <li>Property text names and descriptions are loaded from an external file resource.
 *     This allows the actual names and descriptions to be changed or localised without
 *     impacting this code.
 * <li>The way in which the URL is parsed and converted to properties is rather
 *     different from the original jTDS Driver class.
 *     See parseURL and Connection.unpackProperties methods for more detail.
 * </ol>
 *
 * @author Brian Heineman
 * @author Mike Hutchinson
 * @author Alin Sinpalean
 * @version $Id: Driver.java,v 1.54.2.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public class Driver {
    /** Driver major version. */
    static final int MAJOR_VERSION = 1;
    /** Driver minor version. */
    static final int MINOR_VERSION = 0;
    /** Driver version miscellanea (e.g "-rc2", ".1" or <code>null</code>). */
    static final String MISC_VERSION = ".2";
    /** Set if the JDBC specification to implement is 3.0 or greater. */
    /** TDS 7.0 protocol (SQL Server 7.0 and later). */
    public static final int TDS70 = 3;
    /** TDS 8.0 protocol (SQL Server 2000 and later)*/
    public static final int TDS80 = 4;
    /** TDS 8.1 protocol (SQL Server 2000 SP1 and later). */
    public static final int TDS81 = 5;

    //
    // Property name keys
    //
    public static final String APPNAME       = "prop.appname";
    public static final String BATCHSIZE     = "prop.batchsize";
    public static final String CHARSET       = "prop.charset";
    public static final String DATABASENAME  = "prop.databasename";
    public static final String LANGUAGE      = "prop.language";
    public static final String LASTUPDATECOUNT = "prop.lastupdatecount";
    public static final String LOGFILE       = "prop.logfile";
    public static final String LOGINTIMEOUT  = "prop.logintimeout";
    public static final String MACADDRESS    = "prop.macaddress";
    public static final String PASSWORD      = "prop.password";
    public static final String PORTNUMBER    = "prop.portnumber";
    public static final String PROGNAME      = "prop.progname";
    public static final String SERVERNAME    = "prop.servername";
    public static final String SSL           = "prop.ssl";
    public static final String TCPNODELAY    = "prop.tcpnodelay";
    public static final String TDS           = "prop.tds";
    public static final String USER          = "prop.user";
    public static final String SENDSTRINGPARAMETERSASUNICODE = "prop.useunicode";
    public static final String WSID          = "prop.wsid";

    /**
     * Returns the driver version.
     * <p>
     * Per [908906] 0.7: Static Version information, please.
     *
     * @return the driver version
     */
    public static final String getVersion() {
        return MAJOR_VERSION + "." + MINOR_VERSION
                + ((MISC_VERSION == null) ? "" : MISC_VERSION);
    }

    /**
     * Returns the string form of the object.
     * <p>
     * Per [887120] DriverVersion.getDriverVersion(); this will return a short
     * version name.
     * <p>
     * Added back to driver per [1006449] 0.9rc1: Driver version broken
     *
     * @return the driver version
     */
    public String toString() {
        return "jTDS " + getVersion();
    }

    public Connection connect(Properties props)
            throws SQLException  {
        props = DefaultProperties.addDefaultProperties(props);

        return new ConnectionJDBC3(props);
    }

    public static void main(String[] args) {
        System.out.println("jTDS " + getVersion());
    }
}
