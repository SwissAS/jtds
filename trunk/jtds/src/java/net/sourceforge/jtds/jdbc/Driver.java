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
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Properties;

public class Driver implements java.sql.Driver {
    static {
        try {
            // Register this with the DriverManager
            DriverManager.registerDriver(new Driver());
        } catch (SQLException e) {
            // Ignore any exceptions (there should not be any!)
        }
    }

    public boolean acceptsURL(String url) throws SQLException {
        if (url == null) {
            return false;
        }

        return url.toLowerCase().startsWith(ConnectionImpl.URL_PREFIX);
    }

    public Connection connect(String url, Properties props) throws SQLException {
        if (url == null || !url.toLowerCase().startsWith(ConnectionImpl.URL_PREFIX)) {
            return null;
        }
        DataSourceImpl ds = new DataSourceImpl(url, props);

        if (DriverManager.getLoginTimeout() > 0) {
            ds.setLoginTimeout(DriverManager.getLoginTimeout());
        }
        ds.setLogWriter(DriverManager.getLogWriter());
        
        return ds.getConnection();
    }

    public int getMajorVersion() {
        return ConnectionImpl.MAJOR_VERSION;
    }

    public int getMinorVersion() {
        return ConnectionImpl.MINOR_VERSION;
    }

    public DriverPropertyInfo[] getPropertyInfo(String url, Properties props)
            throws SQLException {
        DataSourceImpl ds = new DataSourceImpl(url, props);
        return ds.getPropertyInfo();
    }

    public boolean jdbcCompliant() {
        return false;
    }

    public static final String getVersion() {
        return ConnectionImpl.MAJOR_VERSION + "." 
               + ConnectionImpl.MINOR_VERSION
                + ConnectionImpl.MISC_VERSION;
    }

    public String toString() {
        return "jTDS " + getVersion();
    }

    public static void main(String[] args) {
        System.out.println("jTDS " + getVersion());
    }
}
