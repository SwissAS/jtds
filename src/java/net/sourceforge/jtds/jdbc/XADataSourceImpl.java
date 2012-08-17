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

import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.logging.Logger;

import javax.sql.XAConnection;

/**
 * jTDS implementation of the XADatasource interface.
 *
 */
public class XADataSourceImpl extends CommonDataSource implements javax.sql.XADataSource {

    static final long serialVersionUID = 119767589072543751L;

    /**
     * Default constructor.
     *
     */
    public XADataSourceImpl() {
        super();
    }
    
    /**
     * Custom constructor that accepts connection properties and a URL.
     * @param url the connection URL string.
     * @param props additional connection properties.
     * @throws SQLException
     */
    public XADataSourceImpl(final String url, final Properties props) throws SQLException {
        super(url, props);
    }

    //
    // ----- methods from javax.sql.XAConnection -----
    //
    public XAConnection getXAConnection() throws SQLException {
        return getXAConnection(getUser(), getPassword());
    }

    public XAConnection getXAConnection(String user, String password)
            throws SQLException {
        ConnectionImpl con = new ConnectionImpl(this, user, password);
        con.open();
        return new XAConnectionImpl(con);
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException();
    }

}
