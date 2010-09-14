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

import java.sql.*;

import javax.resource.spi.LocalTransaction;
import javax.resource.spi.ManagedConnection;
import javax.sql.DataSource;
import javax.transaction.xa.XAResource;
import javax.transaction.xa.Xid;

import net.sourceforge.jtds.jca.ManagedConnectionFactoryImpl;

/**
 * Test case to illustrate JCA methods.
 *
 * @version    1.0
 */
public class JcaTest extends TestBase {

    public JcaTest(String name)
    {
        super(name);
    }
    
    /**
     * Test ConnectionHandle.
     */
    public void testConnectionHandle() throws Exception {
        ManagedConnectionFactoryImpl mcf = new ManagedConnectionFactoryImpl();
        mcf.setConnectionURL(props.getProperty("url"));
        mcf.setUserName(props.getProperty("USER"));
        mcf.setPassword(props.getProperty("PASSWORD"));
        DataSource ds = (DataSource)mcf.createConnectionFactory();
        Connection con = ds.getConnection();
        Statement stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT 1");
        assertNotNull(rs);
        assertTrue(rs.next());
        con.close();
    }

    /**
     * Test ManagedConnection
     */
    public void testManagedConnection() throws Exception {
        ManagedConnectionFactoryImpl mcf = new ManagedConnectionFactoryImpl();
        mcf.setConnectionURL(props.getProperty("url"));
        mcf.setUserName(props.getProperty("USER"));
        mcf.setPassword(props.getProperty("PASSWORD"));
        ManagedConnection mc = mcf.createManagedConnection(null, null);
        Connection con = (Connection)mc.getConnection(null, null);
        Statement stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT 1");
        assertNotNull(rs);
        assertTrue(rs.next());
        LocalTransaction lx = mc.getLocalTransaction();
        assertNotNull(lx);
        lx.begin();
        lx.commit();
        XAResource xares = mc.getXAResource();
        assertNotNull(xares);
        Xid xid = new XidImpl(new byte[]{0x01}, new byte[]{0x02});
        xares.start(xid, XAResource.TMNOFLAGS);
        xares.end(xid, XAResource.TMSUCCESS);
        xares.prepare(xid);
        xares.commit(xid, false);
        con.close();
        mc.cleanup();
        mc.destroy();
    }
    
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(JcaTest.class);
    }
}
