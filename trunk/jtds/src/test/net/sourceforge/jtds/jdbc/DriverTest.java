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
import java.util.Enumeration;
import java.util.Properties;

/**
 * Test case to exercise the Driver and DataSource classes.
 *
 * @version    1.0
 */
public class DriverTest extends TestBase {

    public DriverTest(String name)
    {
        super(name);
    }

    public void testDriverMethods() throws Exception {
        String driverClass = props.getProperty("driver"); 
        if (!driverClass.equals("net.sourceforge.jtds.jdbc.Driver")) {
            // We are only interested in testing jTDS
            return;
        }
        Class.forName(driverClass);
        java.sql.Driver drv = null;
        for (Enumeration<java.sql.Driver> e = DriverManager.getDrivers(); e.hasMoreElements(); ) {
            drv = e.nextElement();
            if (drv.getClass().getName().equals(driverClass)) {
                break;
            }
            drv = null;
        }
        assertNotNull(drv);
        assertTrue(drv.acceptsURL("jdbc:jtds:"));
        assertFalse(drv.acceptsURL("jdbc:odbc:"));
        assertEquals(ConnectionImpl.MAJOR_VERSION, drv.getMajorVersion());
        assertEquals(ConnectionImpl.MINOR_VERSION, drv.getMinorVersion());
        assertFalse(drv.jdbcCompliant());
        assertEquals("jTDS", drv.toString().substring(0,4));
        assertEquals(ConnectionImpl.MAJOR_VERSION + "." 
               + ConnectionImpl.MINOR_VERSION
                + ConnectionImpl.MISC_VERSION, net.sourceforge.jtds.jdbc.Driver.getVersion());
        DriverPropertyInfo dpi[] = drv.getPropertyInfo(null, null);
        assertNotNull(dpi);
        assertEquals(40, dpi.length);
        dpi = drv.getPropertyInfo("jdbc:jtds:sqlserver://localhost/jtds", null);
/*        for (int i = 0; i < dpi.length; i++) {
            System.out.print(dpi[i].name + "(" + dpi[i].description + ") = " + 
                    dpi[i].value + " [");
            for (int c = 0; c < dpi[i].choices.length; c++) {
                System.out.print(dpi[i].choices[c]+" ");
            }
            System.out.println("] mandatory=" + dpi[i].required);
        }
*/
        boolean found = false;
        for (int i = 0; i < dpi.length && !found; i++) {
            if (dpi[i].name.equals("serverName")) {
                assertEquals("localhost", dpi[i].value);
                found = true;
            }
        }
        assertTrue(found);
        Properties info = new Properties();
        info.setProperty("DATABASENAME", "jtds");
        dpi = drv.getPropertyInfo("jdbc:jtds:sqlserver://localhost", info);
        found = false;
        for (int i = 0; i < dpi.length && !found; i++) {
            if (dpi[i].name.equals("databaseName")) {
                assertEquals("jtds", dpi[i].value);
                found = true;
            }
        }
        assertTrue(found);
        assertNull(drv.connect(null, null));
        assertNull(drv.connect("jdbc:odbc", null));
        info = new Properties();
        Connection con2 = drv.connect(props.getProperty("url"), props);
        assertNotNull(con2);
        con2.close();
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(DriverTest.class);
    }
}
