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
package net.sourceforge.jtds.test;

import java.sql.*;

/**
 * JDBC 3.0-only tests for Connection.
 *
 * @author Alin Sinpalean
 * @version $Id: ConnectionJDBC3Test.java,v 1.3 2009-08-10 15:48:39 ickzon Exp $
 */
public class ConnectionJDBC3Test extends DatabaseTestCase {

    public ConnectionJDBC3Test(String name) {
        super(name);
    }

    /**
     * Test that temporary procedures created within transactions with
     * savepoints which are released are still kept in the procedure cache.
     *
     * @test.manual when testing, prepareSQL will have to be set to 1 to make
     *              sure temp procedures are used
     */
    public void testSavepointRelease() throws SQLException {
        // Manual commit mode
        con.setAutoCommit(false);
        // Create two savepoints
        Savepoint sp1 = con.setSavepoint();
        Savepoint sp2 = con.setSavepoint();
        // Create and execute a prepared statement
        PreparedStatement stmt = con.prepareStatement("SELECT 1");
        assertTrue(stmt.execute());
        // Release the inner savepoint and rollback the outer
        con.releaseSavepoint(sp2);
        con.rollback(sp1);
        // Now make sure the temp stored procedure still exists
        assertTrue(stmt.execute());
        // Release resources
        stmt.close();
        con.close();
    }

    /**
     * Test for bug [1296482] setAutoCommit() behaviour.
     * <p/>
     * The behaviour of setAutoCommit() on ConnectionJDBC2 is inconsistent with
     * the Sun JDBC 3.0 Specification. JDBC 3.0 Specification, section 10.1.1:
     * <blockquote>"If the value of auto-commit is changed in the middle of a
     * transaction, the current transaction is committed."</blockquote>
     */
    public void testAutoCommit() throws Exception {
        Connection con = getConnection();

        try {
            Statement stmt = con.createStatement();
            // Create temp table
            assertEquals(0, stmt.executeUpdate(
                    "create table #testAutoCommit (i int)"));
            // Manual commit mode
            con.setAutoCommit(false);
            // Insert one row
            assertEquals(1, stmt.executeUpdate(
                    "insert into #testAutoCommit (i) values (0)"));
            // Set commit mode to manual again; should have no effect
            con.setAutoCommit(false);
            // Rollback the transaction; should roll back the insert
            con.rollback();
            // Insert one more row
            assertEquals(1, stmt.executeUpdate(
                    "insert into #testAutoCommit (i) values (1)"));
            // Set commit mode to automatic; should commit everything
            con.setAutoCommit(true);
            // Go back to manual commit mode
            con.setAutoCommit(false);
            // Rollback transaction; should do nothing
            con.rollback();
            // And back to auto commit mode again
            con.setAutoCommit(true);
            // Now see if the second row is there
            ResultSet rs = stmt.executeQuery("select i from #testAutoCommit");
            assertTrue(rs.next());
            assertEquals(1, rs.getInt(1));
            assertFalse(rs.next());
            // We're done, close everything
            rs.close();
            stmt.close();
        } finally {
            con.close();
        }
    }
    
    /**
     * Test for bug [1755448], login failure leaves unclosed sockets.
     */
    public void testUnclosedSocket() {
        final int count = 100000;

        String url = props.getProperty("url") + ";loginTimeout=600";

        for (int i = 0; i < count; i ++) {
            try {
                DriverManager.getConnection(url, "sa", "invalid_password");
                assertTrue(false);
            } catch (SQLException e) {
                assertEquals(18456, e.getErrorCode());
            }
        }
    }

}