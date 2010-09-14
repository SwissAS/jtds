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
import java.util.HashMap;

/**
 * Test case to exercise the Connection class.
 *
 * @version    1.0
 */
public class ConnectionTest extends TestBase {
        
    public ConnectionTest(String name) {
        super(name);
    }
    
    /**
     * Check get/set catalog methods.
     * @throws Exception
     */
    public void testSetCatalog() throws Exception {
        //
        // Obtain a utility statement
        //
        Statement stmt = con.createStatement();
        assertNotNull(stmt);
        //
        // Check set/get catalog
        //
        String database = con.getCatalog();
        assertNotNull(database);
        String testDB  = "tempdb";
        if (isASA) {
            // ASA can't change the database 
            testDB = database;
        }
        con.setCatalog(testDB);
        assertEquals(testDB, con.getCatalog());
        //
        // See if server really changed
        //
        ResultSet rs = stmt.executeQuery("SELECT {fn dAtaBaSe()}");
        assertNotNull(rs);
        assertTrue(rs.next());
        assertEquals(testDB, rs.getString(1));
        con.setCatalog(database);
        stmt.close();
    }
    
    /**
     * Excercise the get / clear warnings methods.
     * @throws Exception
     */
    public void testWarnings() throws Exception {
        SQLWarning warn = con.getWarnings();
//        assertNotNull(warn); Sybase + SQL Server clear warnings
        while (null != warn) {
            System.out.println(warn.getMessage());
            warn = warn.getNextWarning();
        }
        con.clearWarnings();
        assertNull(con.getWarnings());
    }
    
    /**
     * Test get/set readonly methods.
     * @throws Exception
     */
    public void testReadOnly() throws Exception {
        //
        // Readonly is a do nothing for jTDS
        //
        assertFalse(con.isReadOnly());
        con.setReadOnly(true);
        assertTrue(con.isReadOnly());
        con.setReadOnly(false);        
    }
    
    /**
     * Test nativeSQL method.
     * @throws Exception
     */
    public void testNativeSQL() throws Exception {
        if (con instanceof net.sourceforge.jtds.jdbc.ConnectionImpl) {
            assertEquals("select user_name()", 
                con.nativeSQL("select {fn user()}"));
        }
    }
    
    /**
     * Test get / set Typemap.
     * @throws Exception
     */
    public void testTypeMap() throws Exception {
        //
        // jTDS getTypeMap returns an empty map
        //
        java.util.Map<String,Class<?>> map = con.getTypeMap();
        assertNotNull(map);
        map.put("TEST", java.lang.String.class);
        try {
            //
            // jTDS reports not implemented for setTypeMap
            //
            con.setTypeMap(map);
            if (con instanceof net.sourceforge.jtds.jdbc.ConnectionImpl) {
                fail("setTypeMap");
            }
        } catch (SQLException e) {
            assertTrue(e.getMessage().indexOf("not implemented") >= 0);
        }        
    }
    
    /**
     * Test get / set transaction isolation.
     * @throws Exception
     */
    public void testTransactionIsolation() throws Exception {
        //
        // Obtain a utility statement
        //
        Statement stmt = con.createStatement();
        assertNotNull(stmt);
        //
        int iso = con.getTransactionIsolation();
        assertEquals("getTransactionIsolation", Connection.TRANSACTION_READ_COMMITTED, iso);
        con.setTransactionIsolation(Connection.TRANSACTION_READ_UNCOMMITTED);
        assertEquals("getTransactionIsolation", 
                Connection.TRANSACTION_READ_UNCOMMITTED, con.getTransactionIsolation());
        //
        // See if server really changed
        //
        int serverLevel = -1;
        if (con.getMetaData().getDatabaseProductName().toLowerCase().startsWith("microsoft")){
            // MS Approach
            ResultSet rs = stmt.executeQuery("DBCC USEROPTIONS");
            while (rs.next()) {
                if (rs.getString(1).equals("isolation level") &&
                    rs.getString(2).equals("read uncommitted")){
                    serverLevel = 0;
                }
            }
        } else {
            // Sybase approach (much easier)
            ResultSet rs = stmt.executeQuery("SELECT @@isolation"); 
            rs.next();
            serverLevel = rs.getInt(1);
        }
        assertEquals(0, serverLevel);
        // Restore original
        con.setTransactionIsolation(iso);        
    }
    
    /**
     * Test commit and rollback.
     * @throws Exception
     */
    public void testCommitRollback() throws Exception {
        //
        // Obtain a utility statement
        //
        Statement stmt = con.createStatement();
        assertNotNull(stmt);
        //
        // Driver should start with auto commit = true
        //
        assertTrue(con.getAutoCommit());
        stmt.execute("CREATE TABLE #TESTCOMMIT (id int primary key)");        
        con.setAutoCommit(false);
        assertFalse(con.getAutoCommit());
        //
        assertEquals(1, stmt.executeUpdate("INSERT INTO #TESTCOMMIT VALUES (1)"));
        con.commit();
        assertEquals(1, stmt.executeUpdate("INSERT INTO #TESTCOMMIT VALUES (2)"));
        assertEquals(1, stmt.executeUpdate("INSERT INTO #TESTCOMMIT VALUES (3)"));
        con.rollback();
        assertEquals(1, stmt.executeUpdate("INSERT INTO #TESTCOMMIT VALUES (4)"));
        // Should be committed by set
        con.setAutoCommit(true);
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM #TESTCOMMIT");
        rs.next();
        assertEquals("commit", 2, rs.getInt(1));
        stmt.close();
    }
    
    /**
     * Test that connection methods handle closed connections correctly.
     * @throws Exception
     */
    public void testClosed() throws Exception {
        //
        // Check connection close
        //
        assertFalse(con.isClosed());
        con.close();
        assertTrue(con.isClosed());
        //
        // Check all other methods generate is closed exception
        //
        String msg = "Invalid state, the Connection object is closed.";
//        String msg = "[Microsoft][SQLServer 2000 Driver for JDBC]Object has been closed.";
        try {
            con.clearWarnings();
            fail("closed test fail-1"); // MS allows this
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.commit();
            fail("closed test fail-2");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.createStatement();
            fail("closed test fail-3");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
            fail("closed test fail-4");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.getAutoCommit();
            fail("closed test fail-5");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.getCatalog();
            fail("closed test fail-6");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.getMetaData();
            fail("closed test fail-7");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.getTransactionIsolation();
            fail("closed test fail-8");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.getTypeMap();
            fail("closed test fail-9"); // MS Allows this
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.getWarnings();
            fail("closed test fail-10"); // MS Allows this
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.isReadOnly();
            fail("closed test fail-11");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.nativeSQL("SELECT 1");
            fail("closed test fail-12");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.prepareCall("{call sp_who}");
            fail("closed test fail-13");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.prepareCall("{call sp_who}", ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
            fail("closed test fail-14");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.prepareStatement("SELECT 1");
            fail("closed test fail-15");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.prepareStatement("SELECT 1", ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
            fail("closed test fail-16");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.rollback();
            fail("closed test fail-17");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.setAutoCommit(true);
            fail("closed test fail-18");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.setCatalog("dummy");
            fail("closed test fail-19");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.setReadOnly(true);
            fail("closed test fail-20");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            fail("closed test fail-21");
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            con.setTypeMap(new HashMap<String,Class<?>>());
            fail("closed test fail-22"); // MS Allows this
        } catch (SQLException e) {
            assertEquals(msg, e.getMessage());
        }        
    }

    public void testSavepoint1() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #savepoint1 (data int)");
        stmt.close();

        con.setAutoCommit(false);

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #savepoint1 (data) VALUES (?)");

        pstmt.setInt(1, 1);
        assertTrue(pstmt.executeUpdate() == 1);

        Savepoint savepoint = con.setSavepoint();

        assertNotNull(savepoint);
        assertTrue(savepoint.getSavepointId() == 1);

        try {
            savepoint.getSavepointName();
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        pstmt.setInt(1, 2);
        assertTrue(pstmt.executeUpdate() == 1);
        pstmt.close();

        stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint1");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 3);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.rollback(savepoint);
        con.commit();

        stmt = con.createStatement();
        rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint1");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 1);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.setAutoCommit(true);
    }

    public void testSavepoint2() throws Exception {
        String savepointName = "SAVEPOINT_1";

        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #savepoint2 (data int)");
        stmt.close();

        con.setAutoCommit(false);

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #savepoint2 (data) VALUES (?)");

        pstmt.setInt(1, 1);
        assertTrue(pstmt.executeUpdate() == 1);

        Savepoint savepoint = con.setSavepoint(savepointName);

        assertNotNull(savepoint);
        assertTrue(savepointName.equals(savepoint.getSavepointName()));

        try {
            savepoint.getSavepointId();
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        pstmt.setInt(1, 2);
        assertTrue(pstmt.executeUpdate() == 1);
        pstmt.close();

        stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint2");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 3);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.rollback(savepoint);

        try {
            con.rollback(null);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.rollback(savepoint);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.releaseSavepoint(null);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.releaseSavepoint(savepoint);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        con.commit();

        stmt = con.createStatement();
        rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint2");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 1);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.setAutoCommit(true);

        try {
            con.setSavepoint();
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.setSavepoint(savepointName);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }
    }

    public void testSavepoint3() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #savepoint3 (data int)");
        stmt.close();

        con.setAutoCommit(false);

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #savepoint3 (data) VALUES (?)");

        pstmt.setInt(1, 1);
        assertTrue(pstmt.executeUpdate() == 1);

        Savepoint savepoint1 = con.setSavepoint();

        assertNotNull(savepoint1);
        assertTrue(savepoint1.getSavepointId() == 1);

        pstmt.setInt(1, 2);
        assertTrue(pstmt.executeUpdate() == 1);

        Savepoint savepoint2 = con.setSavepoint();

        assertNotNull(savepoint2);
        assertTrue(savepoint2.getSavepointId() == 2);

        pstmt.setInt(1, 3);
        assertTrue(pstmt.executeUpdate() == 1);

        Savepoint savepoint3 = con.setSavepoint();

        assertNotNull(savepoint3);
        assertTrue(savepoint3.getSavepointId() == 3);

        pstmt.setInt(1, 4);
        assertTrue(pstmt.executeUpdate() == 1);

        pstmt.close();

        stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint3");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 10);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.releaseSavepoint(savepoint1);

        try {
            con.rollback(savepoint1);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.releaseSavepoint(savepoint1);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        con.rollback(savepoint2);

        try {
            con.rollback(savepoint2);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.releaseSavepoint(savepoint2);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.rollback(savepoint3);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.releaseSavepoint(savepoint3);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        con.commit();

        stmt = con.createStatement();
        rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint3");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 3);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.setAutoCommit(true);
    }

    /**
     * Test to ensure savepoint ids restart at 1. Also ensures that the
     * procedure cache is managed properly with savepoints.
     */
    public void testSavepoint4() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #savepoint4 (data int)");
        stmt.close();

        con.setAutoCommit(false);

        for (int i = 0; i < 3; i++) {
//            System.out.println("iteration: " + i);
            PreparedStatement pstmt = con.prepareStatement("INSERT INTO #savepoint4 (data) VALUES (?)");

            pstmt.setInt(1, 1);
            assertTrue(pstmt.executeUpdate() == 1);

            Savepoint savepoint = con.setSavepoint();
            assertNotNull(savepoint);
            assertTrue(savepoint.getSavepointId() == 1);

            try {
                savepoint.getSavepointName();
                assertTrue(false);
            } catch (SQLException e) {
                // Ignore, we should get this exception
            }

            pstmt.setInt(1, 2);
            assertTrue(pstmt.executeUpdate() == 1);
            pstmt.close();

            pstmt = con.prepareStatement("SELECT SUM(data) FROM #savepoint4");
            ResultSet rs = pstmt.executeQuery();

            assertTrue(rs.next());
            assertTrue(rs.getInt(1) == 3);
            assertTrue(!rs.next());
            pstmt.close();
            rs.close();

            con.rollback(savepoint);

            pstmt = con.prepareStatement("SELECT SUM(data) FROM #savepoint4");
            rs = pstmt.executeQuery();

            assertTrue(rs.next());
            assertTrue(rs.getInt(1) == 1);
            assertTrue(!rs.next());
            pstmt.close();
            rs.close();

            con.rollback();
        }

        con.setAutoCommit(true);
    }

    /**
     * Test to ensure savepoints can be created even when no statements have
     * been issued.
     */
    public void testSavepoint5() throws Exception {
        con.setAutoCommit(false);
        con.setSavepoint();
        con.rollback();
        con.setAutoCommit(true);
    }
    
    /**
     * Check set / get holdability methods
     * 
     */
    public void testHoldability() throws Exception {
        con.setHoldability(ResultSet.HOLD_CURSORS_OVER_COMMIT);
        assertEquals(ResultSet.HOLD_CURSORS_OVER_COMMIT, con.getHoldability());
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ConnectionTest.class);
    }
}
