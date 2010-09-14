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
import java.sql.DataTruncation;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.BatchUpdateException;


/**
 * Test case to exercise the Statement class.
 *
 * @version    1.0
 */
public class StatementTest extends TestBase {
        
    public StatementTest(String name) {
        super(name);
    }

    /**
     * Test create all statement type concurrencies.
     * @throws Exception
     */
    public void testCreateStatement() throws Exception {
        Statement stmt;
        //
        // Check bad params
        //
        try {
            stmt = con.createStatement(999, ResultSet.CONCUR_UPDATABLE);
            fail("Expected error bad type");
        } catch (SQLException e) {
            // Ignore
        }
        try {
            stmt = con.createStatement(ResultSet.TYPE_FORWARD_ONLY, 999);
            fail("Expected error bad concurrency");
        } catch (SQLException e) {
            // Ignore
        }
        //
        // Default type / concurrency
        //
        stmt = con.createStatement();
        assertNotNull(stmt);
        stmt.close();
        //
        // Forward read only
        //
        stmt = con.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
        assertNotNull(stmt);
        stmt.close();
        //
        // Forward updateable
        //
        stmt = con.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_UPDATABLE);
        assertNotNull(stmt);
        stmt.close();
        //
        // Scrollable read only
        //
        stmt = con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        assertNotNull(stmt);
        stmt.close();
        //
        // Scrollable updateable
        //
        stmt = con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
        assertNotNull(stmt);
        stmt.close();
        //
        // Scrollable read only
        //
        stmt = con.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_READ_ONLY);
        assertNotNull(stmt);
        stmt.close();
        //
        // Scrollable updateable
        //
        stmt = con.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_UPDATABLE);
        assertNotNull(stmt);
        stmt.close();
        stmt = con.createStatement(ResultSet.TYPE_FORWARD_ONLY, 
                ResultSet.CONCUR_READ_ONLY, 
                ResultSet.HOLD_CURSORS_OVER_COMMIT);
        stmt.close();
        //
        // Check bad params
        //
        try {
            stmt = con.createStatement(ResultSet.TYPE_FORWARD_ONLY, 
                            ResultSet.CONCUR_READ_ONLY, 
                                999);
            fail("Expected error bad Holdability");
        } catch (SQLException e) {
            // Ignore
        }
    }
    
    /**
     * Test get type / concurrency.
     * @throws Exception
     */
    public void testGetTypeConcur() throws Exception {
        Statement stmt = con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
        assertNotNull(stmt);
        assertEquals(ResultSet.TYPE_SCROLL_INSENSITIVE, stmt.getResultSetType());
        assertEquals(ResultSet.CONCUR_UPDATABLE, stmt.getResultSetConcurrency());
        stmt.close();
        // Default type/concurrency
        stmt = con.createStatement();
        assertNotNull(stmt);
        assertEquals(ResultSet.TYPE_FORWARD_ONLY, stmt.getResultSetType());
        assertEquals(ResultSet.CONCUR_READ_ONLY, stmt.getResultSetConcurrency());
        stmt.close();
    }
    
    /**
     * Test get Connection.
     * @throws Exception
     */
    public void testGetConnection() throws Exception {
        Statement stmt = con.createStatement();
        //
        // Get connection
        //
        assertTrue(con.equals(stmt.getConnection()));        
        stmt.close();
    }
    
    /**
     * Test get / set fetch direction.
     * @throws Exception
     */
    public void testFetchDirection() throws Exception {
        Statement stmt = con.createStatement();
        //
        // Fetch direction
        //
        assertEquals(ResultSet.FETCH_FORWARD, stmt.getFetchDirection());
        stmt.setFetchDirection(ResultSet.FETCH_REVERSE);
        assertEquals(ResultSet.FETCH_REVERSE, stmt.getFetchDirection());
        stmt.setFetchDirection(ResultSet.FETCH_FORWARD);
        stmt.close();
    }
    
    /**
     * Test get/set Fetch size.
     * @throws Exception
     */
    public void testFetchSize() throws Exception {
        Statement stmt = con.createStatement();
        //
        // Fetch size
        //
        int orig = stmt.getFetchSize();
        stmt.setMaxRows(1);
        try {
            stmt.setFetchSize(8);
            fail("error expected setFetchSize > maxrows");
        } catch (SQLException e) {
            // Ignore
        }
        stmt.setMaxRows(0);
        try {
            stmt.setFetchSize(-1);
            fail("error expected setFetchSize < 0");
        } catch (SQLException e) {
            // Ignore
        }
        stmt.setFetchSize(8);
        assertEquals(8, stmt.getFetchSize());
        stmt.setFetchSize(orig);        
        stmt.close();
    }
    
    /**
     * Test set escape processing.
     * @throws Exception
     */
    public void testEscapeProcessing() throws Exception {
        Statement stmt = con.createStatement();
        //
        // Set escape processing
        //
        stmt.setEscapeProcessing(false);
        try {
            stmt.executeQuery("select {oj 'the oj will be removed'}");
            fail("Exception processing not disabled");
        } catch (SQLException e) {
            // Ignore
        }
        stmt.setEscapeProcessing(true);
        stmt.close();
    }
    
    /**
     *  Test set/get max rows and max field size.
     * @throws Exception
     */
    public void testMaxRowsMaxFieldSize() throws Exception {
        try {
            dropTable("jtdsStmtTest");
            Statement stmt = con.createStatement();
            //
            // Test setMaxRows and setMaxFieldSize
            //
            stmt.execute("CREATE TABLE jtdsStmtTest (id int primary key, data text)");
            assertEquals(1, stmt.executeUpdate("INSERT INTO jtdsStmtTest VALUES(1, " + 
                    "'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')"));
            assertEquals(1, stmt.executeUpdate("INSERT INTO jtdsStmtTest VALUES(2, " + 
                    "'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')"));
            Statement stmt2 = con.createStatement();
            stmt.setMaxFieldSize(10);
            assertEquals("getMaxFieldSize", 10, stmt.getMaxFieldSize());
            stmt.setMaxRows(1);
            assertEquals("getMaxRows", 1, stmt.getMaxRows());
            ResultSet rs = stmt.executeQuery("SELECT * FROM jtdsStmtTest");
            assertTrue(rs.next());
            assertEquals(10, rs.getString(2).length());
            assertFalse(rs.next());
            rs.close();
            // Ensure settings are statement specific
            rs = stmt2.executeQuery("SELECT * FROM jtdsStmtTest");
            assertTrue(rs.next());
            assertEquals(30, rs.getString(2).length());
            assertTrue(rs.next());
            rs.close();
            stmt2.close();
            //
            // Check illegal value validation
            //
            try {
                stmt.setMaxFieldSize(-1);
                fail("Expected error maxFieldSize < 0");
            } catch (SQLException e) {
                // Ignore
            }
            try {
                stmt.setMaxRows(-1);
                fail("Expected error maxRows < 0");
            } catch (SQLException e) {
                // Ignore
            }
            stmt.setMaxFieldSize(0);
            stmt.setMaxRows(0);
            stmt.close();
        } finally {
            dropTable("jtdsStmtTest");
        }
    }
    
    /**
     * Test set cursor name.
     * @throws Exception
     */
    public void testCursorName() throws Exception {
        if (isASA) {
            // No positioned updates
            return;
        }
        Statement stmt = con.createStatement();
        //
        // Test setCursorName
        //
        stmt.execute("CREATE TABLE #TESTCNAME (id int)");
        stmt.setCursorName("TESTCURSOR");
        ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTCNAME");
        assertEquals("getCursorName", "TESTCURSOR", rs.getCursorName());
        rs.close();
        stmt.setCursorName(null);
        stmt.close();
    }
    
    /**
     * Test set/get query timeout
     * @throws Exception
     */
    public void testQueryTimeout1() throws Exception {
        try {
            dropTable("jtdsStmtTest");
            Statement stmt = con.createStatement();
            stmt.execute("CREATE TABLE jtdsStmtTest (id int primary key, data text)");
            assertEquals(1, stmt.executeUpdate("INSERT INTO jtdsStmtTest VALUES(1, " + 
                    "'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')"));
            assertEquals(1, stmt.executeUpdate("INSERT INTO jtdsStmtTest VALUES(2, " + 
                    "'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')"));
            //
            // Query timeout
            //
            try {
                stmt.setQueryTimeout(-1);
                fail("Expected error timeout < 0");
            } catch (SQLException e) {
                // Ignore
            }
            con.setAutoCommit(false);
            assertEquals(1, stmt.executeUpdate("UPDATE jtdsStmtTest SET data = '' WHERE id = 1"));
            Connection con2 = getConnection();
            Statement stmt2 = con2.createStatement();
            stmt2.setQueryTimeout(2);
            assertEquals(2, stmt2.getQueryTimeout());
            try {
                stmt2.executeQuery("SELECT * FROM jtdsStmtTest WHERE id = 1");
                fail("Expected time out exception");
            } catch (SQLException e) {
                System.out.println(e);
                // Timeout expected
            }
            con2.close();
            con.rollback();
            con.setAutoCommit(true);
            stmt.close();
        } finally {
            con.setAutoCommit(true);
          	dropTable("jtdsStmtTest");
        }
    }
    

    /**
     * Test for bug [1694194], queryTimeout does not work on MSSQL2005 when
     * property 'useCursors' is set to 'true'. Furthermore, the test also
     * checks timeout with a query that cannot use a cursor. <p>
     *
     * This test requires property 'queryTimeout' to be set to true.
     */
    public void testQueryTimeout2() throws Exception {
        Statement st = con.createStatement();
        st.setQueryTimeout(1);

        st.execute("create procedure #testTimeout as begin waitfor delay '00:00:30'; select 1; end");

        long start = System.currentTimeMillis();
        try {
            // this query doesn't use a cursor
            st.executeQuery("exec #testTimeout");
            fail("query did not time out");
        } catch (SQLException e) {
            assertEquals("HYT00", e.getSQLState());
            assertEquals(1000, System.currentTimeMillis() - start, 10);
        }

        st.execute("create table #dummy1(A varchar(200))");
        st.execute("create table #dummy2(B varchar(200))");
        st.execute("create table #dummy3(C varchar(200))");

        // create test data
        con.setAutoCommit(false);
        for(int i = 0; i < 100; i++) {
            st.execute("insert into #dummy1 values('" + i + "')");
            st.execute("insert into #dummy2 values('" + i + "')");
            st.execute("insert into #dummy3 values('" + i + "')");
        }
        con.commit();
        con.setAutoCommit(true);

        start = System.currentTimeMillis();
        try {
            // this query can use a cursor
            st.executeQuery("select * from #dummy1, #dummy2, #dummy3 order by A desc, B asc, C desc");
            fail("query did not time out");
        } catch (SQLException e) {
            assertEquals("HYT00", e.getSQLState());
            assertEquals(1000, System.currentTimeMillis() - start, 10);
        }

        st.close();
    }

    /**
     * Test getMoreResults, getUpdateCount and execute().
     * @throws Exception
     */
    public void testMoreResults() throws Exception {
        try {
            dropTable("jtdsStmtTest");
            dropProcedure("jtdsTestProc");
            Statement stmt = con.createStatement();
            stmt.execute("CREATE TABLE jtdsStmtTest (id int primary key, data text)");
            //
            // Test execute get more results etc
            //
            stmt.execute("CREATE PROC jtdsTestProc AS\r\n" +
                    "BEGIN\r\n"+
                    "INSERT INTO jtdsStmtTest VALUES(3, " + 
                        "'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')\r\n" +
                    "SELECT * FROM jtdsStmtTest WHERE id = 3\r\n" + 
                    "DELETE FROM jtdsStmtTest WHERE id = 3\r\n"+
                    "END\r\n");
            assertFalse(stmt.execute("EXEC jtdsTestProc"));
            assertEquals(1, stmt.getUpdateCount());
            assertTrue(stmt.getMoreResults());
            assertNotNull(stmt.getResultSet());
            assertFalse(stmt.getMoreResults());
            assertEquals(1, stmt.getUpdateCount());
            assertFalse(stmt.getMoreResults());
            assertEquals(-1, stmt.getUpdateCount());
            assertNull(stmt.getResultSet());            
        } finally {
            dropProcedure("jtdsTestProc");
            dropTable("jtdsStmtTest");
        }
    }

    /**
     * Test batch execution methods.
     * @throws Exception
     */
    public void testExecuteBatch() throws Exception {
        //
        // Test batch execution
        //
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TESTBATCH (id int primary key, data varchar(255))");
        //
        stmt.addBatch("INSERT INTO #TESTBATCH VALUES(1, 'THIS WILL WORK')");
        stmt.addBatch("INSERT INTO #TESTBATCH VALUES(2, 'AS WILL THIS')");
        int counts[];
        counts = stmt.executeBatch();
        assertEquals(2, counts.length);
        assertEquals(1, counts[0]);
        assertEquals(1, counts[1]);
        // Now with errors
        stmt.addBatch("INSERT INTO #TESTBATCH VALUES(3, 'THIS WILL WORK')");
        stmt.addBatch("INSERT INTO #TESTBATCH VALUES(1, 'THIS WILL NOT')");
//         DriverManager.setLogStream(System.out);
        try {
            counts = stmt.executeBatch();
            fail("Expected exec batch to fail");
        } catch (BatchUpdateException e) {
            counts = e.getUpdateCounts();
        }
        if (con.getMetaData().getDatabaseProductName().toLowerCase().startsWith("microsoft")) {
            assertEquals(2, counts.length);
            assertEquals(1, counts[0]);
            assertEquals(-3, counts[1]); // EXECUTE failed
        } else {
            assertEquals(2, counts.length);
            assertEquals(1, counts[0]);
            assertEquals(-3, counts[1]); // EXECUTE failed
        }
        //
        // Test batch cleared after execution
        //
        assertEquals(0, stmt.executeBatch().length);        
        //
        // Test clear batch
        //
        stmt.addBatch("INSERT INTO #TESTBATCH VALUES(3, 'DUMMY')");
        stmt.clearBatch();
        assertEquals(0, stmt.executeBatch().length);      
        stmt.close();
    }
    
    /**
     * Test DataTruncation exception
     * @throws Exception
     */
    public void testDataTruncation() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TRUNC (si smallint, c char(4))");
        try {
            if (isSql65) {
                stmt.execute("SET ARITHABORT ON");
            }
            stmt.executeUpdate("INSERT INTO #TRUNC VALUES(100000, 'TEST')");
            fail("Expected data truncation exception");
        } catch (DataTruncation e) {
            // OK
        }
        if (!isSql65) {
            try {
                if (isSybase) {
                    stmt.execute("SET STRING_RTRUNCATION ON");
                }
                stmt.executeUpdate("INSERT INTO #TRUNC VALUES(100, 'TEST TO LONG')");
                fail("Expected data truncation exception");
            } catch (DataTruncation e) {
                // OK
            }
        }
    }
    
    /**
     * Test get/clear Warnings.
     * @throws Exception
     */
    public void testWarnings() throws Exception {
        Statement stmt = con.createStatement();
        stmt.clearWarnings();
        assertNull(stmt.getWarnings());
        stmt.execute("PRINT 'TEST WARNING'");
        assertEquals("TEST WARNING", stmt.getWarnings().getMessage().substring(0, 12));
        stmt.clearWarnings();
        assertNull(stmt.getWarnings());
        stmt.close();
    }
    
    /**
     * Test execution of methods on closed statememt.
     * @throws Exception
     */
    public void testClosed() throws Exception {
        Statement stmt = con.createStatement();
        stmt.close();
        String msg = "Invalid state, the Statement object is closed.";
        try {
            stmt.addBatch("");
            fail("Closed test fail-1");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.cancel();
            fail("Closed test fail-2");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.clearBatch();
            fail("Closed test fail-3");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.clearWarnings();
            fail("Closed test fail-4");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.execute("");
            fail("Closed test fail-5");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.executeBatch();
            fail("Closed test fail-6");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.executeQuery("");
            fail("Closed test fail-7");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.executeUpdate("");
            fail("Closed test fail-8");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getConnection();
            fail("Closed test fail-9");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getFetchDirection();
            fail("Closed test fail-10");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getFetchSize();
            fail("Closed test fail-11");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getMaxFieldSize();
            fail("Closed test fail-12");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getMaxRows();
            fail("Closed test fail-13");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getMoreResults();
            fail("Closed test fail-14");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getQueryTimeout();
            fail("Closed test fail-15");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getResultSet();
            fail("Closed test fail-16");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getResultSetConcurrency();
            fail("Closed test fail-17");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getResultSetType();
            fail("Closed test fail-18");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getUpdateCount();
            fail("Closed test fail-19");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.getWarnings();
            fail("Closed test fail-20");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.setCursorName("");
            fail("Closed test fail-21");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.setEscapeProcessing(false);
            fail("Closed test fail-22");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.setFetchDirection(ResultSet.FETCH_FORWARD);
            fail("Closed test fail-23");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.setFetchSize(1);
            fail("Closed test fail-24");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.setMaxFieldSize(0);
            fail("Closed test fail-25");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.setMaxRows(0);
            fail("Closed test fail-26");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            stmt.setQueryTimeout(0);
            fail("Closed test fail-27");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
    }

    /**
     * Test get holdability method
     * @throws Exception
     */
    public void testGetHoldability() throws Exception {
        Statement stmt;
        stmt = con.createStatement(ResultSet.TYPE_FORWARD_ONLY, 
                                   ResultSet.CONCUR_READ_ONLY, 
                                   ResultSet.HOLD_CURSORS_OVER_COMMIT);
        assertEquals(ResultSet.HOLD_CURSORS_OVER_COMMIT, 
                        stmt.getResultSetHoldability());
        stmt.close();
    }
    
    /**
     * Test get generated keys.
     * @throws Exception
     */
    public void testGenKeys() throws Exception {
        //
        // Test data
        //
        Statement stmt = con.createStatement();

        stmt.execute("CREATE TABLE #gktemp (id NUMERIC(10) IDENTITY PRIMARY KEY, dummyx VARCHAR(50))");

        stmt.close();
        //
        // Test Parameter validation
        //
        try {
            stmt.executeUpdate("INSERT ", 999);
            fail("Expected parameter error");
        } catch (SQLException e) {
            // ignore
        }
        try {
            stmt.execute("INSERT ", 999);
            fail("Expected parameter error");
        } catch (SQLException e) {
            // ignore
        }
        //
        // Test RETURN_GENERATED keys variant
        //
        stmt = con.createStatement();
        assertEquals("First Insert failed", 1,
                     stmt.executeUpdate("INSERT INTO #gktemp (dummyx) VALUES ('TEST04')",
                                        Statement.RETURN_GENERATED_KEYS));
        ResultSet rs = stmt.getGeneratedKeys();
        assertTrue("ResultSet 1 empty", rs.next());
        assertEquals("Bad inserted row ID ", 1, rs.getInt(1));
        rs.close();
        stmt.execute("INSERT INTO #gktemp (dummyx) VALUES ('TEST04')",
                                   Statement.RETURN_GENERATED_KEYS);
        assertEquals(1, stmt.getUpdateCount());
        rs = stmt.getGeneratedKeys();
        assertTrue("ResultSet 2 empty", rs.next());
        assertEquals("Bad inserted row ID ", 2, rs.getInt(1));
        rs.close();
        //
        // int[] variant
        //
        assertEquals("Third Insert failed", 1,
                stmt.executeUpdate("INSERT INTO #gktemp (dummyx) VALUES ('TEST04')",
                                   new int[]{1}));
        rs = stmt.getGeneratedKeys();
        assertTrue("ResultSet 3 empty", rs.next());
        assertEquals("Bad inserted row ID ", 3, rs.getInt(1));
        rs.close();
        stmt.execute("INSERT INTO #gktemp (dummyx) VALUES ('TEST04')",
                              new int[]{1});
        assertEquals(1, stmt.getUpdateCount());
        rs = stmt.getGeneratedKeys();
        assertTrue("ResultSet 4 empty", rs.next());
        assertEquals("Bad inserted row ID ", 4, rs.getInt(1));
        rs.close();
        //
        // String[] variant
        //
        assertEquals("Fith Insert failed", 1,
                stmt.executeUpdate("INSERT INTO #gktemp (dummyx) VALUES ('TEST04')",
                                   new String[]{"dummy"}));
        rs = stmt.getGeneratedKeys();
        assertTrue("ResultSet 5 empty", rs.next());
        assertEquals("Bad inserted row ID ", 5, rs.getInt(1));
        rs.close();
        stmt.execute("INSERT INTO #gktemp (dummyx) VALUES ('TEST04')",
                                    new String[]{"dummy"});
        assertEquals(1, stmt.getUpdateCount());
        rs = stmt.getGeneratedKeys();
        assertTrue("ResultSet 6 empty", rs.next());
        assertEquals("Bad inserted row ID ", 6, rs.getInt(1));
        rs.close();

        stmt.close();
    }

    /**
     * Test empty result set returned when no keys available.
     */
    public void testNoKeys() throws Exception {
        Statement stmt = con.createStatement();
        ResultSet rs = stmt.getGeneratedKeys();
        assertEquals("ID", rs.getMetaData().getColumnName(1));
        assertFalse(rs.next());
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(StatementTest.class);
    }
}
