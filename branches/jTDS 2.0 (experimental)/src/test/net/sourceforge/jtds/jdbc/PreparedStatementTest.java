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

import java.math.BigDecimal;
import java.sql.*;
import java.util.Calendar;
import java.util.TimeZone;
import java.io.ByteArrayInputStream;
import java.io.CharArrayReader;

/**
 * Test case to exercise the PreparedStatement class.
 *
 * @version    1.0
 */
public class PreparedStatementTest extends TestBase {
        
    public PreparedStatementTest(String name) {
        super(name);
    }

    /**
     * Test create all statement type concurrencies.
     * @throws Exception
     */
    public void testCreatePreparedStatement() throws Exception {
        PreparedStatement pstmt;
        //
        // Check bad params
        //
        try {
            pstmt = con.prepareStatement("SELECT 1", 
                                            999, 
                                                ResultSet.CONCUR_UPDATABLE);
            fail("Expected error bad type");
        } catch (SQLException e) {
            // Ignore
        }
        try {
            pstmt = con.prepareStatement("SELECT 1", 
                                            ResultSet.TYPE_FORWARD_ONLY, 
                                                999);
            fail("Expected error bad concurrency");
        } catch (SQLException e) {
            // Ignore
        }
        //
        // Default type / concurrency
        //
        pstmt = con.prepareStatement("SELECT 1");
        assertNotNull(pstmt);
        pstmt.close();
        //
        // Forward read only
        //
        pstmt = con.prepareStatement("SELECT 1", 
                                        ResultSet.TYPE_FORWARD_ONLY, 
                                            ResultSet.CONCUR_READ_ONLY);
        assertNotNull(pstmt);
        pstmt.close();
        //
        // Forward updateable
        //
        pstmt = con.prepareStatement("SELECT 1", 
                                        ResultSet.TYPE_FORWARD_ONLY, 
                                            ResultSet.CONCUR_UPDATABLE);
        assertNotNull(pstmt);
        pstmt.close();
        //
        // Scrollable read only
        //
        pstmt = con.prepareStatement("SELECT 1", 
                                        ResultSet.TYPE_SCROLL_INSENSITIVE, 
                                            ResultSet.CONCUR_READ_ONLY);
        assertNotNull(pstmt);
        pstmt.close();
        //
        // Scrollable updateable
        //
        pstmt = con.prepareStatement("SELECT 1", 
                                        ResultSet.TYPE_SCROLL_INSENSITIVE, 
                                            ResultSet.CONCUR_UPDATABLE);
        assertNotNull(pstmt);
        pstmt.close();
        //
        // Scrollable read only
        //
        pstmt = con.prepareStatement("SELECT 1", 
                                        ResultSet.TYPE_SCROLL_SENSITIVE, 
                                            ResultSet.CONCUR_READ_ONLY);
        assertNotNull(pstmt);
        pstmt.close();
        //
        // Scrollable updateable
        //
        pstmt = con.prepareStatement("SELECT 1", 
                                        ResultSet.TYPE_SCROLL_SENSITIVE, 
                                            ResultSet.CONCUR_UPDATABLE);
        assertNotNull(pstmt);
        pstmt.close();
        //
        // JDBC3 methods
        //
        pstmt = con.prepareStatement("SELECT 1", 
                ResultSet.TYPE_FORWARD_ONLY, 
                ResultSet.CONCUR_READ_ONLY, 
                ResultSet.HOLD_CURSORS_OVER_COMMIT);
        pstmt.close();
        //
        // Check bad params
        //
        try {
            pstmt = con.prepareStatement("SELECT 1", 
                    ResultSet.TYPE_FORWARD_ONLY, 
                    ResultSet.CONCUR_READ_ONLY, 
                    999);
            fail("Expected error bad Holdability");
        } catch (SQLException e) {
            // Ignore
        }
        pstmt.close();
    }
    
    /**
     * Test get type / concurrency.
     * @throws Exception
     */
    public void testGetTypeConcur() throws Exception {
        PreparedStatement pstmt = 
            con.prepareStatement("SELECT 1", 
                                    ResultSet.TYPE_SCROLL_INSENSITIVE, 
                                        ResultSet.CONCUR_UPDATABLE);
        assertNotNull(pstmt);
        assertEquals(ResultSet.TYPE_SCROLL_INSENSITIVE, pstmt.getResultSetType());
        assertEquals(ResultSet.CONCUR_UPDATABLE, pstmt.getResultSetConcurrency());
        pstmt.close();
        // Default type/concurrency
        pstmt = con.prepareStatement("SELECT 1");
        assertNotNull(pstmt);
        assertEquals(ResultSet.TYPE_FORWARD_ONLY, pstmt.getResultSetType());
        assertEquals(ResultSet.CONCUR_READ_ONLY, pstmt.getResultSetConcurrency());
        pstmt.close();
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
        stmt.execute(
             "CREATE TABLE #TESTBATCH (id int primary key, data varchar(255))");
        //
        PreparedStatement pstmt = 
            con.prepareStatement("INSERT INTO #TESTBATCH VALUES(?, ?)");
        pstmt.setInt(1, 1);
        pstmt.setString(2, "THIS WILL WORK");
        pstmt.addBatch();
        pstmt.setInt(1, 2);
        pstmt.setString(2, "AS WILL THIS");
        pstmt.addBatch();
        int counts[];
        counts = pstmt.executeBatch();
        assertEquals(2, counts.length);
        assertEquals(1, counts[0]);
        assertEquals(1, counts[1]);
        // Now with errors
        pstmt.setInt(1, 3);
        pstmt.setString(2, "THIS WILL WORK");
        pstmt.addBatch();
        pstmt.setInt(1, 1);
        pstmt.setString(2, "THIS WILL NOT");
        pstmt.addBatch();
        try {
            counts = pstmt.executeBatch();
            fail("Expected exec batch to fail");
        } catch (BatchUpdateException e) {
            counts = e.getUpdateCounts();
        }
        if (con.getMetaData().getDatabaseProductName().
                toLowerCase().startsWith("microsoft")) {
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
        assertEquals(0, pstmt.executeBatch().length);        
        //
        // Test clear batch
        //
        pstmt.addBatch();
        pstmt.clearBatch();
        assertEquals(0, pstmt.executeBatch().length);      
        pstmt.close();
        stmt.close();
    }

    /**
     * Get multiple generated keys from batch.
     * See RFE [1303257] getGeneratedKeys when using executeBatch
     * @throws Exception
     */
    public void testBatchGenKey() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TEST (id numeric(10) identity primary key, data varchar(255))");
        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #TEST (data) VALUES (?)", Statement.RETURN_GENERATED_KEYS);
        pstmt.setString(1, "TEST 1");
        pstmt.addBatch();
        pstmt.setString(1, "TEST 2");
        pstmt.addBatch();
        pstmt.setString(1, "TEST 3");
        pstmt.addBatch();
        int counts[] = pstmt.executeBatch();
        assertEquals(3, counts.length);
        assertEquals(1, counts[0]);
        assertEquals(1, counts[1]);
        assertEquals(1, counts[2]);
        ResultSet rs = pstmt.getGeneratedKeys();
        assertNotNull(rs);
        assertTrue(rs.next());
        assertEquals(1, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(2, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(3, rs.getInt(1));
        assertFalse(rs.next());
        pstmt.close();
        stmt.close();
    }

    /**
     * Test that excution of Statement only methods fails
     * @throws Exception
     */
    public void testStatementOnlyMethods() throws Exception {
        PreparedStatement pstmt = con.prepareStatement("SELECT 1");
        try {
            pstmt.execute("DUMMY");
            fail("Expected execute(sql) to fail");
        } catch (SQLException e) {
            assertTrue(e.getMessage().indexOf("method is not supported") >= 0);
        }
        try {
            pstmt.executeQuery("DUMMY");
            fail("Expected executeQuery(sql) to fail");
        } catch (SQLException e) {
            assertTrue(e.getMessage().indexOf("method is not supported") >= 0);
        }
        try {
            pstmt.executeUpdate("DUMMY");
            fail("Expected executeUpdate(sql) to fail");
        } catch (SQLException e) {
            assertTrue(e.getMessage().indexOf("method is not supported") >= 0);
        }
        try {
            pstmt.addBatch("DUMMY");
            fail("Expected addBatch(sql) to fail");
        } catch (SQLException e) {
            assertTrue(e.getMessage().indexOf("method is not supported") >= 0);
        }
    }
    
    /**
     * Test setting numeric parameters
     * @throws Exception
     */
    public void testSetNumericParams() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TESTSETNUM (ti tinyint, si smallint, i int, " + 
                      "r real, f float, sm smallmoney, m money, n numeric(28,10), "+ 
                      "d decimal(28,10))");
        PreparedStatement pstmt = con.prepareStatement(
                "INSERT INTO #TESTSETNUM VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        pstmt.setByte(1, (byte)123);
        pstmt.setShort(2, (short)12345);
        pstmt.setInt(3, 123456789);
        pstmt.setFloat(4, (float)12345.67);
        pstmt.setDouble(5, 1234567.89);
        pstmt.setBigDecimal(6, new BigDecimal("12345.6789"));
        pstmt.setBigDecimal(7, new BigDecimal("12345.6789"));
        pstmt.setBigDecimal(8, new BigDecimal("12345.678901"));
        pstmt.setBigDecimal(9, new BigDecimal("12345.678901"));
        assertEquals(1, pstmt.executeUpdate());
        pstmt.setObject(1, "123", Types.TINYINT);
        pstmt.setObject(2, "12345", Types.SMALLINT);
        pstmt.setObject(3, "123456789", Types.INTEGER);
        pstmt.setObject(4, "12345.67", Types.REAL);
        pstmt.setObject(5, "1234567.89", Types.FLOAT);
        pstmt.setObject(6, "12345.6789", Types.NUMERIC);
        pstmt.setObject(7, "12345.6789", Types.NUMERIC, 4);
        pstmt.setObject(8, "12345.678901", Types.NUMERIC, 6);
        pstmt.setObject(9, "12345.678901", Types.DECIMAL);
        assertEquals(1, pstmt.executeUpdate());
        ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTSETNUM");
        assertNotNull(rs);
        for (int i = 0; i < 2; i++) {
            assertTrue(rs.next());
            assertEquals(123, rs.getByte(1));
            assertEquals(12345, rs.getShort(2));
            assertEquals(123456789, rs.getInt(3));
            assertEquals((float)12345.67, rs.getFloat(4),(float)0.01);
            assertEquals(1234567.89, rs.getDouble(5),0.01);
            assertEquals("12345.6789", rs.getString(6));
            assertEquals("12345.6789", rs.getString(7));
            assertEquals("12345.6789010000", rs.getString(8));
            assertEquals("12345.6789010000", rs.getString(9));
        }
        pstmt.close();
        stmt.close();
    }
    
    /**
     * Test set string parameters
     * @throws Exception
     */
    public void testCharParams() throws Exception {
       String data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
       String hex = "4142434445464748494A4B4C4D4E4F505152535455565758595A";
       byte   ucData[] = new byte[26*2];
       for (int i = 0; i < 26; i++) {
           ucData[(i*2)+1] = (byte)data.charAt(i);
       }
       Statement stmt = con.createStatement();
       stmt.execute("CREATE TABLE #TESTSETCHAR (C VARCHAR(255))");
       PreparedStatement pstmt = 
           con.prepareStatement("INSERT INTO #TESTSETCHAR VALUES (?)");
       pstmt.setString(1, data);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setCharacterStream(1, new CharArrayReader(data.toCharArray()), 26);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setAsciiStream(1, new ByteArrayInputStream(data.getBytes()), 26);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setUnicodeStream(1, new ByteArrayInputStream(ucData), 26 * 2);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setObject(1, data.getBytes(), Types.VARCHAR);
       assertEquals(1, pstmt.executeUpdate());
       ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTSETCHAR");
       assertNotNull(rs);
       for (int i = 0; i < 5; i++) {
           assertTrue(rs.next());
           if (i < 4) {
               assertEquals(data, rs.getString(1));
           } else {
               assertEquals(hex, rs.getString(1));
           }
       }
       pstmt.close();
       stmt.close();
    }

    /**
     * Test set CLOB parameters
     * @throws Exception
     */
    public void testClobParams() throws Exception {
       int BUF_LEN = 20000;
       String data;
       StringBuffer tmp = new StringBuffer(BUF_LEN);
       for (int i = 0; i < BUF_LEN; i++) {
           tmp.append((char)('A' + (i%10)));
       }
       data = tmp.toString();
       byte   ucData[] = new byte[data.length()*2];
       for (int i = 0; i < BUF_LEN; i++) {
           ucData[(i*2)+1] = (byte)data.charAt(i);
       }
       Statement stmt = con.createStatement();
       stmt.execute("CREATE TABLE #TESTSETCHAR (C TEXT)");
       PreparedStatement pstmt = 
           con.prepareStatement("INSERT INTO #TESTSETCHAR VALUES (?)");
       pstmt.setString(1, data);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setCharacterStream(1, new CharArrayReader(data.toCharArray()), BUF_LEN);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setAsciiStream(1, new ByteArrayInputStream(data.getBytes()), BUF_LEN);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setUnicodeStream(1, new ByteArrayInputStream(ucData), BUF_LEN * 2);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setObject(1, data.getBytes(), Types.VARCHAR);
       assertEquals(1, pstmt.executeUpdate());
       ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTSETCHAR");
       assertNotNull(rs);
       for (int i = 0; i < 5; i++) {
           assertTrue(rs.next());
           if (i < 4) {
           	   assertEquals(data, rs.getString(1));
           } else {
           	   assertEquals("41424344", rs.getString(1).substring(0, 8)); 
           }
       }
       rs.close();
       rs = stmt.executeQuery("SELECT * FROM #TESTSETCHAR");
       assertNotNull(rs);
       assertTrue(rs.next());
       Clob clob = rs.getClob(1);
       assertEquals(data, clob.getSubString((long)1, (int)clob.length()));
       rs.close();
       assertEquals(5, stmt.executeUpdate("DELETE FROM #TESTSETCHAR"));
       pstmt.setClob(1, clob);
       assertEquals(1, pstmt.executeUpdate());
       rs.close();
       rs = stmt.executeQuery("SELECT * FROM #TESTSETCHAR");
       assertNotNull(rs);
       assertTrue(rs.next());
       assertEquals(data, rs.getString(1));
       pstmt.close();
       stmt.close();
    }

    /**
     * Test set byte parameters
     * @throws Exception
     */
    public void testByteParams() throws Exception {
       byte data[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes();
       Statement stmt = con.createStatement();
       stmt.execute("CREATE TABLE #TESTSETBIN (C VARBINARY(255))");
       PreparedStatement pstmt = 
           con.prepareStatement("INSERT INTO #TESTSETBIN VALUES (?)");
       pstmt.setBytes(1, data);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setBinaryStream(1, new ByteArrayInputStream(data), 26);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setObject(1, new String(data), Types.VARBINARY);
       assertEquals(1, pstmt.executeUpdate());
       ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTSETBIN");
       assertNotNull(rs);
       for (int i = 0; i < 3; i++) {
           assertTrue(rs.next());
           assertEquals(new String(data), new String(rs.getBytes(1)));
       }
       pstmt.close();
       stmt.close();
    }

    /**
     * Test set BLOB parameters
     * @throws Exception
     */
    public void testBlobParams() throws Exception {
       int BUF_LEN = 20000;
       byte data[];
       StringBuffer tmp = new StringBuffer(BUF_LEN);
       for (int i = 0; i < BUF_LEN; i++) {
           tmp.append((char)('A' + (i%10)));
       }
       data = tmp.toString().getBytes();
       Statement stmt = con.createStatement();
       stmt.execute("CREATE TABLE #TESTSETBIN (i IMAGE)");
       PreparedStatement pstmt = 
           con.prepareStatement("INSERT INTO #TESTSETBIN VALUES (?)");
       pstmt.setBytes(1, data);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setBinaryStream(1, new ByteArrayInputStream(data), BUF_LEN);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setObject(1, new String(data), Types.LONGVARBINARY);
       assertEquals(1, pstmt.executeUpdate());
       ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTSETBIN");
       assertNotNull(rs);
       for (int i = 0; i < 3; i++) {
           assertTrue(rs.next());
           assertEquals(new String(data), new String(rs.getBytes(1)));
       }
       rs.close();
       rs = stmt.executeQuery("SELECT * FROM #TESTSETBIN");
       assertNotNull(rs);
       assertTrue(rs.next());
       Blob blob = rs.getBlob(1);
       assertEquals(new String(data), 
                       new String(blob.getBytes((long)1, 
                               (int)blob.length())));
       rs.close();
       assertEquals(3, stmt.executeUpdate("DELETE FROM #TESTSETBIN"));
       pstmt.setBlob(1, blob);
       assertEquals(1, pstmt.executeUpdate());
       rs.close();
       rs = stmt.executeQuery("SELECT * FROM #TESTSETBIN");
       assertNotNull(rs);
       assertTrue(rs.next());
       assertEquals(new String(data), new String(rs.getBytes(1)));
       pstmt.close();
       stmt.close();
    }
    
    /**
     * Test set boolean parameters
     * @throws Exception
     */
    public void testBoolParams() throws Exception {
       Statement stmt = con.createStatement();
       stmt.execute("CREATE TABLE #TESTSETBIT (B BIT NOT NULL)");
       PreparedStatement pstmt = 
           con.prepareStatement("INSERT INTO #TESTSETBIT VALUES (?)");
       pstmt.setBoolean(1, true);
       assertEquals(1, pstmt.executeUpdate());
       pstmt.setObject(1, "1", Types.BIT);
       assertEquals(1, pstmt.executeUpdate());
       ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTSETBIT");
       assertNotNull(rs);
       for (int i = 0; i < 2; i++) {
           assertTrue(rs.next());
           assertTrue(rs.getBoolean(1));
       }
       pstmt.close();
       stmt.close();
    }
    
    /**
     * Test set date / time parameters
     * @throws Exception
     */
    public void testDateTime() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TESTDT (d1 datetime, d2 smalldatetime)");
        PreparedStatement pstmt = 
            con.prepareStatement("INSERT INTO #TESTDT VALUES(?, ?)");
        // Using date/time methods
        pstmt.setTime(1, Time.valueOf("23:59:59"));
        // NB. smalldatetime rounded to nearest minute.
        pstmt.setTime(2, Time.valueOf("23:59:00"));
        assertEquals(1, pstmt.executeUpdate());
        pstmt.setDate(1, Date.valueOf("1970-01-01"));
        pstmt.setDate(2, Date.valueOf("1999-12-31"));
        assertEquals(1, pstmt.executeUpdate());
        Timestamp ts = Timestamp.valueOf("1999-01-01 23:59:10.123");
        pstmt.setTimestamp(1, ts);
        pstmt.setTimestamp(2, ts);
        assertEquals(1, pstmt.executeUpdate());
        // With set Object
        pstmt.setObject(1, "23:59:59", Types.TIME);
        // NB. smalldatetime rounded to nearest minute.
        pstmt.setObject(2, "23:59:00", Types.TIME);
        assertEquals(1, pstmt.executeUpdate());
        pstmt.setObject(1, "1970-01-01", Types.DATE);
        pstmt.setObject(2, "1999-12-31", Types.DATE);
        assertEquals(1, pstmt.executeUpdate());
        pstmt.setObject(1, "1999-01-01 23:59:10.123", Types.TIMESTAMP);
        pstmt.setObject(2, "1999-01-01 23:59:10.123", Types.TIMESTAMP);
        assertEquals(1, pstmt.executeUpdate());
        // With timezone
        Calendar calNY = 
            Calendar.getInstance(TimeZone.getTimeZone("America/New_York"));
        pstmt.setTime(1, Time.valueOf("12:00:00"), calNY);
        pstmt.setTime(2, Time.valueOf("12:00:00"), calNY);
        assertEquals(1, pstmt.executeUpdate());
        pstmt.setDate(1, Date.valueOf("1999-12-31"), calNY);
        pstmt.setDate(2, Date.valueOf("2000-01-01"), calNY);
        assertEquals(1, pstmt.executeUpdate());
        pstmt.setTimestamp(1, ts, calNY);
        pstmt.setTimestamp(2, ts, calNY);
        assertEquals(1, pstmt.executeUpdate());
        //
        // Now read back
        //
        ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTDT");
        assertNotNull(rs);
        // Time
        assertTrue(rs.next());
        assertEquals("23:59:59", rs.getTime(1).toString());
        assertEquals("23:59:00", rs.getTime(2).toString());
        // Date
        assertTrue(rs.next());
        assertEquals("1970-01-01", rs.getDate(1).toString());
        assertEquals("1999-12-31", rs.getDate(2).toString());
        // Timestamp
        assertTrue(rs.next());
        if (isASA) {
            assertEquals("1999-01-01 23:59:10.12", rs.getString(1));
        } else {
            assertEquals("1999-01-01 23:59:10.123", rs.getString(1));
        }
        assertEquals("1999-01-01 23:59:00.0", rs.getString(2));
        // and again from setObject
        // Time
        assertTrue(rs.next());
        assertEquals("23:59:59", rs.getTime(1).toString());
        assertEquals("23:59:00", rs.getTime(2).toString());
        // Date
        assertTrue(rs.next());
        assertEquals("1970-01-01", rs.getDate(1).toString());
        assertEquals("1999-12-31", rs.getDate(2).toString());
        // Timestamp
        assertTrue(rs.next());
        if (isASA) {
            assertEquals("1999-01-01 23:59:10.12", rs.getString(1));
        } else {
            assertEquals("1999-01-01 23:59:10.123", rs.getString(1));
        }
        assertEquals("1999-01-01 23:59:00.0", rs.getString(2));        
        // Time with time zone set
        assertTrue(rs.next());
        assertEquals("12:00:00", rs.getTime(1, calNY).toString());
        assertEquals("12:00:00", rs.getTime(2, calNY).toString());
        // Date with time zone set
        assertTrue(rs.next());
        assertEquals("1999-12-30", rs.getDate(1, calNY).toString());
        assertEquals("1999-12-31", rs.getDate(2, calNY).toString());
        // Timestamp with time zone set
        assertTrue(rs.next());
        if (isASA) {
            assertEquals("1999-01-01 23:59:10.12", rs.getTimestamp(1, calNY).toString());
        } else {
            assertEquals("1999-01-01 23:59:10.123", rs.getTimestamp(1, calNY).toString());
        }
        assertEquals("1999-01-01 23:59:00.0", rs.getTimestamp(2, calNY).toString());
        pstmt.close();
        stmt.close();
    }

    /**
     * Test set null
     * @throws Exception
     */
    public void testSetNull() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TESTNUL (id int null, n varchar(10) null)");
        PreparedStatement pstmt = 
            con.prepareStatement("INSERT INTO #TESTNUL VALUES(?, ?)");
        pstmt.setNull(1, Types.INTEGER);
        pstmt.setNull(2, Types.VARCHAR);
        assertEquals(1, pstmt.executeUpdate());
        pstmt.setInt(1, 2);
        pstmt.setString(2, null);
        assertEquals(1, pstmt.executeUpdate());
        //
        // Now read back
        //
        ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTNUL");
        assertNotNull(rs);
        assertTrue(rs.next());
        assertEquals(0, rs.getInt(1));
        assertTrue(rs.wasNull());
        assertNull(rs.getString(2));
        assertTrue(rs.next());
        assertEquals(2, rs.getInt(1));
        assertFalse(rs.wasNull());
        assertNull(rs.getString(2));
        pstmt.close();
        stmt.close();
    }
    
    /**
     * Test getMetaData
     * @throws Exception
     */
    public void testGetMetaData() throws Exception {
        PreparedStatement pstmt = 
            con.prepareStatement("SELECT name from master..sysdatabases where name not like ?");
        pstmt.setString(1, "tempdb");
        ResultSetMetaData rsmd = pstmt.getMetaData();
        assertNotNull(rsmd);
        assertEquals(1, rsmd.getColumnCount());
        assertTrue(rsmd.getColumnType(1) == Types.VARCHAR);
        pstmt.close();
    }
    
    /**
     * Test clearparams and unset params.
     * @throws Exception
     */
    public void testClearParams() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TESTCP (id int null, n varchar(10) null)");
        PreparedStatement pstmt = 
            con.prepareStatement("INSERT INTO #TESTCP VALUES(?, ?)");
        pstmt.setInt(1, 1);
        pstmt.setString(2, "TEST");
        assertEquals(1, pstmt.executeUpdate());
        pstmt.clearParameters();
        try {
            pstmt.executeUpdate();
            fail("Expected unset parameters exception");
        } catch (SQLException e) {
            // Parameters not set exception
        }
    }
    
    /**
     * Test execution of methods on closed statememt.
     * @throws Exception
     */
    public void testClosed() throws Exception {
        PreparedStatement pstmt = con.prepareStatement("SELECT ?");
        pstmt.close();
        String msg = "Invalid state, the PreparedStatement object is closed.";
        try {
            pstmt.addBatch();
            fail("Closed test fail-1");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            pstmt.execute();
            fail("Closed test fail-2");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            pstmt.executeQuery();
            fail("Closed test fail-3");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            pstmt.executeUpdate();
            fail("Closed test fail-4");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
        try {
            pstmt.setObject(1, null, Types.NULL);
            fail("Closed test fail-5");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
    }
        
    public void testGenKeys() throws Exception {
        //
        // Test data
        //
        Statement stmt = con.createStatement();

        stmt.execute("CREATE TABLE #gktemp (id NUMERIC IDENTITY PRIMARY KEY, dummyx VARCHAR(50))");

        stmt.close();
        //
        // Test PrepareStatement(sql, int) option
        //
        PreparedStatement pstmt =
            con.prepareStatement("INSERT INTO #gktemp (dummyx) VALUES (?)", 
                                    Statement.RETURN_GENERATED_KEYS);
        pstmt.setString(1, "TEST01");
        assertEquals("First Insert failed", 1, pstmt.executeUpdate());
        ResultSet rs = pstmt.getGeneratedKeys();
        assertTrue("ResultSet empty", rs.next());
        assertEquals("Bad inserted row ID ", 1, rs.getInt(1));
        rs.close();
        pstmt.close();
        //
        // Test PrepareStatement(sql, int[]) option
        //
        pstmt =
            con.prepareStatement("INSERT INTO #gktemp (dummyx) VALUES (?)", 
                                     new int[]{1});
        pstmt.setString(1, "TEST02");
        assertEquals("Second Insert failed", 1, pstmt.executeUpdate());
        rs = pstmt.getGeneratedKeys();
        assertTrue("ResultSet 2 empty", rs.next());
        assertEquals("Bad inserted row ID ", 2, rs.getInt(1));
        rs.close();
        pstmt.close();
        //
        // Test PrepareStatement(sql, String[]) option
        //
        String colNames[] = new String[1];
        colNames[0] = "ID";
        pstmt =
            con.prepareStatement("INSERT INTO #gktemp (dummyx) VALUES (?)", 
                                    new String[]{"dummu"});
        pstmt.setString(1, "TEST03");
        pstmt.execute();
        assertEquals("Third Insert failed", 1, pstmt.getUpdateCount());
        rs = pstmt.getGeneratedKeys();
        assertTrue("ResultSet 3 empty", rs.next());
        assertEquals("Bad inserted row ID ", 3, rs.getInt(1));
        rs.close();
        pstmt.close();
    }
    
    /**
     * Test for bug [930305] getGeneratedKeys() does not work with triggers
     */
    public void testTrigger1() throws Exception {
        try {
            dropTable("jtdsTestTrigger1");
            dropTable("jtdsTestTrigger2");
            Statement stmt = con.createStatement();
            stmt.execute("CREATE TABLE jtdsTestTrigger1 (id NUMERIC(10) IDENTITY PRIMARY KEY, data INT)");
            stmt.execute("CREATE TABLE jtdsTestTrigger2 (id NUMERIC(10) IDENTITY PRIMARY KEY, data INT)");
            stmt.close();

            stmt = con.createStatement();
            stmt.execute("CREATE TRIGGER testTrigger1 ON jtdsTestTrigger1 FOR INSERT AS "
                    + "INSERT INTO jtdsTestTrigger2 (data) VALUES (1)");
            stmt.close();

            PreparedStatement pstmt = con.prepareStatement(
                    "INSERT INTO jtdsTestTrigger1 (data) VALUES (?)",
                    Statement.RETURN_GENERATED_KEYS);

            for (int i = 0; i < 10; i++) {
                pstmt.setInt(1, i);
                assertEquals("Insert failed: " + i, 1, pstmt.executeUpdate());

                ResultSet rs = pstmt.getGeneratedKeys();

                assertTrue("ResultSet empty: " + i, rs.next());
                assertEquals("Bad inserted row ID: " + i, i + 1, rs.getInt(1));
                assertTrue("ResultSet not empty: " + i, !rs.next());
                rs.close();
            }

            pstmt.close();
        } finally {
            dropTable("jtdsTestTrigger1");
            dropTable("jtdsTestTrigger2");
        }
    }

    /**
     * Test that SELECT statements work correctly with
     * <code>PreparedStatement</code>s created with
     * <code>RETURN_GENERATED_KEYS</code>.
     */
    public void testSelect() throws SQLException {
        Statement stmt = con.createStatement();
        stmt.executeUpdate("create table #colors (id int, color varchar(255))");
        stmt.executeUpdate("insert into #colors values (1, 'red')");
        stmt.executeUpdate("insert into #colors values (1, 'green')");
        stmt.executeUpdate("insert into #colors values (1, 'blue')");
        stmt.close();

        PreparedStatement pstmt = con.prepareStatement(
                "select * from #colors", Statement.RETURN_GENERATED_KEYS);
        assertTrue(pstmt.execute());
        ResultSet rs = pstmt.getResultSet();
        assertEquals(2, rs.getMetaData().getColumnCount());
        assertTrue(rs.next());
        assertTrue(rs.next());
        assertTrue(rs.next());
        assertFalse(rs.next());
        rs.close();
        assertFalse(pstmt.getMoreResults());
        assertEquals(-1, pstmt.getUpdateCount());

        rs = pstmt.executeQuery();
        assertEquals(2, rs.getMetaData().getColumnCount());
        assertTrue(rs.next());
        assertTrue(rs.next());
        assertTrue(rs.next());
        assertFalse(rs.next());
        rs.close();
        pstmt.close();
    }

    /**
     * Test get parameter meta data
     */
    public void testGetParamMetaData() throws SQLException {
        PreparedStatement pstmt = con.prepareStatement("SELECT ?,?,?");
        ParameterMetaData pmd = pstmt.getParameterMetaData();
        pstmt.setString(1, "TEST");
        pstmt.setBigDecimal(2, new BigDecimal("123.45"));
        pstmt.setBoolean(3, true);
        assertEquals(3, pmd.getParameterCount());
        assertEquals(Types.VARCHAR, pmd.getParameterType(1));
        assertEquals("java.lang.String", pmd.getParameterClassName(1));
//        assertEquals("varchar", pmd.getParameterTypeName(1));
        assertEquals(2, pmd.getScale(2));
        if (isSql70 || isSql65) {
            assertEquals(28, pmd.getPrecision(2));
        } else {
            assertEquals(38, pmd.getPrecision(2));
        }
        assertEquals(ParameterMetaData.parameterModeIn, 
                       pmd.getParameterMode(3));
    }
    
    
    public static void main(String[] args) {
        junit.textui.TestRunner.run(PreparedStatementTest.class);
    }
}
