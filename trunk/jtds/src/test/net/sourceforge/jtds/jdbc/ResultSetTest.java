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

import java.io.ByteArrayInputStream;
import java.io.CharArrayReader;
import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;

import net.sourceforge.jtds.jdbc.BlobImpl;
import net.sourceforge.jtds.jdbc.ClobImpl;

/**
 * Test case to exercise result set
 *
 * @version    1.0
 */
public class ResultSetTest extends TestBase {

    public ResultSetTest(String name) {
        super(name);
    }
    
    /**
     * Test get value Methods.
     * @throws Exception
     */
    public void testGetMethods() throws Exception
    {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TESTRS ("+
                "ti tinyint not null, si smallint not null, "+
                "i int not null, r real not null, f float not null, "+
                "m money not null, " + 
                "sm smallmoney not null, n numeric(28,10) not null, "+
                "d decimal(28,10) not null, "+
                "dt datetime not null, sdt smalldatetime not null," +
                "c char(10) not null, vc varchar(255) not null, " + 
                "b binary(8) not null, vb varbinary(255) not null, " +
                "txt text not null, img image not null, bt bit not null)");
        assertEquals(1, stmt.executeUpdate(
                "INSERT INTO #TESTRS VALUES( 123, 12345, 12345678," +
                "12345.67, 1234567.89, 12345.6789, 12345.6789, "+
                "1234567.89, 1234567.89," +
                "'1999-12-31 23:59:59.123', '2000-01-01 12:30:00'," +
                "'ABCD', 'ABCDEFGHIJ', 0x4142434445464748, 0x41424344, " +
                "'TEXT FIELD', 0x41424344, 1)"));
        ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTRS");
        assertNotNull(rs);
        //
        // Read back with matching type
        //
        assertTrue(rs.next());
        assertEquals(123, rs.getByte("ti"));
        assertEquals((short)12345, rs.getShort("si"));
        assertEquals(12345678, rs.getInt("i"));
        assertEquals("12345.67", Float.toString(rs.getFloat("r")));
        assertEquals("1234567.89", Double.toString(rs.getDouble("f")));
        assertEquals("12345.6789", rs.getBigDecimal("m").toString());
        assertEquals("12345.6789", rs.getBigDecimal("sm").toString());
        assertEquals("1234567.8900000000", rs.getBigDecimal("n").toString());
        assertEquals("1234567.89", rs.getBigDecimal("d", 2).toString());
        if (isASA) {
            assertEquals("1999-12-31 23:59:59.12", rs.getTimestamp("dt").toString());
        } else {
            assertEquals("1999-12-31 23:59:59.123", rs.getTimestamp("dt").toString());
        }
        assertEquals("2000-01-01 12:30:00.0", rs.getTimestamp("sdt").toString());
        assertEquals("2000-01-01", rs.getDate("sdt").toString());
        assertEquals("12:30:00", rs.getTime("sdt").toString());
        assertEquals("ABCD", rs.getString("c").trim());
        assertEquals("ABCDEFGHIJ", rs.getString("vc"));
        InputStream is = rs.getAsciiStream("vc");
        assertNotNull(is);
        byte tst[] = new byte[11];
        tst[10] = 'Z';
        assertEquals(10, is.read(tst));
        assertEquals("ABCDEFGHIJZ", new String(tst));
        assertEquals("ABCDEFGH", new String(rs.getBytes("b")));
        assertEquals("ABCD", new String(rs.getBytes("vb")));
        
        is = rs.getBinaryStream("vb");
        assertNotNull(is);
        tst[0] = 0;
        assertEquals(4, is.read(tst));
        assertEquals("ABCDEFGHIJZ", new String(tst));
        assertEquals("TEXT FIELD", rs.getString("txt"));
        
        Reader cr = rs.getCharacterStream("txt");
        assertNotNull(cr);
        char buf[] = new char[11];
        buf[10] = 'Z';
        assertEquals(10, cr.read(buf));
        assertEquals("TEXT FIELDZ", new String(buf));
        
        is = rs.getUnicodeStream("txt");
        assertNotNull(cr);
        tst = new byte[22];
        tst[21] = 'Z';
        assertEquals(20, is.read(tst));
        StringBuffer txtBuf = new StringBuffer();
        for (int i = 1; i < tst.length; i += 2) {
            txtBuf.append((char)tst[i]);
        }
        assertEquals("TEXT FIELDZ", txtBuf.toString());

        assertEquals("TEXT FIELD", rs.getClob("txt").getSubString(1L, (int)rs.getClob("txt").length()));
        assertEquals("ABCD", new String(rs.getBytes("img")));
        assertEquals("ABCD", new String(rs.getBlob("img").getBytes(1L, (int)rs.getBlob("img").length())));
        assertTrue(rs.getBoolean("bt"));
        //
        // Read back converted to string
        //
        assertEquals("123", rs.getString(1));
        assertEquals("12345", rs.getString(2));
        assertEquals("12345678", rs.getString(3));
        assertEquals("12345.67", rs.getString(4));
        assertEquals("1234567.89", rs.getString(5));
        assertEquals("12345.6789", rs.getString(6));
        assertEquals("12345.6789", rs.getString(7));
        assertEquals("1234567.8900000000", rs.getString(8));
        assertEquals("1234567.8900000000", rs.getString(9));
        if (isASA) {
            assertEquals("1999-12-31 23:59:59.12", rs.getString(10));
        } else {
            assertEquals("1999-12-31 23:59:59.123", rs.getString(10));
        }
        assertEquals("2000-01-01 12:30:00.0", rs.getString(11));
        assertEquals("ABCD", rs.getString(12).trim());
        assertEquals("ABCDEFGHIJ", rs.getString(13));
        assertEquals("4142434445464748", rs.getString(14));
        assertEquals("41424344", rs.getString(15));
        assertEquals("TEXT FIELD", rs.getString(16));
        assertEquals("41424344", rs.getString(17));
        assertEquals("1", rs.getString(18));
        //
        // Check find column works
        //
        assertEquals(18, rs.findColumn("bt"));
        rs.close();
        stmt.close();
    }

    /**
     * Test get value Methods returning nulls.
     * @throws Exception
     */
    public void testGetNulls() throws Exception
    {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TESTRS (ti tinyint null, si smallint null, "+
                      "i int null, r real null, f float null, m money null, " + 
                      "sm smallmoney null, n numeric(28,10) null, "+
                      "d decimal(28,10) null, "+
                      "dt datetime null, sdt smalldatetime null," +
                      "c char(10) null, vc varchar(255) null, " + 
                      "b binary(8) null, vb varbinary(255) null, " +
                      "txt text null, img image null)");
        assertEquals(1, stmt.executeUpdate(
                "INSERT INTO #TESTRS VALUES( 123, 12345, 12345678," +
                "12345.67, 1234567.89, 12345.6789, 12345.6789, "+
                "1234567.89, 1234567.89," +
                "'1999-12-31 23:59:59.123', '2000-01-01 12:30:00'," +
                "'ABCD', 'ABCDEFGHIJ', 0x4142434445464748, 0x41424344, " +
                "'TEXT FIELD', 0x41424344)"));
        assertEquals(1, stmt.executeUpdate(
                "INSERT INTO #TESTRS VALUES( null, null, null," +
                "null, null, null, null, "+
                "null, null," +
                "null, null," +
                "null, null, null, null, " +
                "null, null)"));
        ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTRS");
        assertNotNull(rs);
        //
        // Read back non null values
        //
        assertTrue(rs.next());
        assertEquals(123, rs.getByte("ti"));
        assertFalse(rs.wasNull());
        assertEquals((short)12345, rs.getShort("si"));
        assertFalse(rs.wasNull());
        assertEquals(12345678, rs.getInt("i"));
        assertFalse(rs.wasNull());
        assertEquals("12345.67", Float.toString(rs.getFloat("r")));
        assertFalse(rs.wasNull());
        assertEquals("1234567.89", Double.toString(rs.getDouble("f")));
        assertFalse(rs.wasNull());
        assertEquals("12345.6789", rs.getBigDecimal("m").toString());
        assertFalse(rs.wasNull());
        assertEquals("12345.6789", rs.getBigDecimal("sm").toString());
        assertFalse(rs.wasNull());
        assertEquals("1234567.8900000000", rs.getBigDecimal("n").toString());
        assertFalse(rs.wasNull());
        assertEquals("1234567.8900000000", rs.getBigDecimal("d").toString());
        assertFalse(rs.wasNull());
        if (isASA) {
            assertEquals("1999-12-31 23:59:59.12", rs.getTimestamp("dt").toString());
        } else {
            assertEquals("1999-12-31 23:59:59.123", rs.getTimestamp("dt").toString());
        }
        assertFalse(rs.wasNull());
        assertEquals("2000-01-01 12:30:00.0", rs.getTimestamp("sdt").toString());
        assertFalse(rs.wasNull());
        assertEquals("2000-01-01", rs.getDate("sdt").toString());
        assertFalse(rs.wasNull());
        assertEquals("12:30:00", rs.getTime("sdt").toString());
        assertFalse(rs.wasNull());
        assertEquals("ABCD", rs.getString("c").trim());
        assertFalse(rs.wasNull());
        assertEquals("ABCDEFGHIJ", rs.getString("vc"));
        assertFalse(rs.wasNull());
        assertEquals("ABCDEFGH", new String(rs.getBytes("b")));
        assertFalse(rs.wasNull());
        assertEquals("ABCD", new String(rs.getBytes("vb")));
        assertFalse(rs.wasNull());
        assertEquals("TEXT FIELD", rs.getString("txt"));
        assertFalse(rs.wasNull());
        assertEquals("TEXT FIELD", rs.getClob("txt").getSubString(1L, (int)rs.getClob("txt").length()));
        assertFalse(rs.wasNull());
        assertEquals("ABCD", new String(rs.getBytes("img")));
        assertFalse(rs.wasNull());
        assertEquals("ABCD", new String(rs.getBlob("img").getBytes(1L, (int)rs.getBlob("img").length())));
        assertFalse(rs.wasNull());
        //
        // Read back null values
        //
        assertTrue(rs.next());
        assertEquals(0, rs.getByte("ti"));
        assertTrue(rs.wasNull());
        assertEquals(0, rs.getShort("si"));
        assertTrue(rs.wasNull());
        assertEquals(0, rs.getInt("i"));
        assertTrue(rs.wasNull());
        assertEquals("0.0", Float.toString(rs.getFloat("r")));
        assertTrue(rs.wasNull());
        assertEquals("0.0", Double.toString(rs.getDouble("f")));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getBigDecimal("m"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getBigDecimal("sm"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getBigDecimal("n"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getBigDecimal("d"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getTimestamp("dt"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getTimestamp("sdt"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getDate("sdt"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getTime("sdt"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getString("c"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getString("vc"));
        assertEquals(null, rs.getAsciiStream("vc"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getBytes("b"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getBytes("vb"));
        assertEquals(null, rs.getBinaryStream("VB"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getString("txt"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getCharacterStream("txt"));
        assertEquals(null, rs.getClob("txt"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getBytes("img"));
        assertTrue(rs.wasNull());
        assertEquals(null, rs.getBlob("img"));
        assertTrue(rs.wasNull());
        rs.close();
        stmt.close();
    }
    
    /**
     * Test update methods
     * @throws Exception
     */
    public void testUpdateMethods() throws Exception {
        if (isASA) {
            // No cursor updates
            return;
        }
        try {
            dropTable("jTDS_TESTRS");
            Statement stmt = con.createStatement();
            stmt.execute("CREATE TABLE jTDS_TESTRS (ti tinyint not null primary key, si smallint null, "+
                          "i int null, r real null, f float null, m money null, " + 
                          "sm smallmoney null, n numeric(28,10) null, "+
                          "d decimal(28,10) null, "+
                          "dt datetime null, sdt smalldatetime null," +
                          "c char(10) null, vc varchar(255) null, " + 
                          "b binary(8) null, vb varbinary(255) null, " +
                          "txt text null, img image null, bt bit not null)");
            assertEquals(1, stmt.executeUpdate(
                    "INSERT INTO jTDS_TESTRS VALUES( 123, null, null," +
                    "null, null, null, null, "+
                    "null, null," +
                    "null, null," +
                    "null, null, null, null, " +
                    "' ', 0x00, 0)"));
            stmt = con.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_UPDATABLE+1);
            ResultSet rs = stmt.executeQuery("SELECT * FROM jTDS_TESTRS");
            assertEquals(ResultSet.TYPE_FORWARD_ONLY, rs.getType());
            assertEquals(ResultSet.CONCUR_UPDATABLE+1, rs.getConcurrency());
            assertTrue(rs.next());
            //
            // Save Blob/Clob for later
            //
            Blob blob = rs.getBlob("img");
            Clob clob = rs.getClob("txt");
            // Update existing row
            rs.updateByte("ti", (byte)1);
            rs.updateShort("si", (short)12345);
            rs.updateInt("i", 12345678);
            rs.updateFloat("r", 12345.67f);
            rs.updateDouble("f", 1234567.89);
            rs.updateBigDecimal("m", new BigDecimal("12345.6789"));
            rs.updateBigDecimal("sm", new BigDecimal("12345.6789"));
            rs.updateBigDecimal("n", new BigDecimal("1234567.89"));
            rs.updateBigDecimal("d", new BigDecimal("1234567.89"));
            rs.updateTimestamp("dt", Timestamp.valueOf("1999-12-31 23:59:59.123"));
            rs.updateTimestamp("sdt", Timestamp.valueOf("2000-01-01 12:30:00"));
            rs.updateString("c", "ABCD");
            rs.updateString("vc", "ABCDEFGHIJ");
            rs.updateBytes("b", "ABCDEFGH".getBytes());
            rs.updateBytes("vb", "ABCD".getBytes());
            rs.updateString("txt", "TEXT FIELD");
            rs.updateBytes("img", "ABCD".getBytes());
            rs.updateBoolean("bt", true);
            rs.updateRow();
            // Insert additional row
            rs.moveToInsertRow();
            rs.updateByte("ti", (byte)2);
            rs.updateShort("si", (short)12345);
            rs.updateInt("i", 12345678);
            rs.updateFloat("r", 12345.67f);
            rs.updateDouble("f", 1234567.89);
            rs.updateBigDecimal("m", new BigDecimal("12345.6789"));
            rs.updateBigDecimal("sm", new BigDecimal("12345.6789"));
            rs.updateBigDecimal("n", new BigDecimal("1234567.89"));
            rs.updateBigDecimal("d", new BigDecimal("1234567.89"));
            rs.updateTimestamp("dt", Timestamp.valueOf("1999-12-31 23:59:59.123"));
            rs.updateTimestamp("sdt", Timestamp.valueOf("2000-01-01 12:30:00"));
            rs.updateString("c", "ABCD");
            rs.updateString("vc", "ABCDEFGHIJ");
            rs.updateBytes("b", "ABCDEFGH".getBytes());
            rs.updateBytes("vb", "ABCD".getBytes());
            rs.updateString("txt", "TEXT FIELD");
            rs.updateBytes("img", "ABCD".getBytes());
            rs.updateBoolean("bt", false);
            rs.insertRow();
            // Insert row with streams etc
            rs.updateByte("ti", (byte)3);
            rs.updateShort("si", (short)12345);
            rs.updateInt("i", 12345678);
            rs.updateFloat("r", 12345.67f);
            rs.updateDouble("f", 1234567.89);
            rs.updateObject("m", new BigDecimal("12345.6789"));
            rs.updateBigDecimal("sm", new BigDecimal("12345.6789"));
            rs.updateBigDecimal("n", new BigDecimal("1234567.89"));
            rs.updateBigDecimal("d", new BigDecimal("1234567.89"));
            rs.updateTimestamp("dt", Timestamp.valueOf("1999-12-31 23:59:59.123"));
            rs.updateTimestamp("sdt", Timestamp.valueOf("2000-01-01 12:30:00"));
            rs.updateAsciiStream("c", new ByteArrayInputStream("ABCD".getBytes()), 4);
            rs.updateCharacterStream("vc", new CharArrayReader("ABCDEFGHIJ".toCharArray()), 10);
            rs.updateBinaryStream("b", new ByteArrayInputStream("ABCDEFGH".getBytes()), 8);
            rs.updateBytes("vb", "ABCD".getBytes());
            ((ClobImpl)clob).setString(1, "TEXT FIELD");
            rs.updateClob("txt", clob);
            ((BlobImpl)blob).setBytes(1, "ABCD".getBytes());
            rs.updateBlob("img", blob);
            rs.updateBoolean("bt", false);
            rs.insertRow();
            
            rs.close();
            // Read back and check
            rs = stmt.executeQuery("SELECT * FROM jTDS_TESTRS ORDER BY ti");
            assertNotNull(rs);
            for (int row = 1; row <= 3; row++) {
                assertTrue(rs.next());
                assertEquals(row, rs.getByte("ti"));
                assertEquals((short)12345, rs.getShort("si"));
                assertEquals(12345678, rs.getInt("i"));
                assertEquals("12345.67", Float.toString(rs.getFloat("r")));
                assertEquals("1234567.89", Double.toString(rs.getDouble("f")));
                assertEquals("12345.6789", rs.getBigDecimal("m").toString());
                assertEquals("12345.6789", rs.getBigDecimal("sm").toString());
                assertEquals("1234567.8900000000", rs.getBigDecimal("n").toString());
                assertEquals("1234567.89", rs.getBigDecimal("d", 2).toString());
                assertEquals("1999-12-31 23:59:59.123", rs.getTimestamp("dt").toString());
                assertEquals("2000-01-01 12:30:00.0", rs.getTimestamp("sdt").toString());
                assertEquals("2000-01-01", rs.getDate("sdt").toString());
                assertEquals("12:30:00", rs.getTime("sdt").toString());
                assertEquals("ABCD", rs.getString("c").trim());
                assertEquals("ABCDEFGHIJ", rs.getString("vc"));
                assertEquals("ABCDEFGH", new String(rs.getBytes("b")));
                assertEquals("ABCD", new String(rs.getBytes("vb")));
                assertEquals("TEXT FIELD", rs.getString("txt"));
                assertEquals("ABCD", new String(rs.getBytes("img")));
                if (row == 1) {
                    assertTrue(rs.getBoolean("bt"));
                } else {
                    assertFalse(rs.getBoolean("bt"));
                }
            }
            rs.close();
            stmt.close();
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        } finally {
            dropTable("jTDS_TESTRS");
        }
    }
    
    /**
     * Test update date/time (and updateNull).
     * @throws Exception
     */
    public void testUpdateDateTime() throws Exception {
        if (isASA) {
            // Can't do cursor updates
            return;
        }
        try {
            dropTable("jTDS_TESTDT");
            Statement stmt = con.createStatement();
            stmt.execute("CREATE TABLE jTDS_TESTDT (id int not null primary key, tn varchar(10) null, "+
                    "d1 datetime not null, d2 datetime not null, d3 smalldatetime not null)");
            assertEquals(1, stmt.executeUpdate("INSERT INTO jTDS_TESTDT VALUES(1, 'TEST', "+ 
                    "'1900-01-01', '1900-01-01', '1900-01-01')"));
            stmt = con.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_UPDATABLE);
            ResultSet rs = stmt.executeQuery("SELECT * FROM jTDS_TESTDT");
            assertNotNull(rs);
            assertTrue(rs.next());
            rs.updateNull("tn");
            rs.updateTimestamp("d1", Timestamp.valueOf("1999-12-31 23:59:59.123"));
            rs.updateTime("d2", Time.valueOf("12:20:20"));
            rs.updateDate("d3", Date.valueOf("2001-01-01"));
            rs.updateRow();
            // Read back values
            rs = stmt.executeQuery("SELECT * FROM jTDS_TESTDT");
            assertNotNull(rs);
            assertTrue(rs.next());
            assertNull(rs.getString("tn"));
            assertEquals("1999-12-31 23:59:59.123", rs.getTimestamp("d1").toString());
            assertEquals("12:20:20", rs.getTime("d2").toString());
            assertEquals("2001-01-01", rs.getDate("d3").toString());
            rs.close();
            stmt.close();
        } finally {
            dropTable("jTDS_TESTDT");
        }
    }

    /**
     * General test of scrollable cursor functionality.
     * When running on SQL Server this test will exercise MSCursorResultSet.
     * When running on Sybase this test will exercise CachedResultSet.
     */
    public void testCachedCursor() throws Exception {
        if (isASA) {
            // No cursor updates
            return;
        }
        try {
            dropTable("jTDS_CachedCursorTest");
            Statement stmt = con.createStatement();
            stmt.execute("CREATE TABLE jTDS_CachedCursorTest " +
                    "(key1 int NOT NULL, key2 char(4) NOT NULL," +
                    "data varchar(255))\r\n" +
                    "ALTER TABLE jTDS_CachedCursorTest " +
                    "ADD CONSTRAINT PK_jTDS_CachedCursorTest PRIMARY KEY CLUSTERED" +
                    "( key1, key2)");
            for (int i = 1; i <= 16; i++) {
                assertEquals(1, stmt.executeUpdate("INSERT INTO jTDS_CachedCursorTest VALUES(" + i + ", 'XXXX','LINE " + i + "')"));
            }
            stmt.close();
            stmt = con.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_UPDATABLE);
            ResultSet rs = stmt.executeQuery("SELECT * FROM jTDS_CachedCursorTest ORDER BY key1");
            assertNotNull(rs);
            assertEquals(null, stmt.getWarnings());
            assertTrue(rs.isBeforeFirst());
            assertTrue(rs.first());
            assertEquals(1, rs.getInt(1));
            assertTrue(rs.isFirst());
            assertTrue(rs.last());
            assertEquals(16, rs.getInt(1));
            assertTrue(rs.isLast());
            assertFalse(rs.next());
            assertTrue(rs.isAfterLast());
            rs.beforeFirst();
            assertTrue(rs.next());
            assertEquals(1, rs.getInt(1));
            rs.afterLast();
//            assertTrue(rs.previous()); // Does not work with SQL 6.5
//            assertEquals(16, rs.getInt(1)); // Does not work with SQL 6.5
            assertTrue(rs.absolute(8));
            assertEquals(8, rs.getInt(1));
            assertTrue(rs.relative(-1));
            assertEquals(7, rs.getInt(1));
            rs.updateString(3, "New line 7");
            rs.updateRow();
//            assertTrue(rs.rowUpdated()); // MS API cursors appear not to support this
            rs.moveToInsertRow();
            rs.updateInt(1, 17);
            rs.updateString(2, "XXXX");
            rs.updateString(3, "LINE 17");
            rs.insertRow();
            rs.moveToCurrentRow();
            rs.last();
//            assertTrue(rs.rowInserted()); // MS API cursors appear not to support this
            Statement stmt2 = con.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_READ_ONLY);
            ResultSet rs2 = stmt2.executeQuery("SELECT * FROM jTDS_CachedCursorTest ORDER BY key1");
            rs.updateString(3, "NEW LINE 17");
            rs.updateRow();
            assertTrue(rs2.last());
            assertEquals(17, rs2.getInt(1));
            assertEquals("NEW LINE 17", rs2.getString(3));
            rs.deleteRow();
            rs2.refreshRow();
            assertTrue(rs2.rowDeleted());
            rs2.close();
            stmt2.close();
            rs.close();
            stmt.close();
        } finally {
            dropTable("jTDS_CachedCursorTest");
        }
    }

    /**
     * Test support for JDBC 1 style positioned updates with named cursors.
     * When running on SQL Server this test will exercise MSCursorResultSet.
     * When running on Sybase this test will exercise CachedResultSet.
     */
     public void testPositionedUpdate() throws Exception
     {
         if (isASA) {
             // Can't do positioned updates
             return;
         }
         assertTrue(con.getMetaData().supportsPositionedDelete());
         assertTrue(con.getMetaData().supportsPositionedUpdate());
         Statement stmt = con.createStatement();
         stmt.execute("CREATE TABLE #TESTPOS (id INT primary key, data VARCHAR(255))");
         for (int i = 1; i <  5; i++) {
             stmt.execute("INSERT INTO #TESTPOS VALUES(" + i + ", 'This is line " + i + "')");
         }
         stmt.setCursorName("curname");
         ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTPOS FOR UPDATE");
         assertEquals("curname", rs.getCursorName());
         Statement stmt2 = con.createStatement();
         while (rs.next()) {
             if (rs.getInt(1) == 1) {
                 stmt2.execute("UPDATE #TESTPOS SET data = 'Updated' WHERE CURRENT OF curname");
             } else
             if (rs.getInt(1) == 3) {
                 stmt2.execute("DELETE FROM #TESTPOS WHERE CURRENT OF curname");
             }
         }
         rs.close();
         stmt.setFetchSize(100);
         rs = stmt.executeQuery("SELECT * FROM #TESTPOS");
         while (rs.next()) {
             int id = rs.getInt(1);
             assertTrue(id != 3); // Should have been deleted
             if (id == 1) {
                 assertEquals("Updated", rs.getString(2));
             }
         }
         stmt2.close();
         stmt.close();
     }

     /**
      * Test optimistic updates throw exception if row is changed on disk.
      */
     public void testOptimisticUpdates() throws Exception
     {
         if (isASA) {
             // Can't do cursor updates
             return;
         }
         if (isSql2005) {
             // CTP June does not seem to detect optimistic conflict
             return;
         }
         Connection con2 = getConnection();
         try {
             dropTable("jTDS_CachedCursorTest");
             Statement stmt = con.createStatement(ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_UPDATABLE);
             ResultSet rs;
             stmt.execute("CREATE TABLE jTDS_CachedCursorTest (id int primary key, data varchar(255))");
             for (int i = 0; i < 4; i++) {
                 stmt.executeUpdate("INSERT INTO jTDS_CachedCursorTest VALUES("+i+", 'Table A line "+i+"')");
             }
             // Open cursor
             rs = stmt.executeQuery("SELECT id, data FROM jTDS_CachedCursorTest");
             Statement stmt2 = con2.createStatement();
             while (rs.next()) {
                 if (rs.getInt(1) == 1) {
                     assertEquals(1, stmt2.executeUpdate("UPDATE jTDS_CachedCursorTest SET data = 'NEW VALUE' WHERE id = 1"));
                     rs.updateString(2, "TEST UPDATE");
                     try {
                         rs.updateRow();
                         fail("Expected optimistic update exception");
                     } catch (SQLException e) {
                         // Expected exception as row has been modified on disk
                     }
                 }
             }
             rs.close();
         } finally {
             if (con2 != null) {
                 con2.close();
             }
             dropTable("jTDS_CachedCursorTest");
         }
     }

     /**
      * Test updateable result set where table is not keyed.
      * Uses a server side cursor and positioned updates on Sybase.
      */
    public void testUpdateNoKeys() throws Exception
    {
        if (isASA) {
            // Can't do cursor updates
            return;
        }
        try {
            dropTable("jTDS_TESTNOKEY");
            Statement stmt = con.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_UPDATABLE);
            stmt.execute("CREATE TABLE jTDS_TESTNOKEY (id int, data varchar(255))");
            for (int i = 0; i < 4; i++) {
                stmt.executeUpdate("INSERT INTO jTDS_TESTNOKEY VALUES("+i+", 'Test line "+i+"')");
            }
            ResultSet rs = stmt.executeQuery("SELECT * FROM jTDS_TESTNOKEY");
            assertTrue(rs.next());
            assertTrue(rs.next());
            rs.updateString(2, "UPDATED");
            rs.updateRow();
            rs.close();
            rs = stmt.executeQuery("SELECT * FROM jTDS_TESTNOKEY");
            while (rs.next()) {
                if (rs.getInt(1) == 1) {
                    assertEquals("UPDATED", rs.getString(2));
                }
            }
            stmt.close();
        } finally {
            dropTable("jTDS_TESTNOKEY");
        }
    }

    /**
     * Test that calling <code>absolute()</code> with very large positive
     * values positions the cursor after the last row and with very large
     * negative values positions the cursor before the first row.
     */
    public void testAbsoluteLargeValue() throws SQLException {
        Statement stmt = con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE,
                ResultSet.CONCUR_READ_ONLY);

        stmt.executeUpdate(
                "create table #absoluteLargeValue (val int primary key)");
        stmt.executeUpdate(
                "insert into #absoluteLargeValue (val) values (1)");
        stmt.executeUpdate(
                "insert into #absoluteLargeValue (val) values (2)");
        stmt.executeUpdate(
                "insert into #absoluteLargeValue (val) values (3)");

        ResultSet rs = stmt.executeQuery(
                "select val from #absoluteLargeValue order by val");

        assertFalse(rs.absolute(10));
        assertEquals(0, rs.getRow());
        assertTrue(rs.isAfterLast());
        assertFalse(rs.next());
        assertEquals(0, rs.getRow());
        assertTrue(rs.isAfterLast());

        assertFalse(rs.absolute(-10));
        assertEquals(0, rs.getRow());
        assertTrue(rs.isBeforeFirst());
        assertFalse(rs.previous());
        assertEquals(0, rs.getRow());
        assertTrue(rs.isBeforeFirst());

        rs.close();
        stmt.close();
    }

    /**
     * Test that calling <code>absolute()</code> with very large positive
     * values positions the cursor after the last row and with very large
     * negative values positions the cursor before the first row.
     */
    public void testRelativeLargeValue() throws SQLException {
        Statement stmt = con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE,
                ResultSet.CONCUR_READ_ONLY);

        stmt.executeUpdate(
                "create table #relativeLargeValue (val int primary key)");
        stmt.executeUpdate(
                "insert into #relativeLargeValue (val) values (1)");
        stmt.executeUpdate(
                "insert into #relativeLargeValue (val) values (2)");
        stmt.executeUpdate(
                "insert into #relativeLargeValue (val) values (3)");

        ResultSet rs = stmt.executeQuery(
                "select val from #relativeLargeValue order by val");

        assertFalse(rs.relative(10));
        assertEquals(0, rs.getRow());
        assertTrue(rs.isAfterLast());
        assertFalse(rs.next());
        assertEquals(0, rs.getRow());
        assertTrue(rs.isAfterLast());

        assertFalse(rs.relative(-10));
        assertEquals(0, rs.getRow());
        assertTrue(rs.isBeforeFirst());
        assertFalse(rs.previous());
        assertEquals(0, rs.getRow());
        assertTrue(rs.isBeforeFirst());

        rs.close();
        stmt.close();
    }
   
    public static void main(String[] args) {
        junit.textui.TestRunner.run(ResultSetTest.class);
    }
}
