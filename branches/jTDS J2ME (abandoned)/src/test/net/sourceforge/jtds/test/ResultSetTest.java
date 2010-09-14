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
import java.util.ArrayList;

/**
 * @version 1.0
 */
public class ResultSetTest extends TestBase {
    public ResultSetTest(String name) {
        super(name);
    }

    /**
     * Test BIT data type.
     */
    public void testGetObject1() throws Exception {
        boolean data = true;

        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #getObject1 (data BIT, minval BIT, maxval BIT)");
        stmt.close();

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #getObject1 (data, minval, maxval) VALUES (?, ?, ?)");

        pstmt.setBoolean(1, data);
        pstmt.setBoolean(2, false);
        pstmt.setBoolean(3, true);
        assertEquals(1, pstmt.executeUpdate());

        pstmt.close();

        Statement stmt2 = con.createStatement();
        ResultSet rs = stmt2.executeQuery("SELECT data, minval, maxval FROM #getObject1");

        assertTrue(rs.next());

        assertTrue(rs.getBoolean(1));
        assertTrue(rs.getByte(1) == 1);
        assertTrue(rs.getShort(1) == 1);
        assertTrue(rs.getInt(1) == 1);
        assertTrue(rs.getLong(1) == 1);
        assertTrue(rs.getFloat(1) == 1);
        assertTrue(rs.getDouble(1) == 1);
        assertEquals("1", rs.getString(1));

        Object tmpData = rs.getObject(1);

        assertTrue(tmpData instanceof Boolean);
        assertEquals(true, ((Boolean) tmpData).booleanValue());

        ResultSetMetaData resultSetMetaData = rs.getMetaData();

        assertNotNull(resultSetMetaData);
        assertEquals(Types.BIT, resultSetMetaData.getColumnType(1));

        assertFalse(rs.getBoolean(2));
        assertTrue(rs.getBoolean(3));

        assertFalse(rs.next());
        stmt2.close();
        rs.close();
    }

    /**
     * Test TINYINT data type.
     */
    public void testGetObject2() throws Exception {
        byte data = 1;

        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #getObject2 (data TINYINT, minval TINYINT, maxval TINYINT)");
        stmt.close();

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #getObject2 (data, minval, maxval) VALUES (?, ?, ?)");

        pstmt.setByte(1, data);
        pstmt.setByte(2, Byte.MIN_VALUE);
        pstmt.setByte(3, Byte.MAX_VALUE);
        assertEquals(1, pstmt.executeUpdate());

        pstmt.close();

        Statement stmt2 = con.createStatement();
        ResultSet rs = stmt2.executeQuery("SELECT data, minval, maxval FROM #getObject2");

        assertTrue(rs.next());

        assertTrue(rs.getBoolean(1));
        assertTrue(rs.getByte(1) == 1);
        assertTrue(rs.getShort(1) == 1);
        assertTrue(rs.getInt(1) == 1);
        assertTrue(rs.getLong(1) == 1);
        assertTrue(rs.getFloat(1) == 1);
        assertTrue(rs.getDouble(1) == 1);
        assertEquals("1", rs.getString(1));

        Object tmpData = rs.getObject(1);

        assertTrue(tmpData instanceof Integer);
        assertEquals(data, ((Integer) tmpData).byteValue());

        ResultSetMetaData resultSetMetaData = rs.getMetaData();

        assertNotNull(resultSetMetaData);
        assertEquals(Types.TINYINT, resultSetMetaData.getColumnType(1));

        assertEquals(rs.getByte(2), Byte.MIN_VALUE);
        assertEquals(rs.getByte(3), Byte.MAX_VALUE);

        assertFalse(rs.next());
        stmt2.close();
        rs.close();
    }

    /**
     * Test SMALLINT data type.
     */
    public void testGetObject3() throws Exception {
        short data = 1;

        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #getObject3 (data SMALLINT, minval SMALLINT, maxval SMALLINT)");
        stmt.close();

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #getObject3 (data, minval, maxval) VALUES (?, ?, ?)");

        pstmt.setShort(1, data);
        pstmt.setShort(2, Short.MIN_VALUE);
        pstmt.setShort(3, Short.MAX_VALUE);
        assertEquals(1, pstmt.executeUpdate());

        pstmt.close();

        Statement stmt2 = con.createStatement();
        ResultSet rs = stmt2.executeQuery("SELECT data, minval, maxval FROM #getObject3");

        assertTrue(rs.next());

        assertTrue(rs.getBoolean(1));
        assertTrue(rs.getByte(1) == 1);
        assertTrue(rs.getShort(1) == 1);
        assertTrue(rs.getInt(1) == 1);
        assertTrue(rs.getLong(1) == 1);
        assertTrue(rs.getFloat(1) == 1);
        assertTrue(rs.getDouble(1) == 1);
        assertEquals("1", rs.getString(1));

        Object tmpData = rs.getObject(1);

        assertTrue(tmpData instanceof Integer);
        assertEquals(data, ((Integer) tmpData).shortValue());

        ResultSetMetaData resultSetMetaData = rs.getMetaData();

        assertNotNull(resultSetMetaData);
        assertEquals(Types.SMALLINT, resultSetMetaData.getColumnType(1));

        assertEquals(rs.getShort(2), Short.MIN_VALUE);
        assertEquals(rs.getShort(3), Short.MAX_VALUE);

        assertFalse(rs.next());
        stmt2.close();
        rs.close();
    }

    /**
     * Test INT data type.
     */
    public void testGetObject4() throws Exception {
        int data = 1;

        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #getObject4 (data INT, minval INT, maxval INT)");
        stmt.close();

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #getObject4 (data, minval, maxval) VALUES (?, ?, ?)");

        pstmt.setInt(1, data);
        pstmt.setInt(2, Integer.MIN_VALUE);
        pstmt.setInt(3, Integer.MAX_VALUE);
        assertEquals(1, pstmt.executeUpdate());

        pstmt.close();

        Statement stmt2 = con.createStatement();
        ResultSet rs = stmt2.executeQuery("SELECT data, minval, maxval FROM #getObject4");

        assertTrue(rs.next());

        assertTrue(rs.getBoolean(1));
        assertTrue(rs.getByte(1) == 1);
        assertTrue(rs.getShort(1) == 1);
        assertTrue(rs.getInt(1) == 1);
        assertTrue(rs.getLong(1) == 1);
        assertTrue(rs.getFloat(1) == 1);
        assertTrue(rs.getDouble(1) == 1);
        assertEquals("1", rs.getString(1));

        Object tmpData = rs.getObject(1);

        assertTrue(tmpData instanceof Integer);
        assertEquals(data, ((Integer) tmpData).intValue());

        ResultSetMetaData resultSetMetaData = rs.getMetaData();

        assertNotNull(resultSetMetaData);
        assertEquals(Types.INTEGER, resultSetMetaData.getColumnType(1));

        assertEquals(rs.getInt(2), Integer.MIN_VALUE);
        assertEquals(rs.getInt(3), Integer.MAX_VALUE);

        assertFalse(rs.next());
        stmt2.close();
        rs.close();
    }

    /**
     * Test BIGINT data type.
     */
    public void testGetObject5() throws Exception {
        long data = 1;

        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #getObject5 (data DECIMAL(28, 0), minval DECIMAL(28, 0), maxval DECIMAL(28, 0))");
        stmt.close();

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #getObject5 (data, minval, maxval) VALUES (?, ?, ?)");

        pstmt.setLong(1, data);
        pstmt.setLong(2, Long.MIN_VALUE);
        pstmt.setLong(3, Long.MAX_VALUE);
        assertEquals(1, pstmt.executeUpdate());

        pstmt.close();

        Statement stmt2 = con.createStatement();
        ResultSet rs = stmt2.executeQuery("SELECT data, minval, maxval FROM #getObject5");

        assertTrue(rs.next());

        assertTrue(rs.getBoolean(1));
        assertTrue(rs.getByte(1) == 1);
        assertTrue(rs.getShort(1) == 1);
        assertTrue(rs.getInt(1) == 1);
        assertTrue(rs.getLong(1) == 1);
        assertTrue(rs.getFloat(1) == 1);
        assertTrue(rs.getDouble(1) == 1);
        assertEquals("1", rs.getString(1));

        Object tmpData = rs.getObject(1);

        assertTrue(tmpData instanceof String);
        assertEquals(data, Long.parseLong((String) tmpData));

        ResultSetMetaData resultSetMetaData = rs.getMetaData();

        assertNotNull(resultSetMetaData);
        assertEquals(Types.DECIMAL, resultSetMetaData.getColumnType(1));

        assertEquals(rs.getLong(2), Long.MIN_VALUE);
        assertEquals(rs.getLong(3), Long.MAX_VALUE);

        assertFalse(rs.next());
        stmt2.close();
        rs.close();
    }

    /**
     * Test for bug [1009233] ResultSet getColumnName, getColumnLabel return wrong values
     */
    public void testResultSetColumnName1() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #resultSetCN1 (data INT)");
        stmt.close();

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #resultSetCN1 (data) VALUES (?)");

        pstmt.setInt(1, 1);
        assertEquals(1, pstmt.executeUpdate());

        pstmt.close();

        Statement stmt2 = con.createStatement();
        stmt2.executeQuery("SELECT data as test FROM #resultSetCN1");

        ResultSet rs = stmt2.getResultSet();

        assertNotNull(rs);
        assertTrue(rs.next());
        assertEquals(1, rs.getInt("test"));
        assertFalse(rs.next());

        stmt2.close();
        rs.close();
    }

    /**
     * Test for fixed bugs in ResultSetMetaData:
     * <ol>
     * <li>isNullable() always returns columnNoNulls.
     * <li>isSigned returns true in error for TINYINT columns.
     * <li>Type names for numeric / decimal have (prec,scale) appended in error.
     * <li>Type names for auto increment columns do not have "identity" appended.
     * </ol>
     * NB: This test assumes getColumnName has been fixed to work as per the suggestion
     * in bug report [1009233].
     *
     * @throws Exception
     */
    public void testResultSetMetaData() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TRSMD (id INT IDENTITY NOT NULL, byte TINYINT NOT NULL, num DECIMAL(28,10) NULL)");
        ResultSetMetaData rsmd = stmt.executeQuery("SELECT id as idx, byte, num FROM #TRSMD").getMetaData();
        assertNotNull(rsmd);
        // Check id
        assertEquals("idx", rsmd.getColumnName(1)); // no longer returns base name
        assertEquals("idx", rsmd.getColumnLabel(1));
        assertTrue(rsmd.isAutoIncrement(1));
        assertTrue(rsmd.isSigned(1));
        assertEquals(ResultSetMetaData.columnNoNulls, rsmd.isNullable(1));
        assertEquals("int identity", rsmd.getColumnTypeName(1));
        assertEquals(Types.INTEGER, rsmd.getColumnType(1));
        // Check byte
        assertFalse(rsmd.isAutoIncrement(2));
        assertFalse(rsmd.isSigned(2));
        assertEquals(ResultSetMetaData.columnNoNulls, rsmd.isNullable(2));
        assertEquals("tinyint", rsmd.getColumnTypeName(2));
        assertEquals(Types.TINYINT, rsmd.getColumnType(2));
        // Check num
        assertFalse(rsmd.isAutoIncrement(3));
        assertTrue(rsmd.isSigned(3));
        assertEquals(ResultSetMetaData.columnNullable, rsmd.isNullable(3));
        assertEquals("decimal", rsmd.getColumnTypeName(3));
        assertEquals(Types.DECIMAL, rsmd.getColumnType(3));
        stmt.close();
    }

    /**
     * Test whether retrieval by name returns the first occurence (that's what
     * the spec requires).
     */
    public void testGetByName() throws Exception
    {
        Statement stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT 1 myCol, 2 myCol, 3 myCol");
        assertTrue(rs.next());
        assertEquals(1, rs.getInt("myCol"));
        assertFalse(rs.next());
        stmt.close();
    }

    /**
     * Test if COL_INFO packets are processed correctly for
     * <code>ResultSet</code>s with over 255 columns.
     */
    public void testMoreThan255Columns() throws Exception
    {
        Statement stmt = con.createStatement();

        // create the table
        int cols = 260;
        StringBuffer create = new StringBuffer("create table #manycolumns (");
        for (int i=0; i<cols; ++i) {
            create.append("col" + i + " char(10), ") ;
        }
        create.append(")");
        stmt.executeUpdate(create.toString());

        String query = "select * from #manycolumns";
        ResultSet rs = stmt.executeQuery(query);
        rs.close();
        stmt.close();
    }

    /**
     * Test the behavior of <code>sp_cursorfetch</code> with fetch sizes
     * greater than 1.
     * <p>
     * <b>Assertions tested:</b>
     * <ul>
     *   <li>The <i>current row</i> is always the first row returned by the
     *     last fetch, regardless of what fetch type was used.
     *   <li>Row number parameter is ignored by fetch types other than absolute
     *     and relative.
     *   <li>Refresh fetch type simply reruns the previous request (it ignores
     *     both row number and number of rows) and will not affect the
     *     <i>current row</i>.
     *   <li>Fetch next returns the packet of rows right after the last row
     *     returned by the last fetch (regardless of what type of fetch that
     *     was).
     *   <li>Fetch previous returns the packet of rows right before the first
     *     row returned by the last fetch (regardless of what type of fetch
     *     that was).
     *   <li>If a fetch previous tries to read before the start of the
     *     <code>ResultSet</code> the requested number of rows is returned,
     *     starting with row 1 and the error code returned is non-zero (2).
     * </ul>
     */
    public void testCursorFetch() throws Exception
    {
        int rows = 10;
        Statement stmt = con.createStatement();
        stmt.executeUpdate(
                "create table #testCursorFetch (id int primary key, val int)");
        stmt.close();

        PreparedStatement pstmt = con.prepareStatement(
                "insert into #testCursorFetch (id, val) values (?, ?)");
        for (int i = 1; i <= rows; i++) {
            pstmt.setInt(1, i);
            pstmt.setInt(2, i);
            pstmt.executeUpdate();
        }
        pstmt.close();

        //
        // Open cursor
        //
        CallableStatement cstmt = con.prepareCall(
                "{?=call sp_cursoropen(?, ?, ?, ?, ?)}");
        // Return value (OUT)
        cstmt.registerOutParameter(1, Types.INTEGER);
        // Cursor handle (OUT)
        cstmt.registerOutParameter(2, Types.INTEGER);
        // Statement (IN)
        cstmt.setString(3, "select * from #testCursorFetch order by id");
        // Scroll options (INOUT)
        cstmt.setInt(4, 1); // Keyset driven
        cstmt.registerOutParameter(4, Types.INTEGER);
        // Concurrency options (INOUT)
        cstmt.setInt(5, 2); // Scroll locks
        cstmt.registerOutParameter(5, Types.INTEGER);
        // Row count (OUT)
        cstmt.registerOutParameter(6, Types.INTEGER);

        ResultSet rs = cstmt.executeQuery();
        assertEquals(2, rs.getMetaData().getColumnCount());
        assertFalse(rs.next());

        assertEquals(0, cstmt.getInt(1));
        int cursor = cstmt.getInt(2);
        assertEquals(1, cstmt.getInt(4));
        assertEquals(2, cstmt.getInt(5));
        assertEquals(rows, cstmt.getInt(6));

        cstmt.close();

        //
        // Play around with fetch
        //
        cstmt = con.prepareCall("{?=call sp_cursorfetch(?, ?, ?, ?)}");
        // Return value (OUT)
        cstmt.registerOutParameter(1, Types.INTEGER);
        // Cursor handle (IN)
        cstmt.setInt(2, cursor);
        // Fetch type (IN)
        cstmt.setInt(3, 2); // Next row
        // Row number (INOUT)
        cstmt.setInt(4, 1); // Only matters for absolute and relative fetching
        // Number of rows (INOUT)
        cstmt.setInt(5, 2); // Read 2 rows

        // Fetch rows 1-2 (current row is 1)
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertTrue(rs.next());
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch rows 3-4 (current row is 3)
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertTrue(rs.next());
        assertEquals(4, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Refresh rows 3-4 (current row is 3)
        cstmt.setInt(3, 0x80); // Refresh
        cstmt.setInt(4, 2);    // Try to refresh only 2nd row (will be ignored)
        cstmt.setInt(5, 1);    // Try to refresh only 1 row (will be ignored)
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertTrue(rs.next());
        assertEquals(4, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch rows 5-6 (current row is 5)
        cstmt.setInt(3, 2); // Next
        cstmt.setInt(4, 1); // Row number 1
        cstmt.setInt(5, 2); // Get 2 rows
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertTrue(rs.next());
        assertEquals(6, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch previous rows (3-4) (current row is 3)
        cstmt.setInt(3, 4); // Previous
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertEquals(3, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(4, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Refresh rows 3-4 (current row is 3)
        cstmt.setInt(3, 0x80); // Refresh
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertEquals(3, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(4, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch previous rows (1-2) (current row is 1)
        cstmt.setInt(3, 4); // Previous
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertEquals(1, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(2, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch next rows (3-4) (current row is 3)
        cstmt.setInt(3, 2); // Next
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertEquals(3, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(4, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch first rows (1-2) (current row is 1)
        cstmt.setInt(3, 1); // First
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertEquals(1, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(2, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch last rows (9-10) (current row is 9)
        cstmt.setInt(3, 8); // Last
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertEquals(9, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(10, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch next rows; should not fail (current position is after last)
        cstmt.setInt(3, 2); // Next
        rs = cstmt.executeQuery();
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch absolute starting with 6 (6-7) (current row is 6)
        cstmt.setInt(3, 0x10); // Absolute
        cstmt.setInt(4, 6);
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertEquals(6, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(7, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch relative -4 (2-3) (current row is 2)
        cstmt.setInt(3, 0x20); // Relative
        cstmt.setInt(4, -4);
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertEquals(2, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(3, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        // Fetch previous 2 rows; should fail (current row is 1)
        cstmt.setInt(3, 4); // Previous
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertEquals(1, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(2, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        // Returns 2 on error
        assertEquals(2, cstmt.getInt(1));

        // Fetch next rows (3-4) (current row is 3)
        cstmt.setInt(3, 2); // Next
        rs = cstmt.executeQuery();
        assertTrue(rs.next());
        assertEquals(3, rs.getInt(1));
        assertTrue(rs.next());
        assertEquals(4, rs.getInt(1));
        assertFalse(rs.next());
        rs.close();
        assertEquals(0, cstmt.getInt(1));

        cstmt.close();

        //
        // Close cursor
        //
        cstmt = con.prepareCall("{?=call sp_cursorclose(?)}");
        // Return value (OUT)
        cstmt.registerOutParameter(1, Types.INTEGER);
        // Cursor handle (IN)
        cstmt.setInt(2, cursor);
        assertFalse(cstmt.execute());
        assertEquals(0, cstmt.getInt(1));
        cstmt.close();
    }

    /**
     * Test for bug [1075977] <code>setObject()</code> causes SQLException.
     * <p>
     * Conversion of <code>float</code> values to <code>String</code> adds
     * grouping to the value, which cannot then be parsed.
     */
    public void testSetObjectScale() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("create table #testsetobj (i int)");
        PreparedStatement pstmt =
                con.prepareStatement("insert into #testsetobj values(?)");
        // next line causes sqlexception
        pstmt.setObject(1, new Float(1234.5667), Types.INTEGER, 0);
        assertEquals(1, pstmt.executeUpdate());
        ResultSet rs = stmt.executeQuery("select * from #testsetobj");
        assertTrue(rs.next());
        assertEquals("1234", rs.getString(1));
    }

    /**
     * Test the behavior of the ResultSet/Statement/Connection when the JVM
     * runs out of memory (hopefully) in the middle of a packet.
     * <p/>
     * Previously jTDS was not able to close a ResultSet/Statement/Connection
     * after an OutOfMemoryError because the input stream pointer usually
     * remained inside a packet and further attempts to dump the rest of the
     * response failed because of "protocol confusions".
     */
    public void testOutOfMemory() throws SQLException {
        Statement stmt = con.createStatement();
        stmt.executeUpdate("create table #testOutOfMemory (val binary(8000))");

        // Insert a 8KB value
        byte[] val = new byte[8000];
        PreparedStatement pstmt = con.prepareStatement(
                "insert into #testOutOfMemory (val) values (?)");
        pstmt.setBytes(1, val);
        assertEquals(1, pstmt.executeUpdate());
        pstmt.close();

        // Create a list and keep adding rows to it until we run out of memory
        // Most probably this will happen in the middle of a row packet, when
        // jTDS tries to allocate the array, after reading the data length
        ArrayList results = new ArrayList();
        ResultSet rs = null;
        try {
            while (true) {
                rs = stmt.executeQuery("select val from #testOutOfMemory");
                assertTrue(rs.next());
                results.add(rs.getBytes(1));
                assertFalse(rs.next());
                rs.close();
                rs = null;
            }
        } catch (OutOfMemoryError err) {
            results = null;
            if (rs != null) {
                // This used to fail, because the parser got confused
                rs.close();
            }
        }

        // Make sure the Statement still works
        rs = stmt.executeQuery("select 1");
        assertTrue(rs.next());
        assertFalse(rs.next());
        rs.close();
        stmt.close();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ResultSetTest.class);
    }
}
