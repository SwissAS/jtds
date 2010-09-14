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

import java.sql.Statement;
import java.sql.ResultSetMetaData;
import java.sql.Types;

/**
 * Test ResultSetMetaData class.
 */
public class ResultSetMetaDataTest extends TestBase {

    public ResultSetMetaDataTest(String name) {
        super(name);
    }

    /**
     * Test getResultSetMetaData method.
     * @throws Exception
     */
    public void testResultSetMetaData() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TESTRSMD (" +
                        "auto numeric(10,0) identity, " +
                        "pk int primary key not null, " +
                        "mny money not null," +
                        "vc varchar(10) null," +
                        "img image not null)");
        ResultSetMetaData rsmd = 
//            stmt.executeQuery("SELECT *, 'expr' FROM #TESTRSMD FOR BROWSE").getMetaData();
            stmt.executeQuery("SELECT *, 'expr' FROM #TESTRSMD").getMetaData();
        assertEquals(6, rsmd.getColumnCount());
        assertNotNull(rsmd.getCatalogName(1));
        assertNotNull(rsmd.getSchemaName(1));
//        assertEquals("#TESTRSMD", rsmd.getTableName(1));
        assertEquals("", rsmd.getTableName(6));
        assertEquals("auto",rsmd.getColumnName(1));
        assertEquals("auto",rsmd.getColumnLabel(1));
        assertEquals(Types.NUMERIC, rsmd.getColumnType(1));
        assertEquals("numeric identity", rsmd.getColumnTypeName(1));
        assertEquals("java.math.BigDecimal", rsmd.getColumnClassName(1));
        assertEquals(11, rsmd.getColumnDisplaySize(1));
        assertEquals(10, rsmd.getPrecision(1));
        assertEquals(0, rsmd.getScale(1));
        assertTrue(rsmd.isAutoIncrement(1));
        assertFalse(rsmd.isAutoIncrement(2));
        assertFalse(rsmd.isCaseSensitive(1));
        assertFalse(rsmd.isCurrency(1));
        assertTrue(rsmd.isCurrency(3));
        assertFalse(rsmd.isDefinitelyWritable(1));
        assertTrue(rsmd.isReadOnly(1));
        assertFalse(rsmd.isWritable(1));
        assertFalse(rsmd.isDefinitelyWritable(2));
//        assertFalse(rsmd.isReadOnly(2));
//        assertTrue(rsmd.isWritable(2));
        assertTrue(rsmd.isSearchable(1));
        assertFalse(rsmd.isSearchable(5));
        assertTrue(rsmd.isSigned(1));
        assertFalse(rsmd.isSigned(4));
        assertEquals(ResultSetMetaData.columnNoNulls, rsmd.isNullable(1));
        assertEquals(ResultSetMetaData.columnNullable, rsmd.isNullable(4));
    }
    
    public static void main(String[] args) {
        junit.textui.TestRunner.run(ResultSetMetaDataTest.class);
    }
}
