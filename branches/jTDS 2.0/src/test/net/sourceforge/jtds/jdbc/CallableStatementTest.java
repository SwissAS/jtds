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
import java.sql.BatchUpdateException;
import java.sql.CallableStatement;
import java.sql.ParameterMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;

/**
 * Test case to exercise the CallableStatement class.
 *
 * @version    1.0
 */
public class CallableStatementTest extends TestBase {
        
    public CallableStatementTest(String name) {
        super(name);
    }

    /**
     * Test create all statement type concurrencies.
     * @throws Exception
     */
    public void testCreateCallableStatement() throws Exception {
        CallableStatement cstmt;
        //
        // Check bad params
        //
        try {
            cstmt = con.prepareCall("{call sp_who}", 
                                            999, 
                                                ResultSet.CONCUR_UPDATABLE);
            fail("Expected error bad type");
        } catch (SQLException e) {
            // Ignore
        }
        try {
            cstmt = con.prepareCall("{call sp_who}", 
                                            ResultSet.TYPE_FORWARD_ONLY, 
                                                999);
            fail("Expected error bad concurrency");
        } catch (SQLException e) {
            // Ignore
        }
        //
        // Default type / concurrency
        //
        cstmt = con.prepareCall("{call sp_who}");
        assertNotNull(cstmt);
        cstmt.close();
        //
        // Forward read only
        //
        cstmt = con.prepareCall("{call sp_who}", 
                                        ResultSet.TYPE_FORWARD_ONLY, 
                                            ResultSet.CONCUR_READ_ONLY);
        assertNotNull(cstmt);
        cstmt.close();
        //
        // Forward updateable
        //
        cstmt = con.prepareCall("{call sp_who}", 
                                        ResultSet.TYPE_FORWARD_ONLY, 
                                            ResultSet.CONCUR_UPDATABLE);
        assertNotNull(cstmt);
        cstmt.close();
        //
        // Scrollable read only
        //
        cstmt = con.prepareCall("{call sp_who}", 
                                        ResultSet.TYPE_SCROLL_INSENSITIVE, 
                                            ResultSet.CONCUR_READ_ONLY);
        assertNotNull(cstmt);
        cstmt.close();
        //
        // Scrollable updateable
        //
        cstmt = con.prepareCall("{call sp_who}", 
                                        ResultSet.TYPE_SCROLL_INSENSITIVE, 
                                            ResultSet.CONCUR_UPDATABLE);
        assertNotNull(cstmt);
        cstmt.close();
        //
        // Scrollable read only
        //
        cstmt = con.prepareCall("{call sp_who}", 
                                        ResultSet.TYPE_SCROLL_SENSITIVE, 
                                            ResultSet.CONCUR_READ_ONLY);
        assertNotNull(cstmt);
        cstmt.close();
        //
        // Scrollable updateable
        //
        cstmt = con.prepareCall("{call sp_who}", 
                                        ResultSet.TYPE_SCROLL_SENSITIVE, 
                                            ResultSet.CONCUR_UPDATABLE);
        assertNotNull(cstmt);
        cstmt.close();
    }
    
    /**
     * Test get type / concurrency.
     * @throws Exception
     */
    public void testGetTypeConcur() throws Exception {
        CallableStatement cstmt = 
            con.prepareCall("{call sp_who}", 
                                    ResultSet.TYPE_SCROLL_INSENSITIVE, 
                                        ResultSet.CONCUR_UPDATABLE);
        assertNotNull(cstmt);
        assertEquals(ResultSet.TYPE_SCROLL_INSENSITIVE, cstmt.getResultSetType());
        assertEquals(ResultSet.CONCUR_UPDATABLE, cstmt.getResultSetConcurrency());
        cstmt.close();
        // Default type/concurrency
        cstmt = con.prepareCall("{call sp_who}");
        assertNotNull(cstmt);
        assertEquals(ResultSet.TYPE_FORWARD_ONLY, cstmt.getResultSetType());
        assertEquals(ResultSet.CONCUR_READ_ONLY, cstmt.getResultSetConcurrency());
        cstmt.close();
    }
        
    /**
     * Test batch execution methods.
     * @throws Exception
     */
    public void testExecuteBatch() throws Exception {
        try {
            dropProcedure("jtds_TestCall");
        //
        // Test batch execution
        //
        Statement stmt = con.createStatement();
        stmt.execute(
             "CREATE TABLE #TESTBATCH (id int primary key, data varchar(255))");
        stmt.execute("CREATE PROC jtds_TestCall @p1 int, @p2 varchar(255) as " +
                     "BEGIN INSERT INTO #TESTBATCH VALUES(@p1, @p2) END");
        //
        CallableStatement cstmt = 
            con.prepareCall("{call jtds_TestCall (?, ?)}");
        cstmt.setInt(1, 1);
        cstmt.setString(2, "THIS WILL WORK");
        cstmt.addBatch();
        cstmt.setInt(1, 2);
        cstmt.setString(2, "AS WILL THIS");
        cstmt.addBatch();
        int counts[];
//        java.sql.DriverManager.setLogStream(System.out);
        counts = cstmt.executeBatch();
        assertEquals(2, counts.length);
        assertEquals(1, counts[0]);
        assertEquals(1, counts[1]);
        // Now with errors
        cstmt.setInt(1, 3);
        cstmt.setString(2, "THIS WILL WORK");
        cstmt.addBatch();
        cstmt.setInt(1, 1);
        cstmt.setString(2, "THIS WILL NOT");
        cstmt.addBatch();
        try {
            counts = cstmt.executeBatch();
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
        assertEquals(0, cstmt.executeBatch().length);        
        //
        // Test clear batch
        //
        cstmt.addBatch();
        cstmt.clearBatch();
        assertEquals(0, cstmt.executeBatch().length);      
        cstmt.close();
        stmt.close();
        } finally {
            dropProcedure("jtds_TestCall");
        }
    }

    /**
     * Test call parameters
     * @throws Exception
     */
    public void testCallParams() throws Exception {
        try {
            dropProcedure("jtds_TestCall");
            Statement stmt = con.createStatement();
            stmt.execute("CREATE PROC jtds_TestCall @p1 tinyint, @p2 smallint, " +
                    "@p3 int, @p4 real, @p5 float, @p6 money, " +
                    "@p7 smallmoney, @p8 numeric(28,10), @p9 decimal(28,10), " +
                    "@p10 datetime, @p11 smalldatetime, @p12 varchar(10), " +
                    "@p13 varbinary(10), @p14 char(10), @p15 binary(8), " +
                    "@p16 bit as\r\n" +
                    "BEGIN\r\n"+
                    "IF @p1 <> 123 BEGIN PRINT 'Bad tinyint' RETURN 1 END\r\n"+
                    "IF @p2 <> 12345 BEGIN PRINT 'Bad smallint' RETURN 1 END\r\n"+
                    "IF @p3 <> 12345678 BEGIN PRINT 'Bad int' RETURN 1 END\r\n"+
                    "IF convert(decimal(10,1), @p4) <> 12345.7 BEGIN PRINT 'Bad real' RETURN 1 END\r\n"+
                    "IF convert(decimal(10,2), @p5) <> 1234567.89 BEGIN PRINT 'Bad float' RETURN 1 END\r\n"+
                    "IF @p6 <> 12345.6789 BEGIN PRINT 'Bad money' RETURN 1 END\r\n"+
                    "IF @p7 <> 12345.6789 BEGIN PRINT 'Bad smallmoney' RETURN 1 END\r\n"+
                    "IF @p8 <> 1234567.89 BEGIN PRINT 'Bad numeric' RETURN 1 END\r\n"+
                    "IF @p9 <> 1234567.89 BEGIN PRINT 'Bad decimal' RETURN 1 END\r\n"+
                    "IF @p10 <> '1999-12-31 12:30:00' BEGIN PRINT 'Bad datetime' RETURN 1 END\r\n" +
                    "IF @p11 <> '1999-12-31 12:30:00' BEGIN PRINT 'Bad smalldatetime' RETURN 1 END\r\n" +
                    "IF @p12 <> 'ABCDEFGHIJ' BEGIN PRINT 'Bad varchar' RETURN 1 END\r\n"+
                    "IF @p13 <> 0x41424344 BEGIN PRINT 'Bad varbinary' RETURN 1 END\r\n"+
                    "IF @p14 <> 'ABCD' BEGIN PRINT 'Bad char' RETURN 1 END\r\n"+
                    "IF @p15 <> 0x4142434445464748 BEGIN PRINT 'Bad binary' RETURN 1 END\r\n"+
                    "IF @p16 <> 1 BEGIN PRINT 'Bad bit' RETURN 1 END\r\n"+
                    "RETURN 0\r\n" +
                    "END");
             CallableStatement cstmt = con.prepareCall("{?=call jtds_TestCall (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)}");
             cstmt.registerOutParameter( 1, Types.INTEGER);
             cstmt.setByte(2, (byte)123);
             cstmt.setShort(3, (short)12345);
             cstmt.setInt(4, 12345678);
             cstmt.setFloat(5, 12345.67f);
             cstmt.setDouble(6, 1234567.89);
             cstmt.setBigDecimal(7, new BigDecimal("12345.6789"));
             cstmt.setObject(8, new BigDecimal("12345.6789"), Types.DECIMAL);
             cstmt.setBigDecimal(9, new BigDecimal("1234567.89"));
             cstmt.setObject(10, new BigDecimal("1234567.89"));
             cstmt.setTimestamp(11, Timestamp.valueOf("1999-12-31 12:30:00"));
             cstmt.setTimestamp(12, Timestamp.valueOf("1999-12-31 12:30:00"));
             cstmt.setString(13, "ABCDEFGHIJ");
             cstmt.setBytes(14, "ABCD".getBytes());
             cstmt.setString(15, "ABCD");
             cstmt.setBytes(16, "ABCDEFGH".getBytes());
             cstmt.setBoolean(17, true);
             cstmt.execute();
             if (cstmt.getInt(1) != 0) {
                 fail(cstmt.getWarnings().getMessage());
             }
             cstmt.close();
             stmt.close();
        } finally {
            dropProcedure("jtds_TestCall");            
        }
    }
    
    /**
     * Test return parameters
     * @throws Exception
     */
    public void testReturnParams() throws Exception {
        try {
            dropProcedure("jtds_TestRet");
            Statement stmt = con.createStatement();
            stmt.execute("CREATE PROC jtds_TestRet @p1 tinyint output, @p2 smallint output, " +
                    "@p3 int output, @p4 real output, @p5 float output, @p6 money output, " +
                    "@p7 smallmoney output, @p8 numeric(28,10) output, @p9 decimal(28,10) output, " +
                    "@p10 datetime output, @p11 smalldatetime output, @p12 varchar(10) output, " +
                    "@p13 varbinary(10) output, @p14 char(10) output, @p15 binary(8) output, " +
                    "@p16 bit output as\r\n" +
                    "BEGIN\r\n"+
                    "SELECT @p1 = 123\r\n" +
                    "SELECT @p2 = 12345\r\n" +
                    "SELECT @p3 = 12345678\r\n" +
                    "SELECT @p4 = 12345.67\r\n" +
                    "SELECT @p5 = 1234567.89\r\n" +
                    "SELECT @p6 = 12345.6789\r\n" +
                    "SELECT @p7 = 12345.6789\r\n" +
                    "SELECT @p8 = 1234567.89\r\n" +
                    "SELECT @p9 = 1234567.89\r\n" +
                    "SELECT @p10 = '1999-12-31 12:30:00'\r\n" +
                    "SELECT @p11 = '1999-12-31 12:30:00'\r\n" +
                    "SELECT @p12 = 'ABCDEFGHIJ'\r\n" +
                    "SELECT @p13 = 0x41424344\r\n" +
                    "SELECT @p14 = 'ABCD'\r\n" +
                    "SELECT @p15 = 0x4142434445464748\r\n" +
                    "SELECT @p16 = 1\r\n" +
                    "RETURN 99\r\n" +
                    "END");
             CallableStatement cstmt = con.prepareCall("{?=call jtds_TestRet (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)}");
             cstmt.registerOutParameter( 1, Types.INTEGER);
             cstmt.registerOutParameter( 2, Types.TINYINT);
             cstmt.registerOutParameter( 3, Types.SMALLINT);
             cstmt.registerOutParameter( 4, Types.INTEGER);
             cstmt.registerOutParameter( 5, Types.REAL);
             cstmt.registerOutParameter( 6, Types.FLOAT);
             cstmt.registerOutParameter( 7, Types.DECIMAL, 4);
             cstmt.registerOutParameter( 8, Types.DECIMAL, 4);
             cstmt.registerOutParameter( 9, Types.DECIMAL);
             cstmt.registerOutParameter(10, Types.DECIMAL);
             cstmt.registerOutParameter(11, Types.TIMESTAMP);
             cstmt.registerOutParameter(12, Types.TIMESTAMP);
             cstmt.registerOutParameter(13, Types.VARCHAR);
             cstmt.registerOutParameter(14, Types.VARBINARY);
             cstmt.registerOutParameter(15, Types.CHAR);
             cstmt.registerOutParameter(16, Types.BINARY);
             cstmt.registerOutParameter(17, Types.BIT);
             cstmt.execute();
             assertEquals(99, cstmt.getInt(1));
             assertEquals(123, cstmt.getByte(2));
             assertEquals(12345, cstmt.getShort(3));
             assertEquals(12345678, cstmt.getInt(4));
             assertEquals("12345.67", new Float(cstmt.getFloat(5)).toString());
             assertEquals("1234567.89", new Double(cstmt.getDouble(6)).toString());
             assertEquals("12345.6789", cstmt.getBigDecimal(7).toString());
             assertEquals("12345.6789", cstmt.getBigDecimal(8).toString());
             assertEquals("1234567.8900000000", cstmt.getBigDecimal(9).toString());
             assertEquals("1234567.8900000000", cstmt.getBigDecimal(10).toString());
             assertEquals("1999-12-31 12:30:00.0", cstmt.getTimestamp(11).toString());
             assertEquals("12:30:00", cstmt.getTime(11).toString());
             assertEquals("1999-12-31", cstmt.getDate(11).toString());
             assertEquals("1999-12-31 12:30:00.0", cstmt.getTimestamp(12).toString());
             assertEquals("ABCDEFGHIJ", cstmt.getString(13));
             assertEquals("ABCD", new String(cstmt.getBytes(14)));
             assertEquals("ABCD", cstmt.getString(15).trim());
             assertEquals("ABCDEFGH", new String(cstmt.getBytes(16)));
             assertTrue(cstmt.getBoolean(17));
             assertTrue(cstmt.getObject(10) instanceof BigDecimal);
             cstmt.close();
             stmt.close();
        } finally {
            dropProcedure("jtds_TestRet");            
        }
    }
    /**
     * Test execution of methods on closed statememt.
     * @throws Exception
     */
    public void testClosed() throws Exception {
        CallableStatement cstmt = con.prepareCall("{call sp_who (?)}");
        cstmt.close();
        String msg = "Invalid state, the CallableStatement object is closed.";
        try {
            cstmt.registerOutParameter(1, Types.NULL);
            fail("Closed test fail-1");
        } catch(SQLException e) {
            assertEquals(msg, e.getMessage());
        }
    }

    /**
     * Test named parameters.
     */
    public void testNamedParameters() throws Exception {
        if (isASA) {
            // ASA does not seem to handle named parameters correctly
            return;
        }
        try {
            dropProcedure("jtds_namedp");
            Statement stmt = con.createStatement();
            stmt.execute("CREATE PROC jtds_namedp @p1 varchar(10)='default', " + 
                    "@p2 int=-1, @p3 varchar(10) output AS\r\n" +
                    "BEGIN\r\n"+
                    "IF @p1 <> 'default'\r\n" +
                    "   SELECT @p3 = '@p1 set'\r\n" +
                    "IF @p2 <> -1 \r\n"  +
                    "   SELECT @p3 = '@p2 set'\r\n" +
                    "RETURN @p2\r\n" +
                    "END");
            CallableStatement cstmt = con.prepareCall("{?=call jtds_namedp (?,?)}");
            cstmt.registerOutParameter("@return_status", Types.INTEGER);
            cstmt.registerOutParameter("@p3", Types.VARCHAR);
            cstmt.setInt("@p2", 100);
            cstmt.execute();
            assertEquals("@p2 set", cstmt.getString("@p3"));
            assertEquals(100, cstmt.getInt("@return_status"));
            cstmt.close();
            //
            cstmt = con.prepareCall("{?=call jtds_namedp (?,?)}");
            cstmt.registerOutParameter("@return_status", Types.INTEGER);
            cstmt.registerOutParameter("@p3", Types.VARCHAR);
            cstmt.setString("@p1", "TEST");
            cstmt.execute();
            assertEquals("@p1 set", cstmt.getString("@p3"));
            assertEquals(-1, cstmt.getInt("@return_status"));
            cstmt.close();
        } finally {
            dropProcedure("jtds_namedp");
        }
    }
    
    /*
     * Test getParameterMetaData
     */
    public void testGetParamMetaData() throws SQLException {
        try {
            dropProcedure("jtds_ptest");
            Statement stmt = con.createStatement();
            stmt.execute("CREATE PROC jtds_ptest @p1 int, @p2 varchar(10) output AS BEGIN SELECT @p2 = CONVERT(varchar(10), @p1) END");
            stmt.close();
            CallableStatement cstmt = con.prepareCall("{?=call jtds_ptest (?,?)}");
            ParameterMetaData pmd = cstmt.getParameterMetaData();
            assertEquals(3, pmd.getParameterCount());
            if (con.getMetaData().getDriverMajorVersion() == 1 
                && con.getMetaData().getDriverMinorVersion() > 2) {
                assertEquals(ParameterMetaData.parameterModeOut, pmd.getParameterMode(1));
                assertEquals(Types.INTEGER, pmd.getParameterType(1));
                assertEquals("int", pmd.getParameterTypeName(1));
                assertEquals("java.lang.Integer", pmd.getParameterClassName(1));
                assertEquals(ParameterMetaData.parameterModeIn, pmd.getParameterMode(2));
                assertEquals(Types.INTEGER, pmd.getParameterType(2));
                assertEquals("int", pmd.getParameterTypeName(2));
                assertEquals("java.lang.Integer", pmd.getParameterClassName(2));
                assertEquals(ParameterMetaData.parameterModeInOut, pmd.getParameterMode(3));
                assertEquals(Types.VARCHAR, pmd.getParameterType(3));
                assertEquals("varchar", pmd.getParameterTypeName(3));
                assertEquals("java.lang.String", pmd.getParameterClassName(3));
            }
            cstmt.close();
        } finally {
            dropProcedure("jtds_ptest");            
        }
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CallableStatementTest.class);
    }
}
