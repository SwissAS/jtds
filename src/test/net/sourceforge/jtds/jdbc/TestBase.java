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

import java.io.*;
import java.sql.*;

import java.util.*;
import junit.framework.TestCase;

/**
 * @author  builder
 * @version $Id: TestBase.java,v 1.1 2007-09-10 19:19:35 bheineman Exp $
 */
public abstract class TestBase extends TestCase {

    private static final String CONNECTION_PROPERTIES = "conf/connection.properties";
    public static final Properties props = loadProperties(CONNECTION_PROPERTIES);
    public Connection con;
    public boolean isSybase = false;
    public boolean isSyb11  = false;
    public boolean isSyb12  = false;
    public boolean isSyb15  = false;
    public boolean isSql65  = false;
    public boolean isSql70  = false;
    public boolean isSql2K  = false;
    public boolean isSql2005 = false;
    public boolean isASA    = false;
    
    public TestBase(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        super.setUp();
        connect();
    }

    public void tearDown() throws Exception {
        disconnect();
        super.tearDown();
    }

    public Connection getConnection() throws Exception {
        Class.forName(props.getProperty("driver"));
        String url = props.getProperty("url");
        Connection con = DriverManager.getConnection(url, props);
        String prodName = con.getMetaData().getDatabaseProductName();
        String prodVer  = con.getMetaData().getDatabaseProductVersion();
        if (prodName.toLowerCase().startsWith("microsoft")) {
            if (prodVer.startsWith("6.")) {
                isSql65 = true;
            } else
            if (prodVer.startsWith("07.")) {
                isSql70 = true;
            } else {
                isSql2K = true;
            }
            if (prodVer.startsWith("09.")) {
                isSql2005 = true;
            }
        } else {
            isSybase = true;
            if (prodName.toLowerCase().startsWith("adaptive")) {
                isSyb12 = true; // Best option
                isASA = true;
            } else {
                if (prodVer.startsWith("12")) {
                    isSyb12 = true;
                } else {
                    if (prodVer.startsWith("15")) {
                        isSyb12 = true;
                        isSyb15 = true;
                    } else {
                        isSyb11 = true;
                    }
                }
            }
        }
//        System.out.println(con.getMetaData().getDatabaseProductName());
//        System.out.println(con.getMetaData().getDatabaseProductVersion());
//        System.out.println(con.getMetaData().getDatabaseMajorVersion());
//        System.out.println(con.getMetaData().getDatabaseMinorVersion());
        showWarnings(con.getWarnings());
        initLanguage(con);

        return con;
    }

    public Connection getConnection(Properties override) throws Exception {
        Properties newProps = new Properties(props);
        for (Iterator it = override.keySet().iterator(); it.hasNext();) {
            String key = (String) it.next();
            newProps.setProperty(key, override.getProperty(key));
        }

        Class.forName(newProps.getProperty("driver"));
        String url = newProps.getProperty("url");
        return DriverManager.getConnection(url, newProps);
    }

    public void showWarnings(SQLWarning w) {
        while (w != null) {
            System.out.println(w.getMessage());
            w = w.getNextWarning();
        }
    }

    private void disconnect() throws Exception {
        if (con != null) {
            con.close();
            con = null;
        }
    }

    protected void connect() throws Exception {
        disconnect();
        con = getConnection();
    }

    public void dump(ResultSet rs) throws SQLException {
        ResultSetMetaData rsm = rs.getMetaData();
        int cols = rsm.getColumnCount();

        for (int i = 1; i <= cols; i++) {
            if (i > 1) {
                System.out.print(", ");
            }

            System.out.print(rsm.getColumnName(i));
        }

        System.out.println();

        while (rs.next()) {
            dumpRow(rs);
        }
    }

    public void dumpRow(ResultSet rs) throws SQLException {
        ResultSetMetaData rsm = rs.getMetaData();
        int cols = rsm.getColumnCount();

        for (int i = 1; i <= cols; i++) {
            if (i > 1) {
                System.out.print(", ");
            }

            System.out.print(rs.getObject(i));
        }

        System.out.println();
    }

    private void initLanguage(Connection con) throws SQLException {
        Statement stmt = con.createStatement();

//        stmt.executeUpdate("set LANGUAGE 'us_english'");
        stmt.close();
    }

    private static Properties loadProperties(String fileName) {

        File propFile = new File(fileName);

        if (!propFile.exists()) {
            fail("Connection properties not found (" + propFile + ").");
        }

        try {
            Properties props = new Properties();
            props.load(new FileInputStream(propFile));
            return props;
        }
        catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    protected void makeTestTables(Statement stmt) throws SQLException {
        String sql = "CREATE TABLE #test ("
                     + " f_int INT,"
                     + " f_varchar VARCHAR(255))";

        stmt.execute(sql);
    }

    public void makeObjects(Statement stmt, int count) throws SQLException {
        stmt.execute("TRUNCATE TABLE #test");

        for (int i = 0; i < count; i++) {
            String sql = "INSERT INTO #test(f_int, f_varchar)"
                         + " VALUES (" + i + ", 'Row " + i + "')";
            stmt.execute(sql);
        }
    }

    public void compareInputStreams(InputStream is1, InputStream is2) throws IOException {
        try {
            if (is1 == null && is2 == null) {
                return;
            } else if (is1 == null) {
                fail("is1 == null && is2 != null");
                return;
            } else if (is2 == null) {
                fail("is1 != null && is2 == null");
                return;
            }

            long count = 0;
            int res1 = 0, res2 = 0;
            byte buf1[] = new byte[1024], buf2[] = new byte[1024];

            while (res1 != 0 || (res1 = is1.read(buf1)) != -1) {
                if (res2 == 0) {
                    res2 = is2.read(buf2);
                }

                if (res2 == -1) {
                    fail("stream 2 EOF at: " + count);
                }

                int min = Math.min(res1, res2);
                for (int i = 0; i < min; i++) {
                    // Do the check first rather than using assertTrue()
                    // assertTrue() would create a String at each iteration
                    if (buf1[i] != buf2[i]) {
                        fail("stream 1 value [" + buf1[i]
                                + "] differs from stream 2 value ["
                                + buf2[i] + "] at: " + (count + i));
                    }
                }

                count += min;

                if (res1 != min) {
                    System.arraycopy(buf1, min, buf1, 0, res1 - min);
                    res1 -= min;
                } else {
                    res1 = 0;
                }

                if (res2 != min) {
                    System.arraycopy(buf2, min, buf2, 0, res2 - min);
                    res2 -= min;
                } else {
                    res2 = 0;
                }
            }

            if (is2.read() != -1) {
                fail("stream 1 EOF at: " + count);
            }
        } finally {
            if (is1 != null) {
                is1.close();
            }

            if (is2 != null) {
                is2.close();
            }
        }
    }

    public void compareReaders(Reader r1, Reader r2) throws IOException {
        try {
            if (r1 == null && r2 == null) {
                return;
            } else if (r1 == null) {
                fail("r1 == null && r2 != null");
                return;
            } else if (r2 == null) {
                fail("r1 != null && r2 == null");
                return;
            }

            long count = 0;
            int res1 = 0, res2 = 0;
            char buf1[] = new char[1024], buf2[] = new char[1024];

            while (res1 != 0 || (res1 = r1.read(buf1)) != -1) {
                if (res2 == 0) {
                    res2 = r2.read(buf2);
                }

                if (res2 == -1) {
                    fail("reader 2 EOF at: " + count);
                }

                int min = Math.min(res1, res2);
                for (int i = 0; i < min; i++) {
                    // Do the check first rather than using assertTrue()
                    // assertTrue() would create a String at each iteration
                    if (buf1[i] != buf2[i]) {
                        fail("stream 1 value [" + buf1[i]
                                + "] differs from stream 2 value ["
                                + buf2[i] + "] at: " + (count + i));
                    }
                }

                count += min;

                if (res1 != min) {
                    System.arraycopy(buf1, min, buf1, 0, res1 - min);
                    res1 -= min;
                } else {
                    res1 = 0;
                }

                if (res2 != min) {
                    System.arraycopy(buf2, min, buf2, 0, res2 - min);
                    res2 -= min;
                } else {
                    res2 = 0;
                }
            }

            if (r2.read() != -1) {
                fail("reader 1 EOF at: " + count);
            }
        } finally {
            if (r1 != null) {
                r1.close();
            }

            if (r2 != null) {
                r2.close();
            }
        }
    }
    protected void dropTable(String tableName) throws SQLException {
        String sobName = "sysobjects";
        String tableLike = tableName;

        if (tableName.startsWith("#")) {
            sobName = "tempdb.dbo.sysobjects";
            tableLike = tableName + "%";
        }

        Statement stmt = con.createStatement();
        stmt.executeUpdate(
                          "if exists (select * from " + sobName + " where name like '" + tableLike + "' and type = 'U') "
                          + "drop table " + tableName);
        stmt.close();
    }

    protected void dropProcedure(String procname) throws SQLException {
        Statement stmt = con.createStatement();
        dropProcedure(stmt, procname);
        stmt.close();
    }

    protected void dropProcedure(Statement stmt, String procname) throws SQLException {
        String sobName = "sysobjects";
        if (procname.startsWith("#")) {
            sobName = "tempdb.dbo.sysobjects";
        }
        stmt.executeUpdate(
                          "if exists (select * from " + sobName + " where name like '" + procname + "%' and type = 'P') "
                          + "drop procedure " + procname);
    }
    
    protected void dropFunction(String procname) throws SQLException {
        String sobName = "sysobjects";
        Statement stmt = con.createStatement();
        stmt.executeUpdate(
                          "if exists (select * from " + sobName + " where name like '" + procname + "%' and type = 'FN') "
                          + "drop function " + procname);
        stmt.close();
    }
    
    /**
     * Utility method to check column names and number.
     *
     * @param rs    the result set to check
     * @param names the list of column names to compare to result set
     * @return the <code>boolean</code> value true if the columns match
     */
    protected boolean checkColumnNames(ResultSet rs, String[] names)
            throws SQLException {
        ResultSetMetaData rsmd = rs.getMetaData();
        if (rsmd.getColumnCount() < names.length) {
            System.out.println("Cols=" + rsmd.getColumnCount());
            return false;
        }

        for (int i = 1; i <= names.length; i++) {
            if (names[i - 1].length() > 0
                    && !rsmd.getColumnLabel(i).equals(names[i - 1])) {
                System.out.println(
                        names[i - 1] + " = " + rsmd.getColumnLabel(i));
                return false;
            }
        }

        return true;
    }

}
