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

import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.sql.Clob;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 */
public class ClobTest extends TestBase {

    public ClobTest(String name) {
        super(name);
    }

    /**
     * Test Clob class position methods
     * @throws Exception
     */
    public void testBlobMethods() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TESTCLOB (id int, clob text null)");
        assertEquals(1, stmt.executeUpdate(
                "INSERT INTO #TESTCLOB (id) VALUES (1)"));
        assertEquals(1, stmt.executeUpdate(
                "INSERT INTO #TESTCLOB (id, clob) VALUES (2, 'CD')"));
        assertEquals(1, stmt.executeUpdate(
                "INSERT INTO #TESTCLOB (id, clob) VALUES (3, 'ABCDEFGH')"));
        ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTCLOB");
        assertNotNull(rs);
        assertTrue(rs.next());
        assertEquals(1, rs.getInt(1));
        Clob clob = rs.getClob(2);
        assertNull(clob);
        assertTrue(rs.next());
        assertEquals(2, rs.getInt(1));
        Clob pattern = rs.getClob(2);
        assertNotNull(pattern);
        assertTrue(rs.next());
        assertEquals(3, rs.getInt(1));
        clob  = rs.getClob(2);
        assertEquals(8, clob.length());
        assertEquals("ABCDEFGH", clob.getSubString(1, 8));
        assertEquals(3, clob.position(pattern, 1));
        assertEquals(-1, clob.position(pattern, 8));
        assertEquals(3, clob.position("CD", 1));
        assertEquals(-1, clob.position("CD", 8));
        Reader rdr = clob.getCharacterStream();
        char buf[] = new char[(int)clob.length()];
        assertEquals((int)clob.length(), rdr.read(buf));
        assertEquals(-1, rdr.read());
        assertEquals("ABCDEFGH", new String(buf));
        byte bbuf[] = new byte[(int)clob.length()];
        InputStream is = clob.getAsciiStream();
        assertEquals((int)clob.length(), is.read(bbuf));
        assertEquals(-1, is.read());
        assertEquals("ABCDEFGH", new String(bbuf));
    }
    
    /**
     * Test long Clob manipulation including indexed writes.
     * @throws Exception
     */
    public void testClob() throws Exception {
        int size = 100000;
        StringBuffer data = new StringBuffer(size);
        for (int i = 0; i < size; i++) {
            data.append((char)('A'+i%10));
        }
        //
        // Construct a clob
        //
        Statement stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT ''");
        assertNotNull(rs);
        assertTrue(rs.next());
        Clob clob = rs.getClob(1);
        clob.setString(1, data.toString());
        assertEquals((long)size, clob.length());
        assertTrue(data.toString().equals(clob.getSubString(1, (int)clob.length())));
        clob.setString(10, "THIS IS A TEST");
        data.replace(9, 23, "THIS IS A TEST");
        assertEquals("THIS IS A TEST", clob.getSubString(10, 14));
        assertTrue(compare(data.toString(), clob.getSubString(1, (int)clob.length())));
        clob.truncate(23);
        assertEquals("ABCDEFGHITHIS IS A TEST", clob.getSubString(1, 23));
        OutputStream os = clob.setAsciiStream(1);
        for (int i = 0; i < size; i++) {
            os.write(data.charAt(i));
        }
        os.close();
        assertEquals((long)size, clob.length());
        assertTrue(data.toString().equals(clob.getSubString(1, (int)clob.length())));
        InputStream is = clob.getAsciiStream();
        int b;
        int p = 0;
        while ((b = is.read()) >= 0) {
            if ((char)b != data.charAt(p++)) {
                fail("Mismatch at " + p);
            }
        }
        is.close();
        assertTrue(p == size);
        Reader rdr = clob.getCharacterStream();
        p = 0;
        while ((b = rdr.read()) >= 0) {
            if ((char)b != data.charAt(p++)) {
                fail("Mismatch at " + p);
            }
        }
        rdr.close();
        assertTrue(p == size);
        clob.truncate(0);
        Writer wtr = clob.setCharacterStream(1);
        for (int i = 0; i < size; i++) {
            wtr.write(data.charAt(i));
        }
        wtr.close();
        assertTrue(p == size);
        assertTrue(data.toString().equals(clob.getSubString(1, (int)clob.length())));
        wtr = clob.setCharacterStream(10000);
        for (int i = 0; i < 8; i++) {
            wtr.write('X');
        }
        wtr.close();
        data.replace(10000-1, 10000-1+8, "XXXXXXXX");
        assertTrue(data.toString().equals(clob.getSubString(1, (int)clob.length())));
        clob.setString(100001, "XTESTX", 1, 4);
        assertEquals((long)100000+4, clob.length());
        assertEquals("JTEST", clob.getSubString(100000, 8));
        assertEquals(100000, clob.position("JTEST", 100000));
  //      Clob clob2 = rs.getClob(1);
        clob.setString(1, "XXXXXXXX");
        assertEquals(10000, clob.position("XXXXXXXX", 10000));
        assertFalse(10000 == clob.position("XXXXXXXX", 10001));
    }

    /**
     * Compare long Strings
     */
    public boolean compare(String s1, String s2) {
        if (s1.length() != s2.length()) {
            System.out.println("Compare failed: lengths differ");
            return false;
        }
        for (int i = 0; i < s1.length(); i++) {
            if (s1.charAt(i) != s2.charAt(i)) {
                System.out.println("Compare failed: bytes at " + i + " differ ["
                        + s1.charAt(i) + "] [" + s2.charAt(i) + "]");
                return false;
            }
        }
        return true;
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ClobTest.class);
    }
}
