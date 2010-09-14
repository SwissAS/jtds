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
import java.sql.Blob;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 */
public class BlobTest extends TestBase {

    public BlobTest(String name) {
        super(name);
    }

    /**
     * Test position methods 
     * @throws Exception
     */
    public void testBlobMethods() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #TESTBLOB (id int, blob image null)");
        assertEquals(1, stmt.executeUpdate(
                "INSERT INTO #TESTBLOB (id) VALUES (1)"));
        assertEquals(1, stmt.executeUpdate(
                "INSERT INTO #TESTBLOB (id, blob) VALUES (2, 0x4445)"));
        assertEquals(1, stmt.executeUpdate(
                "INSERT INTO #TESTBLOB (id, blob) VALUES (3, 0x4142434445464748)"));
        ResultSet rs = stmt.executeQuery("SELECT * FROM #TESTBLOB");
        assertNotNull(rs);
        assertTrue(rs.next());
        assertEquals(1, rs.getInt(1));
        Blob blob = rs.getBlob(2);
        assertNull(blob);
        assertTrue(rs.next());
        assertEquals(2, rs.getInt(1));
        Blob pattern = rs.getBlob(2);
        assertNotNull(pattern);
        assertTrue(rs.next());
        assertEquals(3, rs.getInt(1));
        blob  = rs.getBlob(2);
        assertEquals(8, blob.length());
        assertEquals("ABCDEFGH", new String(blob.getBytes(1, 8)));
        assertEquals(4, blob.position(pattern, 1));
        assertEquals(-1, blob.position(pattern, 8));
        assertEquals(3, blob.position(new byte[]{0x43,0x44}, 1));
        assertEquals(-1, blob.position(new byte[]{0x43,0x44}, 8));
        byte buf[] = new byte[(int)blob.length()];
        InputStream is = blob.getBinaryStream();
        assertEquals((int)blob.length(), is.read(buf));
        assertEquals(-1, is.read());
        assertEquals("ABCDEFGH", new String(buf));
    }
    
    /**
     * Test Long blob manipluation including updates to middle of BLOB
     * @throws Exception
     */
    public void testBlob() throws Exception {
        byte[] data = new byte[100000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte)('A'+i%10);
        }
        //
        // Construct a blob
        //
        Statement stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT 0x00");
        assertNotNull(rs);
        assertTrue(rs.next());
        Blob blob = rs.getBlob(1);
        blob.setBytes(1, data);
        byte[] tmp = blob.getBytes(1, (int)blob.length());
        assertTrue(compare(data, tmp));
        blob.setBytes(1, data);
        tmp = blob.getBytes(1, (int)blob.length());
        assertTrue(compare(data, tmp));
        data[100] = 'a';
        data[101] = 'b';
        blob.setBytes(101, data, 100, 2);
        tmp = blob.getBytes(1, (int)blob.length());
        assertTrue(compare(data, tmp));
        InputStream is = blob.getBinaryStream();
        tmp = new byte[data.length];
        int b;
        int p = 0;
        while ((b = is.read()) >= 0) {
            tmp[p++] = (byte)b;
        }
        is.close();
        assertTrue(compare(data, tmp));
        tmp = blob.getBytes(101, 2);
        assertTrue(compare(new byte[]{'a','b'}, tmp));
        blob = rs.getBlob(1);
        OutputStream os = blob.setBinaryStream(1);
        for (int i = 0; i < data.length; i++) {
            os.write(('A'+i%10));
        }
        os.close();
        os = blob.setBinaryStream(101);
        os.write('a');
        os.write('b');
        os.close();
        tmp = blob.getBytes(1, (int)blob.length());
        assertTrue(compare(data, tmp));
        tmp = new byte[5000];
        for (int i = 0; i < 5000; i++) {
            tmp[i] = (byte)(0x80 + (i % 10)); 
        }
        blob.setBytes(100000-5000, tmp);
        assertTrue(compare(tmp, blob.getBytes(100000-5000, 5000)));
        assertEquals(100000L, blob.length());
        assertEquals(100000-5000, blob.position(tmp, 100000-5000));

        rs = stmt.executeQuery("SELECT 0x00");
        assertNotNull(rs);
        assertTrue(rs.next());
        Blob blob2 = rs.getBlob(1);
        blob2.setBytes(1, tmp);
        assertEquals(100000-5000, blob.position(blob2, 1));
        assertEquals(101, blob.position(new byte[]{'a','b'}, 1));
        blob.truncate(10);
        assertEquals(10L, blob.length());
        tmp = new byte[10];
        System.arraycopy(data, 0, tmp, 0, 10);
        assertTrue(compare(tmp, blob.getBytes(1, (int)blob.length())));
    }

    /**      
     * Compare long byte arrays
     */
    public boolean compare(byte []b1, byte[] b2) {
        if (b1.length != b2.length) {
            System.out.println("Compare failed: lengths differ");
            return false;
        }
        for (int i = 0; i < b1.length; i++) {
            if (b1[i] != b2[i]) {
                System.out.println("Compare failed: bytes at " + i + " differ ["
                        + b1[i] + "] [" + b2[i] + "]");
                return false;
            }
        }
        return true;
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(BlobTest.class);
    }
}
