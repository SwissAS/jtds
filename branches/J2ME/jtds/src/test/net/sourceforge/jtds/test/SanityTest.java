package net.sourceforge.jtds.test;

import java.sql.*;

/**
 * Some simple tests just to make sure everything is working properly.
 *
 * @created    9 August 2001
 * @version    1.0
 */

public class SanityTest extends TestBase {
    public SanityTest(String name) {
        super(name);
    }

    /**
     * A simple test to make sure everything seems to be OK
     */
    public void testSanity() throws Exception {
        Statement stmt = con.createStatement();
        makeTestTables(stmt);
        makeObjects(stmt, 5);
        stmt.close();
    }

    /**
     * Basic test of cursor mechanisms.
     */
    public void testCursorStatements() throws Exception {
        Statement stmt = con.createStatement();
        makeTestTables(stmt);
        makeObjects(stmt, 5);

        ResultSet rs;

        assertEquals("Expected an update count", false,
                     stmt.execute( "DECLARE cursor1 SCROLL CURSOR FOR"
                                   + "\nSELECT * FROM #test"));

        showWarnings(stmt.getWarnings());

        assertEquals("Expected an update count", false,
                     stmt.execute("OPEN cursor1"));

        rs = stmt.executeQuery("FETCH LAST FROM cursor1");
        dump(rs);
        rs.close();

        rs = stmt.executeQuery("FETCH FIRST FROM cursor1");
        dump(rs);
        rs.close();

        stmt.execute("CLOSE cursor1");
        stmt.execute("DEALLOCATE cursor1");
        stmt.close();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SanityTest.class);
    }
}
