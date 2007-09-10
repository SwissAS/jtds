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

import junit.framework.*;
import net.sourceforge.jtds.jdbc.Driver;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;



/**
 * Unit tests for the {@link Driver} class.
 *
 * @author David D. Kilzer
 * @version $Id: DriverUnitTest.java,v 1.21 2007-09-10 19:19:36 bheineman Exp $
 */
public class DriverUnitTest extends TestBase {


    /**
     * Construct a test suite for this class.
     *
     * @return The test suite to run.
     */
    public static Test suite() {
        TestSuite testSuite = new TestSuite(DriverUnitTest.class);

        return testSuite;
    }


    /**
     * Constructor.
     *
     * @param name The name of the test.
     */
    public DriverUnitTest(final String name) {
        super(name);
    }


    /**
     * Tests that passing in a null properties argument to
     * {@link Driver#getPropertyInfo(String, Properties)}
     * causes the url to be parsed, which then throws a {@link SQLException}.
     */
    public void test_getPropertyInfo_ThrowsSQLExceptionWithNullProperties() {
        try {
            new Driver().getPropertyInfo("wxyz:", null);
            fail("Expected SQLException to be throw");
        }
        catch (SQLException e) {
            // Expected
        }
    }


    /**
     * Tests that passing in a non-null properties argument to
     * {@link Driver#getPropertyInfo(String, Properties)}
     * causes the url to be parsed, which then throws a {@link SQLException}.
     */
    public void test_getPropertyInfo_ThrowsSQLExceptionWithNonNullProperties() {
        try {
            new Driver().getPropertyInfo("wxyz:", new Properties());
            fail("Expected SQLException to be throw");
        }
        catch (SQLException e) {
            // Expected
        }
    }

    /**
     * Retrieve the {@link DriverPropertyInfo} array from
     * {@link Driver#getPropertyInfo(String, Properties)} and convert it
     * into a {@link Map} using the <code>name</code> property for the keys.
     *
     * @param driverPropertyInfoMap The map of {@link DriverPropertyInfo} objects to be populated.
     */
    private void loadDriverPropertyInfoMap(final Map driverPropertyInfoMap) {
        try {
            final DriverPropertyInfo[] driverPropertyInfoArray = new Driver().getPropertyInfo(
                                "jdbc:jtds:sqlserver://servername/databasename", new Properties());
            for (int i = 0; i < driverPropertyInfoArray.length; i++) {
                DriverPropertyInfo driverPropertyInfo = driverPropertyInfoArray[i];
                driverPropertyInfoMap.put(driverPropertyInfo.name, driverPropertyInfo);
            }
        }
        catch (SQLException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
