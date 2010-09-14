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

import junit.framework.Test;
import junit.framework.TestCase;
import net.sourceforge.jtds.jdbc.DefaultProperties;
import net.sourceforge.jtds.jdbc.Driver;
import java.util.Properties;



/**
 * Library for testing default properties.
 * <p/>
 * Uses a {@link DefaultPropertiesTester} object to test different methods
 * in different classes.
 * <p/>
 * To extend this class, the programmer must implement the following items:
 * <ol>
 * <li>Set the {@link #tester} field in a <code>public</code> default
 *     constructor that takes no arguments.</li>
 * <li>A <code>public static Test suite()</code> method that takes one or more
 *     arguments.  (The {@link #suite()} method in this class should
 *     <em>not</em> be overridden.)</li>
 * </ol>
 *
 * @author David D. Kilzer
 * @version $Id: DefaultPropertiesTestLibrary.java,v 1.14.2.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public abstract class DefaultPropertiesTestLibrary extends TestCase {

    /** Object used to run all of the tests. */
    private DefaultPropertiesTester tester;


    /**
     * Provides a null test suite so that JUnit will not try to instantiate
     * this class directly.
     *
     * @return The test suite (always <code>null</code>).
     */
    public static final Test suite() {
        return null;
    }


    /**
     * Default constructor.
     * <p/>
     * The extender of this class is required to set the {@link #tester}
     * field in a <code>public</code> default constructor.
     */
    public DefaultPropertiesTestLibrary() {
    }


    /**
     * Test the <code>tds</code> (version) property.
     */
    public void test_tds() {
        String fieldName = "tdsVersion";
        String messageKey = Driver.TDS;
        assertDefaultProperty(messageKey, fieldName, DefaultProperties.TDS_VERSION_80);
    }


    /**
     * Test the <code>portNumber</code> property.
     * <p/>
     * Different values are set depending on whether SQL Server or
     * Sybase is used.
     */
    public void test_portNumber() {
        String fieldName = "portNumber";
        String messageKey = Driver.PORTNUMBER;
        assertDefaultProperty(messageKey, fieldName, String.valueOf(DefaultProperties.PORT_NUMBER_SQLSERVER));
    }


    /**
     * Test the <code>databaseName</code> property.
     */
    public void test_databaseName() {
        String fieldName = "databaseName";
        String messageKey = Driver.DATABASENAME;
        String expectedValue = DefaultProperties.DATABASE_NAME;
        assertDefaultProperty(messageKey, fieldName, expectedValue);
    }


    /**
     * Test the <code>appName</code> property.
     */
    public void test_appName() {
        String fieldName = "appName";
        String messageKey = Driver.APPNAME;
        String expectedValue = DefaultProperties.APP_NAME;
        assertDefaultProperty(messageKey, fieldName, expectedValue);
    }


    /**
     * Test the <code>lastUpdateCount</code> property.
     */
    public void test_lastUpdateCount() {
        String fieldName = "lastUpdateCount";
        String messageKey = Driver.LASTUPDATECOUNT;
        String expectedValue = String.valueOf(DefaultProperties.LAST_UPDATE_COUNT);
        assertDefaultProperty(messageKey, fieldName, expectedValue);
    }


    /**
     * Test the <code>loginTimeout</code> property.
     */
    public void test_loginTimeout() {
        String fieldName = "loginTimeout";
        String messageKey = Driver.LOGINTIMEOUT;
        String expectedValue = String.valueOf(DefaultProperties.LOGIN_TIMEOUT);
        assertDefaultProperty(messageKey, fieldName, expectedValue);
    }


    /**
     * Test the <code>macAddress</code> property.
     */

    public void test_macAddress() {
        String fieldName = "macAddress";
        String messageKey = Driver.MACADDRESS;
        String expectedValue = DefaultProperties.MAC_ADDRESS;
        assertDefaultProperty(messageKey, fieldName, expectedValue);
    }


    /**
     * Test the <code>progName</code> property.
     */
    public void test_progName() {
        String fieldName = "progName";
        String messageKey = Driver.PROGNAME;
        String expectedValue = DefaultProperties.PROG_NAME;
        assertDefaultProperty(messageKey, fieldName, expectedValue);
    }


    /**
     * Test the <code>sendStringParametersAsUnicode</code> property.
     */
    public void test_sendStringParametersAsUnicode() {
        String fieldName = "sendStringParametersAsUnicode";
        String messageKey = Driver.SENDSTRINGPARAMETERSASUNICODE;
        String expectedValue = String.valueOf(DefaultProperties.USE_UNICODE);
        assertDefaultProperty(messageKey, fieldName, expectedValue);
    }


    /**
     * Test the <code>tcpNoDelay</code> property.
     */
    public void test_tcpNoDelay() {
        String fieldName = "tcpNoDelay";
        String messageKey = Driver.TCPNODELAY;
        String expectedValue = String.valueOf(DefaultProperties.TCP_NODELAY);
        assertDefaultProperty(messageKey, fieldName, expectedValue);
    }


    /**
     * Assert that the <code>expected</code> property value is set.
     *
     * @param key The message key.
     * @param fieldName The field name used in the class.
     * @param expected The expected value of the property.
     */
    private void assertDefaultProperty(String key, String fieldName,
                                       String expected) {
        getTester().assertDefaultProperty("Default property incorrect",
                new Properties(), fieldName, key, expected);
    }


    /**
     * Getter for {@link #tester}.
     *
     * @return Value of {@link #tester}.
     */
    protected DefaultPropertiesTester getTester() {
        return tester;
    }


    /**
     * Setter for {@link #tester}.
     *
     * @param tester The value to set {@link #tester} to.
     */
    public void setTester(DefaultPropertiesTester tester) {
        this.tester = tester;
    }
}
