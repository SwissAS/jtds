package net.sourceforge.jtds.test;

import junit.framework.Test;
import junit.framework.TestSuite;
import java.util.Properties;
import java.util.Enumeration;
import java.util.Hashtable;
import java.sql.*;

import net.sourceforge.jtds.jdbc.*;
import net.sourceforge.jtds.jdbcx.JtdsDataSource;


public class ConnectionJDBC2UnitTest extends UnitTestBase {

    /**
     * Construct a test suite for this class.
     * <p/>
     * The test suite includes the tests in this class, and adds tests
     * from {@link DefaultPropertiesTestLibrary} after creating an
     * anonymous {@link DefaultPropertiesTester} object.
     *
     * @return The test suite to run.
     */
    public static Test suite() {

        final TestSuite testSuite = new TestSuite(ConnectionJDBC2UnitTest.class);

        testSuite.addTest(
                ConnectionJDBC2UnitTest.Test_ConnectionJDBC2_unpackProperties.suite(
                        "test_unpackProperties_DefaultProperties"));

        return testSuite;
    }


    /**
     * Constructor.
     *
     * @param name The name of the test.
     */
    public ConnectionJDBC2UnitTest(String name) {
        super(name);
    }


    /**
     * Test that an {@link java.sql.SQLException} is thrown when
     * parsing invalid integer (and long) properties.
     */
    public void test_unpackProperties_invalidIntegerProperty() {
        assertSQLExceptionForBadWholeNumberProperty(Driver.PORTNUMBER);
        assertSQLExceptionForBadWholeNumberProperty(Driver.LOGINTIMEOUT);
    }


    /**
     * Assert that an SQLException is thrown when
     * {@link ConnectionJDBC3#unpackProperties(Properties)} is called
     * with an invalid integer (or long) string set on a property.
     * <p/>
     * Note that because Java 1.3 is still supported, the
     * {@link RuntimeException} that is caught may not contain the
     * original {@link Throwable} cause, only the original message.
     *
     * @param key The message key used to retrieve the property name.
     */
    private void assertSQLExceptionForBadWholeNumberProperty(final String key) {

        final ConnectionJDBC3 instance =
                (ConnectionJDBC3) invokeConstructor(
                        ConnectionJDBC3.class, new Class[]{}, new Object[]{});

        Properties properties =
                (Properties) invokeStaticMethod(
                        DefaultProperties.class, "addDefaultProperties",
                        new Class[]{Properties.class},
                        new Object[]{new Properties()});

        properties.setProperty(Messages.get(key), "1.21 Gigawatts");

        try {
            invokeInstanceMethod(
                    ConnectionJDBC2.class, instance, "unpackProperties",
                    new Class[]{Properties.class},
                    new Object[]{properties});
            fail("RuntimeException expected");
        }
        catch (RuntimeException e) {
            assertEquals("Unexpected exception message",
                         Messages.get("error.connection.badprop", Messages.get(key)),
                         e.getMessage());
        }
    }



    /**
     * Class used to test {@link net.sourceforge.jtds.jdbc.ConnectionJDBC2#unpackProperties(Properties)}.
     */
    public static class Test_ConnectionJDBC2_unpackProperties
            extends DefaultPropertiesTestLibrary {

        /**
         * Construct a test suite for this library.
         *
         * @param name The name of the tests.
         * @return The test suite.
         */
        public static Test suite(String name) {
            return new TestSuite(
                    ConnectionJDBC2UnitTest.Test_ConnectionJDBC2_unpackProperties.class, name);
        }


        /**
         * Default constructor.
         */
        public Test_ConnectionJDBC2_unpackProperties() {
            setTester(
                    new DefaultPropertiesTester() {

                        public void assertDefaultProperty(
                                String message, Properties properties, String fieldName,
                                String key, String expected) {

                            // FIXME: Hack for ConnectionJDBC2
                            {
                                if ("sendStringParametersAsUnicode".equals(fieldName)) {
                                    fieldName = "useUnicode";
                                }
                            }
                            ConnectionJDBC3 instance =
                                    (ConnectionJDBC3) invokeConstructor(
                                            ConnectionJDBC3.class, new Class[]{}, new Object[]{});
                            invokeStaticMethod(
                                    DefaultProperties.class, "addDefaultProperties",
                                    new Class[]{Properties.class},
                                    new Object[]{properties});
                            invokeInstanceMethod(
                                    ConnectionJDBC2.class, instance, "unpackProperties",
                                    new Class[]{Properties.class},
                                    new Object[]{properties});
                            String actual =
                                    String.valueOf(invokeGetInstanceField(ConnectionJDBC2.class,
                                            instance, fieldName));

                            // FIXME: Another hack for ConnectionJDBC2
                            {
                                if ("tdsVersion".equals(fieldName)) {
                                    expected = String.valueOf(DefaultProperties.getTdsVersion(expected));
                                }
                            }

                            assertEquals(message, expected, actual);
                        }
                    }
            );
        }
    }

    /**
     * Creates a <code>Connection</code>, overriding the default properties
     * with the ones provided.
     *
     * @param override the overriding properties
     * @return a <code>Connection</code> object
     */
    private Connection getConnectionOverrideProperties(Hashtable override)
            throws Exception {
        JtdsDataSource ds = new JtdsDataSource();
        ds.setServerName(TestBase.props.getProperty(Messages.get(Driver.SERVERNAME)));
        ds.setUser(TestBase.props.getProperty(Messages.get(Driver.USER)));
        ds.setPassword(TestBase.props.getProperty(Messages.get(Driver.PASSWORD)));

        // Get properties, override with provided values
        for (Enumeration e = override.keys(); e.hasMoreElements();) {
            String key = (String) e.nextElement();
            Object value = override.get(key);
            invokeInstanceMethod(ds,
                    "set" + key.toUpperCase().charAt(0) + key.substring(1),
                    new Class[] {value instanceof Boolean ? boolean.class : value.getClass()},
                    new Object[] {value});
        }

        // Obtain connection
        return ds.getConnection();
    }

    /**
     * Test correct behavior of the <code>charset</code> property.
     * Values should be stored and retrieved using the requested charset rather
     * than the server's as long as Unicode is not used.
     */
    public void testForceCharset1() throws Exception {
        // Set charset to Cp1251 and Unicode parameters to false
        Hashtable props = new Hashtable();
        props.put("charset", "Cp1251");
        props.put("sendStringParametersAsUnicode", Boolean.FALSE);
        // Obtain connection
        Connection con = getConnectionOverrideProperties(props);

        try {
            // Test both sending and retrieving of values
            String value = "\u0410\u0411\u0412";
            PreparedStatement pstmt = con.prepareStatement("select ?");
            pstmt.setString(1, value);
            ResultSet rs = pstmt.executeQuery();
            assertTrue(rs.next());
            assertEquals(value, rs.getString(1));
            assertFalse(rs.next());
            rs.close();

            pstmt.close();
        } finally {
            con.close();
        }
    }

    /**
     * Test correct behavior of the <code>charset</code> property.
     * Stored procedure output parameters should be decoded using the specified
     * charset rather than the server's as long as they are non-Unicode.
     */
    public void testForceCharset2() throws Exception {
        // Set charset to Cp1251 and Unicode parameters to false
        Hashtable props = new Properties();
        props.put("charset", "Cp1251");
        props.put("sendStringParametersAsUnicode", Boolean.FALSE);
        // Obtain connection
        Connection con = getConnectionOverrideProperties(props);

        try {
            Statement stmt = con.createStatement();
            assertEquals(0,
                    stmt.executeUpdate("create procedure #testForceCharset2 "
                    + "@inParam varchar(10), @outParam varchar(10) output as "
                    + "set @outParam = @inParam"));
            stmt.close();

            // Test both sending and retrieving of parameters
            String value = "\u0410\u0411\u0412";
            CallableStatement cstmt =
                    con.prepareCall("{call #testForceCharset2(?, ?)}");
            cstmt.setString(1, value);
            cstmt.registerOutParameter(2, Types.VARCHAR);
            assertEquals(0, cstmt.executeUpdate());
            assertEquals(value, cstmt.getString(2));
            cstmt.close();
        } finally {
            con.close();
        }
    }
}
