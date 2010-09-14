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

import net.sourceforge.jtds.jdbc.DefaultProperties;
import net.sourceforge.jtds.jdbc.Messages;
import net.sourceforge.jtds.jdbc.Driver;
import java.util.Properties;


/**
 * Unit tests for the {@link net.sourceforge.jtds.jdbc.DefaultProperties} class.
 *
 * @author David D. Kilzer
 * @version $Id: DefaultPropertiesUnitTest.java,v 1.7.4.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public class DefaultPropertiesUnitTest extends UnitTestBase {

    /**
     * Constructor.
     *
     * @param name The name of the test.
     */
    public DefaultPropertiesUnitTest(String name) {
        super(name);
    }


    /**
     * Tests that
     * {@link DefaultProperties#addDefaultPropertyIfNotSet(java.util.Properties, java.lang.String, java.lang.String)}
     * sets a default property if the property is not already set.
     */
    public void test_addDefaultPropertyIfNotSet_PropertyNotSet() {
        final Properties properties = new Properties();
        final String key = Driver.DATABASENAME;
        final String defaultValue = "foobar";
        invokeStaticMethod(
                DefaultProperties.class, "addDefaultPropertyIfNotSet",
                new Class[]{Properties.class, String.class, String.class},
                new Object[]{properties, key, defaultValue});
        assertEquals(defaultValue, properties.get(Messages.get(key)));
    }


    /**
     * Tests that
     * {@link DefaultProperties#addDefaultPropertyIfNotSet(java.util.Properties, java.lang.String, java.lang.String)}
     * does <em>not</em> set a default property if the property is already set.
     */
    public void test_addDefaultPropertyIfNotSet_PropertyAlreadySet() {
        final Properties properties = new Properties();
        final String key = Driver.DATABASENAME;
        final String presetValue = "barbaz";
        final String defaultValue = "foobar";
        properties.setProperty(Messages.get(key), presetValue);
        invokeStaticMethod(DefaultProperties.class, "addDefaultPropertyIfNotSet",
                           new Class[]{Properties.class, String.class, String.class},
                           new Object[]{properties, key, defaultValue});
        assertEquals(presetValue, properties.get(Messages.get(key)));
    }


    public void test_getTdsVersion_StringToInteger_Null() {
        final String message = "Did not return null for unknown TDS version: ";
        final String[] testValues = new String[]{ null, "", "4.0", "5.2", "0.0", "8:0" };
        for (int i = 0; i < testValues.length; i++) {
            assertNull(
                    message + String.valueOf(testValues[i]),
                    DefaultProperties.getTdsVersion(testValues[i]));
        }
    }


    public void test_getTdsVersion_StringToInteger_TDS70() {
        assertEquals(
                "Tds version for TDS 7.0 did not map correctly",
                new Integer(Driver.TDS70),
                DefaultProperties.getTdsVersion(DefaultProperties.TDS_VERSION_70));
    }


    public void test_getTdsVersion_StringToInteger_TDS80() {
        assertEquals(
                "Tds version for TDS 8.0 did not map correctly",
                new Integer(Driver.TDS80),
                DefaultProperties.getTdsVersion(DefaultProperties.TDS_VERSION_80));
    }

}
