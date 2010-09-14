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

import java.text.MessageFormat;
import java.util.ResourceBundle;


/**
 * Support class for <code>Messages.properties</code>.
 *
 * @author David D. Kilzer
 * @author Mike Hutchinson
 */
public final class Messages {


    /**
     * Cached resource bundle containing the messages.
     * <p>
     * <code>ResourceBundle</code> does caching internally but this caching
     * involves a lot of string operations to generate the keys used for
     * caching, leading to a lot of <code>StringBuffer</code> reallocation. In
     * one run through the complete jTDS test suite there were over 60000
     * allocations and reallocations (about one for each <code>get()</code>
     * call).
     */
    private static ResourceBundle defaultResource;


    /**
     * Default constructor.  Private to prevent instantiation.
     */
    private Messages() {
        // Default constructor
    }


    /**
     * Get runtime message using supplied key.
     *
     * @param key The key of the message in Messages.properties
     * @return The selected message as a <code>String</code>.
     */
    public static String get(final String key) {
        return get(key, null);
    }


    /**
     * Get runtime message using supplied key and substitute parameter
     * into message.
     *
     * @param key The key of the message in Messages.properties
     * @param param1 The object to insert into message.
     * @return The selected message as a <code>String</code>.
     */
    public static String get(final String key, final Object param1) {
        Object args[] = {param1};
        return get(key, args);
    }


    /**
     * Get runtime message using supplied key and substitute parameters
     * into message.
     *
     * @param key The key of the message in Messages.properties
     * @param param1 The object to insert into message.
     * @param param2 The object to insert into message.
     * @return The selected message as a <code>String</code>.
     */
    static String get(final String key, final Object param1, final Object param2) {
        Object args[] = {param1, param2};
        return get(key, args);
    }

    /**
     * Get runtime error using supplied key and substitute parameters
     * into message.
     *
     * @param key The key of the error message in Messages.properties
     * @param arguments The objects to insert into the message.
     * @return The selected error message as a <code>String</code>.
     */
    private static String get(final String key, final Object[] arguments) {
        try {
            ResourceBundle bundle = loadResourceBundle();
            String formatString = bundle.getString(key);
            // No need for any formatting if no parameters are specified
            if (arguments == null || arguments.length == 0) {
                return formatString;
            }
            MessageFormat formatter = new MessageFormat(formatString);
            return formatter.format(arguments);
        } catch (java.util.MissingResourceException mre) {
            throw new RuntimeException("No message resource found for message property " + key);
        }
    }

    /**
     * Load the {@link #DEFAULT_RESOURCE} resource bundle.
     *
     * @return The resource bundle.
     */
    private static ResourceBundle loadResourceBundle() {
        if (defaultResource == null) {
            defaultResource = ResourceBundle.getBundle(ConnectionImpl.DEFAULT_RESOURCE);
        }
        return defaultResource;
    }

}
