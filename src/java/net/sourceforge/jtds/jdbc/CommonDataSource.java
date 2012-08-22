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

import java.io.PrintWriter;
import java.io.Serializable;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.naming.StringRefAddr;
import javax.naming.spi.ObjectFactory;

import java.util.Iterator;

/**
 * Class to provide common support for connection properties across all 
 * DataSource classes.
 *
 */
public class CommonDataSource implements Referenceable, Serializable, ObjectFactory {
    static final long serialVersionUID = 4814067721903151136L;
    
    /** Table of connection property names and defaults. */
    private final static HashMap<String,String> propNames = new HashMap<String,String>();
    
    static {
        propNames.put("appName",         "jTDS");
        propNames.put("batchSize",       "0");
        propNames.put("bindAddress",     "");
        propNames.put("cacheMetaData",   "false");
        propNames.put("charset",         "");
        propNames.put("databaseName",    "");
        propNames.put("dataSourceName",  "");
        propNames.put("description",     "");
        propNames.put("domain",          "");
        propNames.put("instance",        "");
        propNames.put("language",        "");
        propNames.put("lastUpdateCount",  "true");
        propNames.put("lobBuffer",       "32768");
        propNames.put("logFile",         "");
        propNames.put("logLevel",        "1");
        propNames.put("loginTimeout",    "0");
        propNames.put("macAddress",      "000000000000");
        propNames.put("maxStatements",   "500");
        propNames.put("namedPipePath",   "/sql/query");
        propNames.put("networkProtocol", "tcp");
        propNames.put("packetSize",      "0");
        propNames.put("password",        "");
        propNames.put("portNumber",      "1433");
        propNames.put("prepareSql",      "3");
        propNames.put("progName",        "jTDS");
        propNames.put("roleName",        "");
        propNames.put("sendStringParametersAsUnicode", "true");
        propNames.put("serverName",      "");
        propNames.put("serverType",      "sqlserver");
        propNames.put("socketTimeout",   "0");
        propNames.put("ssl",             "off");
        propNames.put("tcpNoDelay",      "true");
        propNames.put("tds",             "");
        propNames.put("useCursors",      "false");
        propNames.put("useJCIFS",        "false");
        propNames.put("useLOBs",         "true");
        propNames.put("useNTLMv2",       "false");
        propNames.put("useKerberos",     "false");
        propNames.put("user",            "");
        propNames.put("wsid",            "");
        propNames.put("xaEmulation",     "false");
    }

    /** Map of connection property names and current values. */
    private HashMap<String,String> conProps = new HashMap<String,String>();
     
    private transient PrintWriter logWriter;

    CommonDataSource( ) {
        // Default constructor to satisfy beans contract
    }

    /**
     * Construct a CommonDataSource and load connection properties from 
     * supplied URL and Properties.
     * @param url the connection URL.
     * @param props the connection properties.
     * @throws SQLException
     */
    CommonDataSource(final String url, final Properties props) throws SQLException {
        if (props != null) {
            //
            // Standardise and copy properties
            //
            for (Enumeration e = props.keys(); e.hasMoreElements(); ) {
                String name = (String)e.nextElement();
                conProps.put(normalizePropertyName(name), props.getProperty(name));
            }
        }
        if (url != null) {
            if (!parseURL(url, conProps)) {
                throw new SQLException(Messages.get("error.driver.badurl", url), "08001");
            }
        }
    }

    /**
     * Get the DriverProptyInfo descriptors for the set property values.
     * <p/>The property description is loaded from the Messages.properties file and 
     * should be formatted as description|N| for an optional property and 
     * description|Y| for a mandatory property. Comma separated value options can be
     * appended to the description e.g. boolean property|N|true,false.  
     * @return the property descriptors as a <code>DriverPropertyInfo[]</code>.
     * @throws SQLException
     */
    public DriverPropertyInfo[] getPropertyInfo()
        throws SQLException 
    {
        //
        // Get a list of property fields in this class
        //
        Map<String,String> propertyMap = new TreeMap<String,String>();
        for (Iterator<String> i = propNames.keySet().iterator(); i.hasNext(); ) {
            String name = i.next();
            propertyMap.put(name, Messages.get("prop.desc."+name.toLowerCase()));
        }

        final DriverPropertyInfo[] dpi = new DriverPropertyInfo[propertyMap.size()];
        final Iterator<Map.Entry<String,String>> iterator = propertyMap.entrySet().iterator();
        for (int i = 0; iterator.hasNext(); i++) {
            // Get descriptions for each property from the Messages.properties file.
            final Map.Entry<String, String> entry = iterator.next();
            final String name = entry.getKey();
            final String desc = entry.getValue();
            String value = conProps.get(name);
            if (value == null) {
                value = propNames.get(name);
            }
            // Populate a DriverPropertyInfo instance with information from the
            // parsed property description string and any default or supplied values.
            final DriverPropertyInfo info = new DriverPropertyInfo(name, value);
            int pos = desc.indexOf("|");
            if (pos >= 0) {
                info.description = desc.substring(0, pos);
                info.required = desc.substring(pos+1, pos+2).equals("Y");
                String tmp = desc.substring(pos+3);
                ArrayList<String> c = new ArrayList<String>();
                while ((pos = tmp.indexOf(',')) >= 0) {
                    c.add(tmp.substring(0, pos));
                    tmp = tmp.substring(pos+1);
                }
                c.add(tmp);
                info.choices = c.toArray(new String[c.size()]);
            } else {
                info.choices = new String[0];
                info.description = desc.substring(0, pos);
                info.required = false;
            }
            dpi[i] = info;
        }

        return dpi;
    }

    /**
     * See if a specific value has been set for the named property.
     * @param property the property name.
     * @return <code>boolean</code> true if property has been set.
     * @throws SQLException
     */
    boolean isPropertySet(final String property) {
        return conProps.get(property) != null;
    }

    /**
     * Normalize the connection property names to the correct mixed case form.
     * @param name the input connection property.
     * @return the normalized property name as a <code>String</code>.
     */
    private String normalizePropertyName(final String name) {
        //
        // Normalise property name
        //
        if (propNames.get(name) == null) {
            for (Iterator<String> i = propNames.keySet().iterator(); i.hasNext(); ) {
                String key = i.next();
                if (name.equalsIgnoreCase(key)) {
                    return key;
                }
            }
        }        
        return name;
    }

    /**
     * Parse the driver URL and extract the properties.
     *
     * @param url  the URL to parse
     * @return the URL properties as a <code>Properties</code> object
     */
    private boolean parseURL(final String url, final HashMap<String,String> props) {

        StringBuffer token = new StringBuffer(16);
        int pos = 0;

        pos = nextToken(url, pos, token); // Skip jdbc

        if (!"jdbc".equalsIgnoreCase(token.toString())) {
            return false; // jdbc: missing
        }

        pos = nextToken(url, pos, token); // Skip jtds

        if (!"jtds".equalsIgnoreCase(token.toString())) {
            return false; // jtds: missing
        }

        pos = nextToken(url, pos, token); // Get server type
        String type = token.toString().toLowerCase();

        if (!type.equalsIgnoreCase("sqlserver") &&
            !type.equalsIgnoreCase("sybase") &&
            !type.equalsIgnoreCase("anywhere")) 
        {
            return false;
        }
        props.put("serverType", type);

        pos = nextToken(url, pos, token); // Null token between : and //

        if (token.length() > 0) {
            return false; // There should not be one!
        }

        pos = nextToken(url, pos, token); // Get server name
        String host = token.toString();

        if (host.length() == 0) {
            host = props.get("serverName");
            if (host == null || host.length() == 0) {
                return false; // Server name missing
            }
        }

        props.put("serverName", host);

        if (url.charAt(pos - 1) == ':' && pos < url.length()) {
            pos = nextToken(url, pos, token); // Get port number
            props.put("portNumber", token.toString());
        }

        if (url.charAt(pos - 1) == '/' && pos < url.length()) {
            pos = nextToken(url, pos, token); // Get database name
            props.put("databaseName", token.toString());
        }

        //
        // Process any additional properties in URL
        //
        while (url.charAt(pos - 1) == ';' && pos < url.length()) {
            pos = nextToken(url, pos, token);
            String tmp = token.toString();
            int index = tmp.indexOf('=');
            String name  = tmp;
            String value = "";
            if (index > 0 && index < tmp.length() - 1) {
                name = tmp.substring(0, index);
                value = tmp.substring(index + 1);
            }
            props.put(normalizePropertyName(name), value);
        }
        
        return true;
    }

    /**
     * Extract the next lexical token from the URL.
     *
     * @param url The URL being parsed
     * @param pos The current position in the URL string.
     * @param token The buffer containing the extracted token.
     * @return The updated position as an <code>int</code>.
     */
    private int nextToken(final String url, int pos, final StringBuffer token) {
        token.setLength(0);
        boolean inQuote = false;
        while (pos < url.length()) {
            char ch = url.charAt(pos++);

            if (!inQuote) {
                if (ch == ':' || ch == ';') {
                    break;
                }

                if (ch == '/') {
                    if (pos < url.length() && url.charAt(pos) == '/') {
                        pos++;
                    }

                    break;
                }
            }
            
            if (ch == '[') {
                inQuote = true;
                continue;
            }
            
            if (ch == ']') {
                inQuote = false;
                continue;
            }
            
            token.append(ch);
        }

        return pos;
    }
 
    private String getProperty(final String name) {
        String value = conProps.get(name);
        if (value == null) {
            value = propNames.get(name);
        }
        return value;
    }
    
    /**
     * Retrieves the javax.naming.Reference for this DataSource. 
     * </P>This method allows a JNDI provider to persist the DataSource
     * values. This implementation will preserve original null values
     * in the DataSource so that later code can distinguish values that
     * have never been set from other defaults or user supplied values.
     */
    public Reference getReference() throws NamingException {
        Reference ref = new Reference(getClass().getName(),
                CommonDataSource.class.getName(),
                null);
        for (Iterator<String> i = conProps.keySet().iterator(); i.hasNext(); ) {
            String name = i.next();
            String value = conProps.get(name);
            ref.add(new StringRefAddr(name, value));
        }
        return ref;
    }
    
    public Object getObjectInstance(Object refObj, Name name, Context nameCtx,
            Hashtable<?, ?> env) throws Exception {

        Reference ref = (Reference) refObj;
        
        
        if (ref != null) {
            Object ds;
            Properties props = new Properties();

            for (Enumeration e = ref.getAll(); e.hasMoreElements(); ) {
                RefAddr refVal = (RefAddr)e.nextElement();
                Object value = refVal.getContent();
                if (value instanceof String) {
                    props.setProperty(refVal.getType(), (String)refVal.getContent());
                }
            }
            if (ref.getClassName().equals(net.sourceforge.jtds.jdbc.DataSourceImpl.class.getName())) {
                ds = new net.sourceforge.jtds.jdbc.DataSourceImpl(null, props);
            } else
            if (ref.getClassName().equals(net.sourceforge.jtds.jdbc.ConnectionPoolDataSourceImpl.class.getName())) {
                ds = new net.sourceforge.jtds.jdbc.ConnectionPoolDataSourceImpl(null, props);
            } else
            if (ref.getClassName().equals(net.sourceforge.jtds.jdbc.XADataSourceImpl.class.getName())) {
                ds = new net.sourceforge.jtds.jdbc.XADataSourceImpl(null, props);
            } else {
                return null;
            }
            return ds;
        }

        return null;
    }

    //
    // ---- connection property get/set methods from here ----
    //
    
    public PrintWriter getLogWriter() throws SQLException {
        return logWriter;
    }

    public int getLoginTimeout() throws SQLException {
        try {
            int v = Integer.parseInt(getProperty("loginTimeout"));
            return (v < 0)? 0: v;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    public void setLogWriter(PrintWriter logWriter) throws SQLException {
        this.logWriter = logWriter;
    }

    public void setLoginTimeout(int timeout) throws SQLException {
        conProps.put("loginTimeout", Integer.toString(timeout));        
    }

    public String getAppName()
    {
        return getProperty("appName");
    }
    
    public void setAppName(String appName) {
        conProps.put("appName", appName);
    }

    public int getBatchSize()
    {
        try {
            int v = Integer.parseInt(getProperty("batchSize"));
            return (v < 0)? 0: v;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    public void setBatchSize(int batchSize) {
        conProps.put("batchSize", Integer.toString(batchSize));        
    }

    public String getBindAddress()
    {
        return getProperty("bindAddress");
    }
    
    public void setBindAddress(String bindAddress) {
        conProps.put("bindAddress", bindAddress);
    }

    public void setCacheMetaData(boolean cacheMetaData) {
        conProps.put("cacheMetaData", Boolean.toString(cacheMetaData));
    }
    
    public boolean getCacheMetaData() {
        return Boolean.valueOf(getProperty("cacheMetaData")).booleanValue();
    }

    public String getCharset()
    {
        return getProperty("charset");
    }
    
    public void setCharset(String charset) {
        conProps.put("charset", charset);
    }

    public String getDatabaseName()
    {
        return getProperty("databaseName");
    }
    
    public void setDatabaseName(String databaseName) {
        conProps.put("databaseName", databaseName);
    }
    
    public String getDataSourceName()
    {
        return getProperty("dataSourceName");
    }
    
    public void setDataSourceName(String dataSourceName) {
        conProps.put("dataSourceName", dataSourceName);
    }

    public String getDescription()
    {
        return getProperty("description");
    }
    
    public void setDescription(String description) {
        conProps.put("description", description);        
    }

    public String getDomain()
    {
        return getProperty("domain");
    }
    
    public void setDomain(String domain) {
        conProps.put("domain", domain);        
    }

    public String getInstance()
    {
        return getProperty("instance");
    }
    
    public void setInstance(String instance) {
        conProps.put("instance", instance);        
    }

    public String getLanguage()
    {
        return getProperty("language");
    }
    
    public void setLanguage(String language) {
        conProps.put("language", language);        
    }

    public void setLastUpdateCount(boolean lastUpdateCount) {
        conProps.put("lastUpdateCount", Boolean.toString(lastUpdateCount));
    }
    
    public boolean getLastUpdateCount() {
        return Boolean.valueOf(getProperty("lastUpdateCount")).booleanValue();
    }

    
    public long getLobBuffer()
    {
        try {
            long v = Long.parseLong(getProperty("lobBuffer"));
            return (v < 0 || v > 4294967296L)? 32768L: v;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    public void setLobBuffer(long lobBuffer) {
        conProps.put("lobBuffer", Long.toString(lobBuffer));        
    }

    public String getLogFile()
    {
        return getProperty("logFile");
    }
    
    public void setLogFile(String logFile) {
        conProps.put("logFile", logFile);        
    }

    public int getLogLevel()
    {
        try {
            int v = Integer.parseInt(getProperty("logLevel"));
            return (v < 0 || v > 3)? 0: v;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    public void setLogLevel(int logLevel) {
        conProps.put("logLevel", Integer.toString(logLevel));        
    }
    
    public String getMacAddress()
    {
        return getProperty("macAddress");
    }
    
    public void setMacAddress(String macAddress) {
        conProps.put("macAddress", macAddress);        
    }
    
    public int getMaxStatements()
    {
        try {
            int v = Integer.parseInt(getProperty("maxStatements"));
            return (v < 1)? 0: v;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    public void setMaxStatements(int maxStatements) {
        conProps.put("maxStatements", Integer.toString(maxStatements));        
    }
    
    public String getNamedPipePath()
    {
        return getProperty("namedPipePath");
    }
    
    public void setNamedPipePath(String namedPipePath) {
        conProps.put("namedPipePath", namedPipePath);        
    }

    public String getNetworkProtocol()
    {
        String v = getProperty("networkProtocol");
        if (v == null || (!v.equalsIgnoreCase("tcp") && !v.equalsIgnoreCase("namedpipes"))) {
            return "tcp";
        }
        return v.toLowerCase();
    }
    
    public void setNetworkProtocol(String networkProtocol) {
        conProps.put("networkProtocol", networkProtocol);        
    }
    
    public String getPassword()
    {
        return getProperty("password");
    }
    
    public void setPassword(String password) {
        conProps.put("password", password);        
    }
    
    public int getPacketSize()
    {
        try {
            int v = Integer.parseInt(getProperty("packetSize"));
            if (v < 0 || v > TdsCore.MAX_PKT_SIZE) {
                v = TdsCore.MAX_PKT_SIZE;
            }
            if (v < TdsCore.MIN_PKT_SIZE && (getTds() != null && getTds().equals("4.2"))) {
                v = TdsCore.MIN_PKT_SIZE;
            }
            // Must be a multiple of 512 bytes
            return (v / 512) * 512;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    public void setPacketSize(int packetSize) {
        conProps.put("packetSize", Integer.toString(packetSize));        
    }
    
    public int getPortNumber()
    {
        try {
            int v = Integer.parseInt(getProperty("portNumber"));
            return (v < 1)? 0: v;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    public void setPortNumber(int portNumber) {
        conProps.put("portNumber", Integer.toString(portNumber));        
    }
    
    public int getPrepareSql()
    {
        try {
            int v = Integer.parseInt(getProperty("prepareSql"));
            return (v < 0 || v > 3)? 0: v;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    public void setPrepareSql(int prepareSql) {
        conProps.put("prepareSql", Integer.toString(prepareSql));        
    }
    
    public String getProgName()
    {
        return getProperty("progName");
    }
    
    public void setProgName(String progName) {
        conProps.put("progName", progName);
    }

    public String getRoleName()
    {
        return getProperty("roleName");
    }
    
    public void setRoleName(String roleName) {
        conProps.put("roleName", roleName);                
    }
    
    public boolean getSendStringParametersAsUnicode() {
        return Boolean.valueOf(getProperty("sendStringParametersAsUnicode")).booleanValue();
    }
    
    public void setSendStringParametersAsUnicode(boolean value) {
        conProps.put("sendStringParametersAsUnicode", Boolean.toString(value));        
    }
    
    public String getServerName()
    {
        return getProperty("serverName");
    }
    
    public void setServerName(String serverName) {
        conProps.put("serverName", serverName);
    }    

    public String getServerType()
    {
        String t = getProperty("serverType");
        if (t == null || (!t.equalsIgnoreCase("sqlserver") &&
                          !t.equalsIgnoreCase("sybase") && 
                          !t.equalsIgnoreCase("anywhere"))) {
            return "sqlserver";
        }
        return t.toLowerCase();
    }
    
    public void setServerType(String serverType) {
        conProps.put("serverType", serverType);
    }    

    /**
     * Set the socket timeout
     * @param timeout the socket timeout in seconds.
     */
    public void setSocketTimeout(int timeout) {
        if (timeout < 0) {
            timeout = 0;
        }
        conProps.put("socketTimeout", Integer.toString(timeout));
    }
    
    /**
     * Retrieve the socket timeout.
     * @return the socket timeout as an <code>int</code>.
     */
    public int getSocketTimeout() {
        try {
            int v = Integer.parseInt(getProperty("socketTimeout"));
            return (v > 0)? v: 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    public String getSsl()
    {
        String v = getProperty("ssl");
        if (v == null || 
           (!v.equalsIgnoreCase("off") &&
            !v.equalsIgnoreCase("request") &&
            !v.equalsIgnoreCase("require") &&
            !v.equalsIgnoreCase("authenticate"))) {
            return "off";
        }
        return v.toLowerCase();
    }
    
    public void setSsl(String ssl) {
        conProps.put("ssl", ssl);        
    }

    /**
     * Set the tcpNoDelay property.
     * @param tcpNoDelay value of true enables TCP/IP no delay.
     */
    public void setTcpNoDelay(boolean tcpNoDelay) {
        conProps.put("tcpNoDelay", Boolean.toString(tcpNoDelay));
    }
    
    /**
     * Retrieve the tcpNoDelay property.
     * @return the tcpNoDelay property as a <code>boolean</code>.
     */
    public boolean getTcpNoDelay() {
        return Boolean.valueOf(getProperty("tcpNoDelay")).booleanValue();
    }

    public String getTds()
    {
        String v = getProperty("tds");
        if (!v.equals("4.2") && !v.equals("5.0") && 
               !v.equals("7.0") && !v.equals("8.0"))
        {
            if (getServerType().equals("sybase") ||
                getServerType().equals("anywhere")) {
                return "5.0";
            }
            return "8.0";
        }
        return v;
    }
    
    public void setTds(String tds) {
        conProps.put("tds", tds);        
    }

    public void setUseCursors(boolean useCursors) {
        conProps.put("useCursors", Boolean.toString(useCursors));
    }
    
    public boolean getUseCursors() {
        return Boolean.valueOf(getProperty("useCursors")).booleanValue();
    }

    public void setUseJCIFS(boolean useJCIFS) {
        conProps.put("useJCIFS", Boolean.toString(useJCIFS));
    }
    
    public boolean getUseJCIFS() {
        return Boolean.valueOf(getProperty("useJCIFS")).booleanValue();
    }

    public void setUseLOBs(boolean useLOBs) {
        conProps.put("useLOBs", Boolean.toString(useLOBs));
    }
    
    public boolean getUseLOBs() {
        return Boolean.valueOf(getProperty("useLOBs")).booleanValue();
    }

    public void setUseNTLMv2(boolean useNTLMv2) {
        conProps.put("useNTLMv2", Boolean.toString(useNTLMv2));
    }
    
    public boolean getUseNTLMv2() {
        return Boolean.valueOf(getProperty("useNTLMv2")).booleanValue();
    }

    public void setUseKerberos(boolean useKerberos) {
        conProps.put("useKerberos", Boolean.toString(useKerberos));
    }

    public boolean getUseKerberos() {
        return Boolean.valueOf(getProperty("useKerberos")).booleanValue();
    }

    public String getUser()
    {
        return getProperty("user");
    }
    
    public void setUser(String user) {
        conProps.put("user", user);        
    }
    
    public String getWsid()
    {
        return getProperty("wsid");
    }
    
    public void setWsid(String wsid) {
        conProps.put("wsid", wsid);        
    }    

    public void setXaEmulation(boolean xaEmulation) {
        conProps.put("xaEmulation", Boolean.toString(xaEmulation));
    }
    
    public boolean getXaEmulation() {
        return Boolean.valueOf(getProperty("xaEmulation")).booleanValue();
    }

}
