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

import java.sql.*;
import javax.sql.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.naming.spi.ObjectFactory;



/**
 * Test case to exercise the Driver and DataSource classes.
 *
 * @version    1.0
 */
public class DataSourceTest extends TestBase {

    public DataSourceTest(String name)
    {
        super(name);
    }

    public void testDataSourceMethods() throws Exception {
        DataSourceImpl ds = new DataSourceImpl();
        setProperties(ds);
        checkProperties(ds);
    }
    
    public void testDataSourceSerialisation() throws Exception {
        DataSourceImpl ds = new DataSourceImpl();
        setProperties(ds);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(os);
        oos.writeObject(ds);
        ObjectInputStream ois = new ObjectInputStream(
                                    new ByteArrayInputStream(os.toByteArray()));
        ds = (DataSourceImpl)ois.readObject();
        checkProperties(ds);
    }
    
    public void testDataSourceObjectFactory() throws Exception {
        DataSourceImpl ds = new DataSourceImpl();
        setProperties(ds);
        Reference ref = ((Referenceable)ds).getReference();
        assertEquals("net.sourceforge.jtds.jdbc.CommonDataSource",
                     ref.getFactoryClassName());
        assertEquals("net.sourceforge.jtds.jdbc.DataSourceImpl",
                     ref.getClassName());
        ObjectFactory factory = (ObjectFactory)Class.forName(ref.getFactoryClassName()).newInstance();
        ds = (DataSourceImpl) factory.getObjectInstance(ref, null, null, null);
        checkProperties(ds);
    }
    
    public void testXADataSourceObjectFactory() throws Exception {
        XADataSourceImpl ds = new XADataSourceImpl();
        setProperties(ds);
        Reference ref = ((Referenceable)ds).getReference();
        assertEquals("net.sourceforge.jtds.jdbc.CommonDataSource",
                     ref.getFactoryClassName());
        assertEquals("net.sourceforge.jtds.jdbc.XADataSourceImpl",
                     ref.getClassName());
        ObjectFactory factory = (ObjectFactory)Class.forName(ref.getFactoryClassName()).newInstance();
        ds = (XADataSourceImpl) factory.getObjectInstance(ref, null, null, null);
        checkProperties(ds);
    }

    public void testCPDataSourceObjectFactory() throws Exception {
        ConnectionPoolDataSourceImpl ds = new ConnectionPoolDataSourceImpl();
        setProperties(ds);
        Reference ref = ((Referenceable)ds).getReference();
        assertEquals("net.sourceforge.jtds.jdbc.CommonDataSource",
                     ref.getFactoryClassName());
        assertEquals("net.sourceforge.jtds.jdbc.ConnectionPoolDataSourceImpl",
                     ref.getClassName());
        ObjectFactory factory = (ObjectFactory)Class.forName(ref.getFactoryClassName()).newInstance();
        ds = (ConnectionPoolDataSourceImpl) factory.getObjectInstance(ref, null, null, null);
        checkProperties(ds);
    }

    private void setProperties(CommonDataSource ds) throws SQLException {
        //
        // Standard properties
        //
        ds.setLoginTimeout(99);
        //
        // Custom properties
        //
        ds.setAppName("TestApp");
        ds.setBatchSize(1024);
        ds.setBindAddress("127.0.0.1");
        ds.setCacheMetaData(true);
        ds.setCharset("iso_15");
        ds.setDatabaseName("TestDB");
        ds.setDataSourceName("TestDS");
        ds.setDescription("TestDesc");
        ds.setDomain("domain");
        ds.setInstance("TestIN");
        ds.setLanguage("en");
        ds.setLastUpdateCount(false);
        ds.setLobBuffer(4545);
        ds.setLogFile("System.out");
        ds.setLogLevel(3);
        ds.setMacAddress("FF00FF00FF00");
        ds.setMaxStatements(66);
        ds.setNamedPipePath("PipePath");
        ds.setNetworkProtocol("namedpipes");
        ds.setPacketSize(1024);
        ds.setPassword("TestPwd");
        ds.setPrepareSql(1);
        ds.setPortNumber(123);
        ds.setProgName("TestPN");
        ds.setRoleName("TestRN");
        ds.setSendStringParametersAsUnicode(false);
        ds.setServerName("TestSN");
        ds.setServerType("sybase");
        ds.setSocketTimeout(77);
        ds.setSsl("require");
        ds.setTcpNoDelay(false);
        ds.setTds("4.2");
        ds.setUseCursors(true);
        ds.setUseJCIFS(true);
        ds.setUseLOBs(false);
        ds.setUseNTLMv2(true);
        ds.setUser("TestUID");
        ds.setWsid("TestID");
        ds.setXaEmulation(true);
    }
    
    private void checkProperties(CommonDataSource ds) throws SQLException {
        assertEquals(99, ds.getLoginTimeout());
        //
        // Custom properties
        //
        assertEquals("TestApp", ds.getAppName());
        assertEquals(1024, ds.getBatchSize());
        assertEquals("127.0.0.1", ds.getBindAddress());
        assertTrue(ds.getCacheMetaData());
        assertEquals("iso_15", ds.getCharset());
        assertEquals("TestDB", ds.getDatabaseName());
        assertEquals("TestDS", ds.getDataSourceName());
        assertEquals("TestDesc", ds.getDescription());
        assertEquals("domain", ds.getDomain());
        assertEquals("TestIN", ds.getInstance());
        assertEquals("en", ds.getLanguage());
        assertFalse(ds.getLastUpdateCount());
        assertEquals(4545, ds.getLobBuffer());
        assertEquals("System.out", ds.getLogFile());
        assertEquals(3, ds.getLogLevel());
        assertEquals("FF00FF00FF00", ds.getMacAddress());
        assertEquals(66, ds.getMaxStatements());
        assertEquals("PipePath", ds.getNamedPipePath());
        assertEquals("namedpipes", ds.getNetworkProtocol());
        assertEquals(1024, ds.getPacketSize());
        assertEquals("TestPwd", ds.getPassword());
        assertEquals(1, ds.getPrepareSql());
        assertEquals(123, ds.getPortNumber());
        assertEquals("TestPN", ds.getProgName());
        assertEquals("TestRN", ds.getRoleName());
        assertFalse(ds.getSendStringParametersAsUnicode());
        assertEquals("TestSN", ds.getServerName());
        assertEquals("sybase", ds.getServerType());
        assertEquals(77, ds.getSocketTimeout());
        assertEquals("require", ds.getSsl());
        assertFalse(ds.getTcpNoDelay());
        assertEquals("4.2", ds.getTds());
        assertTrue(ds.getUseCursors());
        assertTrue(ds.getUseJCIFS());
        assertFalse(ds.getUseLOBs());
        assertTrue(ds.getUseNTLMv2());
        assertEquals("TestUID", ds.getUser());
        assertEquals("TestID", ds.getWsid());
        assertTrue(ds.getXaEmulation());
    }
    
    public void testDefaultValues() throws Exception {
        DataSourceImpl ds = new DataSourceImpl();
        assertEquals(0, ds.getLoginTimeout());
        //
        // Custom properties
        //
        assertEquals("jTDS", ds.getAppName());
        assertEquals(0, ds.getBatchSize());
        assertEquals("", ds.getBindAddress());
        assertFalse(ds.getCacheMetaData());
        assertEquals("", ds.getCharset());
        assertEquals("", ds.getDatabaseName());
        assertEquals("", ds.getDataSourceName());
        assertEquals("", ds.getDescription());
        assertEquals("", ds.getDomain());
        assertEquals("", ds.getInstance());
        assertEquals("", ds.getLanguage());
        assertTrue(ds.getLastUpdateCount());
        assertEquals(32768, ds.getLobBuffer());
        assertEquals("", ds.getLogFile());
        assertEquals(1, ds.getLogLevel());
        assertEquals("000000000000", ds.getMacAddress());
        assertEquals(500, ds.getMaxStatements());
        assertEquals("/sql/query", ds.getNamedPipePath());
        assertEquals("tcp", ds.getNetworkProtocol());
        assertEquals(0, ds.getPacketSize());
        assertEquals("", ds.getPassword());
        assertEquals(3, ds.getPrepareSql());
        assertEquals(1433, ds.getPortNumber());
        assertEquals("jTDS", ds.getProgName());
        assertEquals("", ds.getRoleName());
        assertTrue(ds.getSendStringParametersAsUnicode());
        assertEquals("", ds.getServerName());
        assertEquals("sqlserver", ds.getServerType());
        assertEquals(0, ds.getSocketTimeout());
        assertEquals("off", ds.getSsl());
        assertTrue(ds.getTcpNoDelay());
        assertEquals("8.0", ds.getTds());
        assertFalse(ds.getUseCursors());
        assertFalse(ds.getUseJCIFS());
        assertTrue(ds.getUseLOBs());
        assertFalse(ds.getUseNTLMv2());
        assertEquals("", ds.getUser());
        assertEquals("", ds.getWsid());
        assertFalse(ds.getXaEmulation());        
    }
    boolean cClosed = false;
    boolean cError  = false;
    
    class TestListener implements javax.sql.ConnectionEventListener {
        public void connectionClosed(ConnectionEvent ev) {
            cClosed = true;
        }
        public void connectionErrorOccurred(ConnectionEvent ev) {
            cError = true;
        }
    }
    
    public void testConnectionPoolDS() throws Exception {
        ConnectionPoolDataSourceImpl ds = new ConnectionPoolDataSourceImpl();
        ds.setServerName(props.getProperty("SERVERNAME"));
        if (props.getProperty("INSTANCE") != null) {
            ds.setInstance(props.getProperty("INSTANCE"));
        } else {
            if (props.getProperty("PORTNUMBER") != null) {
                ds.setPortNumber(Integer.parseInt(props.getProperty("PORTNUMBER")));
            }
        }
        ds.setServerName(props.getProperty("SERVERNAME"));
        ds.setServerType(props.getProperty("SERVERTYPE"));
        if (props.getProperty("TDS") != null) {
            ds.setTds(props.getProperty("TDS"));
        }
        ds.setLogFile(props.getProperty("LOGFILE"));
        if (props.getProperty("LOGLEVEL") != null) {
            ds.setLogLevel(Integer.parseInt(props.getProperty("LOGLEVEL")));
        }
        PooledConnection pc = ds.getPooledConnection(props.getProperty("USER"), 
                props.getProperty("PASSWORD"));
        assertNotNull(pc);
        pc.addConnectionEventListener(new TestListener());
        Connection con2 = pc.getConnection();
        Statement stmt = con2.createStatement();
        try {
            stmt.execute("This will cause an error");
            fail("Expected an exception");
        } catch (SQLException e) {
  //          assertTrue(cError);
        }
        con2.close();
        assertTrue(cClosed);
        pc.close();
    }
    
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(DataSourceTest.class);
    }
}
