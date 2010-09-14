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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Struct;
import java.util.Map;
import java.util.Properties;

import net.sourceforge.jtds.util.Logger;

/**
 * Implement a connection wrapper.
 * <p/> Reflection is not used for the connection wrapper due to problems
 * in complying with the JCA spec and Sun's J2EE verifier.
 *
 */
public class ConnectionWrapper implements Connection {
    protected Connection con;
    protected boolean closed = false;
    protected PooledConnectionImpl pooledConnection;

    /**
     * Construct a connection wrapper.
     * @param pooledConnection the managing connection.
     * @param con the physical connection.
     */
    protected ConnectionWrapper(final PooledConnectionImpl pooledConnection, final Connection con) {
        if (Logger.isTraceActive()) {
            Logger.printMethod(this, null, new Object[]{pooledConnection, con});
        }
        this.pooledConnection = pooledConnection;
        this.con = con;
    }
    
    /**
     * Retrieve the underlying physical connection.
     * @return the physical connection as a <code>java.sql.Connection</code>.
     */
    protected Connection getPhysicalConnection()
    {
        return con;
    }
    
    /**
     * Set the physical connection.
     * @param con the connection instance.
     */
    protected void setPhysicalConnection(final Connection con) {
        this.con = con;
    }
    
    /**
     * Validates the connection state.
     */
    protected void checkOpen() throws SQLException {
        if (closed) {
            throw new SQLException(Messages.get("error.conproxy.noconn"), "HY010");
        }
    }

    /**
     * Processes SQLExceptions.
     */
    protected void processSQLException(final SQLException sqlException) throws SQLException {
        //
        // Only notify container of fatal exceptions, otherwise the container
        // may discard a perfectly viable connection that has reported a minor
        // exception that the application is expecting to handle.
        //
        if (con.isClosed()) {
            pooledConnection.fireConnectionEvent(false, sqlException);
        }
        throw sqlException;
    }

    public void clearWarnings() throws SQLException {
        checkOpen();
        try {
            con.clearWarnings();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public void close() throws SQLException {
        if (!closed) {
            pooledConnection.fireConnectionEvent(true, null);
            closed = true;
        }
    }

    public void commit() throws SQLException {
        checkOpen();
        try {
            con.commit();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public Statement createStatement() throws SQLException {
        checkOpen();
        try {
            Statement st = con.createStatement();
            return (Statement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{Statement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public Statement createStatement(int resultSetType, int resultSetConcurrency)
            throws SQLException 
    {
        checkOpen();
        try {
            Statement st = con.createStatement(resultSetType, resultSetConcurrency);
            return (Statement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{Statement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public Statement createStatement(int resultSetType,
            int resultSetConcurrency, int resultSetHoldability)
            throws SQLException {
        checkOpen();
        try {
            Statement st = con.createStatement(resultSetType, resultSetConcurrency, resultSetHoldability);
            return (Statement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{Statement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public boolean getAutoCommit() throws SQLException {
        checkOpen();
        try {
            return con.getAutoCommit();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public String getCatalog() throws SQLException {
        checkOpen();
        try {
            return con.getCatalog();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public int getHoldability() throws SQLException {
        checkOpen();
        try {
            return con.getHoldability();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public DatabaseMetaData getMetaData() throws SQLException {
        return con.getMetaData();
    }

    public int getTransactionIsolation() throws SQLException {
        checkOpen();
        try {
            return con.getTransactionIsolation();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public Map<String, Class<?>> getTypeMap() throws SQLException {
        checkOpen();
        try {
            return con.getTypeMap();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public SQLWarning getWarnings() throws SQLException {
        checkOpen();
        try {
            return con.getWarnings();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public boolean isClosed() throws SQLException {
        try {
            return closed || con.isClosed();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public boolean isReadOnly() throws SQLException {
        checkOpen();
        try {
            return con.isReadOnly();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public String nativeSQL(String sql) throws SQLException {
        checkOpen();
        try {
            return con.nativeSQL(sql);
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public CallableStatement prepareCall(String sql) throws SQLException {
        checkOpen();
        try {
            CallableStatement st = con.prepareCall(sql);
            return (CallableStatement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{CallableStatement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public CallableStatement prepareCall(String sql, int resultSetType,
            int resultSetConcurrency) throws SQLException 
       {
        checkOpen();
        try {
            CallableStatement st = con.prepareCall(sql, resultSetType, resultSetConcurrency);
            return (CallableStatement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{CallableStatement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public CallableStatement prepareCall(String sql, int resultSetType,
            int resultSetConcurrency, int resultSetHoldability)
            throws SQLException 
    {
        checkOpen();
        try {
            CallableStatement st = con.prepareCall(sql, resultSetType, resultSetConcurrency, resultSetHoldability);
            return (CallableStatement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{CallableStatement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public PreparedStatement prepareStatement(String sql) throws SQLException {
        checkOpen();
        try {
            PreparedStatement st = con.prepareStatement(sql);
            return (PreparedStatement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{PreparedStatement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys)
            throws SQLException {
        checkOpen();
        try {
            PreparedStatement st = con.prepareStatement(sql, autoGeneratedKeys);
            return (PreparedStatement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{PreparedStatement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public PreparedStatement prepareStatement(String sql, int[] columnIndexes)
            throws SQLException 
    {
        checkOpen();
        try {
            PreparedStatement st = con.prepareStatement(sql, columnIndexes);
            return (PreparedStatement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{PreparedStatement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public PreparedStatement prepareStatement(String sql, String[] columnNames)
            throws SQLException 
    {
        checkOpen();
        try {
            PreparedStatement st = con.prepareStatement(sql, columnNames);
            return (PreparedStatement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{PreparedStatement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public PreparedStatement prepareStatement(String sql, int resultSetType,
            int resultSetConcurrency) throws SQLException 
    {
        checkOpen();
        try {
            PreparedStatement st = con.prepareStatement(sql, resultSetType, resultSetConcurrency);
            return (PreparedStatement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{PreparedStatement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public PreparedStatement prepareStatement(String sql, int resultSetType,
            int resultSetConcurrency, int resultSetHoldability)
            throws SQLException 
    {
        checkOpen();
        try {
            PreparedStatement st = con.prepareStatement(sql, resultSetType, resultSetConcurrency, resultSetHoldability);
            return (PreparedStatement)Proxy.newProxyInstance(getClass().getClassLoader(), 
                new Class[]{PreparedStatement.class}, 
                new StatementHandler(this, st));
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public void releaseSavepoint(Savepoint savepoint) throws SQLException {
        checkOpen();
        try {
            con.releaseSavepoint(savepoint);
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public void rollback() throws SQLException {
        checkOpen();
        try {
            con.rollback();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public void rollback(Savepoint savepoint) throws SQLException {
        checkOpen();
        try {
            con.rollback(savepoint);
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public void setAutoCommit(boolean autoCommit) throws SQLException {
        checkOpen();
        try {
            con.setAutoCommit(autoCommit);
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public void setCatalog(String catalog) throws SQLException {
        checkOpen();
        try {
            con.setCatalog(catalog);
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public void setHoldability(int holdability) throws SQLException {
        checkOpen();
        try {
            con.setHoldability(holdability);
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public void setReadOnly(boolean readOnly) throws SQLException {
        checkOpen();
        try {
            con.setReadOnly(readOnly);
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public Savepoint setSavepoint() throws SQLException {
        checkOpen();
        try {
            return con.setSavepoint();
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public Savepoint setSavepoint(String name) throws SQLException {
        checkOpen();
        try {
            return con.setSavepoint(name);
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public void setTransactionIsolation(int level) throws SQLException {
        checkOpen();
        try {
            con.setTransactionIsolation(level);
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }

    public void setTypeMap(Map<String, Class<?>> map) throws SQLException {
        checkOpen();
        try {
            con.setTypeMap(map);
        } catch (SQLException e) {
            processSQLException(e);
            throw e;
        }
    }
    
    /**
     * Dynamic proxy invocation handler for the Statement interface (all types).
     * Reflection is slower than a traditional wrapper but much more compact
     * and easier to maintain when the interface changes.
     */
    private static class StatementHandler implements InvocationHandler {
        /** The enclosing connection invocation handler.*/
        private ConnectionWrapper con;
        /** The underlying JDBC statement. */
        private Statement st;

        /**
         * Construct a new invocation handler for the Statement interface.
         * @param con the enclosing connection proxy. 
         * @param st the underlying JDBC statement instance.
         */
        StatementHandler(ConnectionWrapper con, Statement st) {
            if (Logger.isTraceActive()) {
                Logger.printMethod(this, null, new Object[]{con, st});
            }
            this.con = con;
            this.st = st;
        }
        
        /**
         * Invoke a method on the proxied interface.
         * @param proxy the proxy statement object.
         * @param method the Statement method being invoked.
         * @param args the method arguments.
         * @return the relevant method return value as a <code>Object</code>.
         */
        public Object invoke(Object proxy, Method method, Object[] args)
        throws Throwable {
            //
            // We need to trap invocations of equals, hashcode and toString to ensure
            // that they operate on the proxied objects.
            // 
            if (method.getDeclaringClass().getName().equals("java.lang.Object")) {
                if (method.getName().equals("equals")) {
                    if (args[0] == null) {
                        return Boolean.FALSE;
                    }
                    try {
                        return Boolean.valueOf(
                                Proxy.isProxyClass(args[0].getClass()) && 
                                     ((StatementHandler) Proxy.
                                      getInvocationHandler(args[0])).st == st
                                );
                    } catch (ClassCastException e) {
                        return Boolean.FALSE;
                    }
                }
                if (method.getName().equals("hashCode")) {
                    return new Integer(st.hashCode());
                }
                if (method.getName().equals("toString")) {
                    return st.toString();
                }
                return method.invoke(st, args);
            }
            //
            // Now process methods being invoked on the Statement interface.
            //
            if (method.getName().equals("close")) {
                if (st != null && !con.isClosed()) {
                    try {
                        st.close();
                    } finally {
                        con = null;
                        st  = null;
                    }
                }
                return null;
            }
            //
            // If the statement is closed all other method invocations must fail
            //
            if (st == null || con.isClosed()) {
                throw new SQLException(
                        Messages.get("error.generic.closed", "Statement"), "HY010");
            }
            //
            // Need to trap getConnection to make sure that we return the
            // connection proxy and not the underlying JDBC connection.
            //
            if (method.getName().equals("getConnection")) {
                return con; 
            }

            try {
                // Invoke all remaining methods
                return method.invoke(st, args);
            } catch (InvocationTargetException inve) {
                Throwable e = inve.getTargetException();
                if (e instanceof SQLException && con.isClosed()) {
                    con.processSQLException((SQLException)e);
                }
                throw e;
            }
        }
    }

    @Override
    public Array createArrayOf(String typeName, Object[] elements)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Blob createBlob() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Clob createClob() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public NClob createNClob() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public SQLXML createSQLXML() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Struct createStruct(String typeName, Object[] attributes)
            throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public Properties getClientInfo() throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public String getClientInfo(String name) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public boolean isValid(int timeout) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setClientInfo(Properties properties)
            throws SQLClientInfoException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public void setClientInfo(String name, String value)
            throws SQLClientInfoException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        // TODO Auto-generated method stub
        throw new AbstractMethodError();
    }
}
