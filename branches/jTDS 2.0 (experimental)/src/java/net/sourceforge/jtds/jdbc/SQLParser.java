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

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;


/**
 * Process JDBC escape strings and parameter markers in the SQL string.
 * <p>
 * This code recognizes the following escapes:
 * <ol>
 * <li>Date      {d 'yyyy-mm-dd'}
 * <li>Time      {t 'hh:mm:ss'}
 * <li>Timestamp {ts 'yyyy-mm-dd hh:mm:ss.nnn'}
 * <li>ESCAPE    {escape 'x'}
 * <li>Function  {fn xxxx([arg,arg...])}
 * NB The concat(arg, arg) operator is converted to (arg + arg)
 * <li>OuterJoin {oj .....}
 * <li>Call      {?=call proc [arg, arg...]}
 * or        {call proc [arg, arg...]}
 * </ol>
 * Notes:
 * <ol>
 * <li>This code is designed to be as efficient as possible and as
 * result the validation done here is limited.
 * <li>SQL comments are parsed correctly thanks to code supplied by
 * Joel Fouse.
 * </ol>
 *
 * @author Mike Hutchinson
 * @version $Id: SQLParser.java,v 1.2 2009-07-23 19:35:35 ickzon Exp $
 */
class SQLParser {
    /**
     * Serialized version of a parsed SQL query (the value stored in the cache
     * for a parsed SQL).
     * <p/>
     * Holds the parsed SQL query and the names, positions and return value and
     * unicode flags for the parameters.
     */
    private static class CachedSQLQuery {
        final String[]  parsedSql;
        final String[]  paramNames;
        final int[]     paramMarkerPos;
        final boolean[] paramIsRetVal;
        final boolean[] paramIsUnicode;

        CachedSQLQuery(final String[] parsedSql, final ArrayList params) 
        {
            this.parsedSql = parsedSql;

            if (params != null) {
                final int size = params.size();
                paramNames     = new String[size];
                paramMarkerPos = new int[size];
                paramIsRetVal  = new boolean[size];
                paramIsUnicode = new boolean[size];

                for (int i = 0; i < size; i++) {
                    ParamInfo paramInfo = (ParamInfo) params.get(i);
                    paramNames[i]     = paramInfo.name;
                    paramMarkerPos[i] = paramInfo.markerPos;
                    paramIsRetVal[i]  = paramInfo.isRetVal;
                    paramIsUnicode[i] = paramInfo.isUnicode;
                }
            } else {
                paramNames = null;
                paramMarkerPos = null;
                paramIsRetVal = null;
                paramIsUnicode = null;
            }
        }
    }
    
    /**
     * Cache key for an SQL query, consisting of the query and server type, major
     * and minor version.
     *
     * @author Brett Wooldridge
     * @author Alin Sinpalean
     * @version $Id: SQLParser.java,v 1.2 2009-07-23 19:35:35 ickzon Exp $
     */
    static class SQLCacheKey {
        private final String sql;
        private final int serverType;
        private final int majorVersion;
        private final int minorVersion;
        private final int hashCode;

        SQLCacheKey(final String sql, 
                    final int serverType, 
                    final int majorVersion, 
                    final int minorVersion) 
        {
            this.sql = sql;
            this.serverType   = serverType;
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;

            this.hashCode = sql.hashCode()
                    ^ (serverType << 24 | majorVersion << 16 | minorVersion);
        }

        public int hashCode() {
            return hashCode;
        }

        public boolean equals(Object object) {
            try {
                SQLCacheKey key = (SQLCacheKey) object;

                return this.hashCode == key.hashCode
                        && this.majorVersion == key.majorVersion
                        && this.minorVersion == key.minorVersion
                        && this.serverType == key.serverType
                        && this.sql.equals(key.sql);
            } catch (ClassCastException e) {
                return false;
            }
        }
    }

    /**
     * Simple LRU cache for any type of object. Implemented as an extended
     * <code>HashMap</code> with a maximum size and an aggregated <code>List</code>
     * as LRU queue.
     *
     * @author Brett Wooldridge
     * @version $Id: SQLParser.java,v 1.2 2009-07-23 19:35:35 ickzon Exp $
     */
    static class SimpleLRUCache extends HashMap<SQLParser.SQLCacheKey, Object> {
        static final long serialVersionUID = -3197929967416505022L;
        /** Maximum cache size. */
        private final int maxCacheSize;
        /** LRU list. */
        private final LinkedList<SQLCacheKey> list;

        /**
         * Constructs a new LRU cache instance.
         *
         * @param maxCacheSize the maximum number of entries in this cache before
         *                     entries are aged off
         */
        SimpleLRUCache(final int maxCacheSize) {
            super(maxCacheSize);
            this.maxCacheSize = Math.max(0, maxCacheSize);
            this.list = new LinkedList<SQLCacheKey>();
        }

        /**
         * Overrides clear() to also clear the LRU list.
         */
        public synchronized void clear() {
            super.clear();
            list.clear();
        }

        /**
         * Overrides <code>put()</code> so that it also updates the LRU list.
         *
         * @param key   key with which the specified value is to be associated
         * @param value value to be associated with the key
         * @return previous value associated with key or <code>null</code> if there
         *         was no mapping for key; a <code>null</code> return can also
         *         indicate that the cache previously associated <code>null</code>
         *         with the specified key
         * @see java.util.Map#put(Object, Object)
         */
        public synchronized Object put(final SQLCacheKey key, final Object value) {
            if (maxCacheSize == 0) {
                return null;
            }

            // if the key isn't in the cache and the cache is full...
            if (!super.containsKey(key) && !list.isEmpty() && list.size() + 1 > maxCacheSize) {
                Object deadKey = list.removeLast();
                super.remove(deadKey);
            }

            freshenKey(key);
            return super.put(key, value);
        }

        /**
         * Overrides <code>get()</code> so that it also updates the LRU list.
         *
         * @param key key with which the expected value is associated
         * @return the value to which the cache maps the specified key, or
         *         <code>null</code> if the map contains no mapping for this key
         */
        synchronized Object get(final SQLCacheKey key) {
            Object value = super.get(key);
            if (value != null) {
                freshenKey(key);
            }
            return value;
        }

        /**
         * @see java.util.Map#remove(Object)
         */
        synchronized Object remove(final SQLCacheKey key) {
            list.remove(key);
            return super.remove(key);
        }

        /**
         * Moves the specified value to the top of the LRU list (the bottom of the
         * list is where least recently used items live).
         *
         * @param key key of the value to move to the top of the list
         */
        private void freshenKey(final SQLCacheKey key) {
            list.remove(key);
            list.addFirst(key);
        }
    }

    /** LRU cache of previously parsed SQL */
    private static SimpleLRUCache cache;

    /** Original SQL string */
    private final String sql;
    /** Input buffer with SQL statement. */
    private final char[] in;
    /** Current position in input buffer. */
    private int s;
    /** Length of input buffer. */
    private final int len;
    /** Output buffer to contain parsed SQL. */
    private final char[] out;
    /** Current position in output buffer. */
    private int d;
    /**
     * Parameter list to be populated or <code>null</code> if no parameters
     * are expected.
     */
    private final ArrayList<ParamInfo> params;
    /** Current expected terminator character. */
    private char terminator;
    /** Procedure name in call escape. */
    private String procName;
    /** First SQL keyword or identifier in statement. */
    private String keyWord;
    /** First table name in from clause */
    private String tableName;
    /** Connection object for server specific parsing. */
    private final ConnectionImpl connection;

    /**
     * Parse the SQL statement processing JDBC escapes and parameter markers.
     *
     * @param extractTable
     *            true to return the first table name in the FROM clause of a select
     * @return The processed SQL statement, any procedure name, the first SQL
     *         keyword and (optionally) the first table name as
     *         elements 0 1, 2 and 3 of the returned <code>String[]</code>.
     * @throws SQLException if a parse error occurs
     */
    static String[] parse(final String sql, 
                          final ArrayList<ParamInfo> paramList,
                          final ConnectionImpl connection,
                          final boolean extractTable)
            throws SQLException 
    {
    	// Don't cache extract table parse requests, just process it
    	if (extractTable) {
    		SQLParser parser = new SQLParser(sql, paramList, connection);
    		return parser.parse(extractTable);
    	}

        SimpleLRUCache cache = getCache(connection);

        SQLCacheKey cacheKey =  new SQLCacheKey(sql, 
                                        connection.getServerType(), 
                                        connection.getDatabaseMajorVersion(), 
                                        connection.getDatabaseMinorVersion());


        // By not synchronizing on the cache, we're admitting that the possibility of multiple
        // parses of the same statement can occur.  However, it is 1) unlikely under normal
        // usage, and 2) harmless to the cache.  By avoiding a synchronization block around
        // the get()-parse()-put(), we reduce the contention greatly in the nominal case.
        CachedSQLQuery cachedQuery = (CachedSQLQuery) cache.get(cacheKey);
        if (cachedQuery == null) {
            // Parse and cache SQL
            SQLParser parser = new SQLParser(sql, paramList, connection);
            cachedQuery = new CachedSQLQuery(parser.parse(extractTable),
                    paramList);
            cache.put(cacheKey, cachedQuery);
        } else {
            // Create full ParamInfo objects out of cached object
            final int length = (cachedQuery.paramNames == null)
                    ? 0 : cachedQuery.paramNames.length;
            for (int i = 0; i < length; i++) {
                ParamInfo paramInfo = new ParamInfo(cachedQuery.paramNames[i],
                                                    cachedQuery.paramMarkerPos[i],
                                                    cachedQuery.paramIsRetVal[i],
                                                    cachedQuery.paramIsUnicode[i]);
                paramList.add(paramInfo);
            }
        }
        return cachedQuery.parsedSql;
    }

    // --------------------------- Private Methods --------------------------------

    /**
     * Retrieves the statement cache, creating it if required.
     *
     * @return the cache as a <code>SimpleLRUCache</code>
     */
    private synchronized static SimpleLRUCache getCache(final ConnectionImpl connection) {
        if (cache == null) {
            int maxStatements = connection.getDataSource().getMaxStatements();
            maxStatements = Math.max(0, maxStatements);
            maxStatements = Math.min(1000, maxStatements);
            cache = new SimpleLRUCache(maxStatements);
        }
        return cache;
    }


    /** Lookup table to test if character is part of an identifier. */
    private static boolean identifierChar[] = {
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, true,  true,  false, false, false,
            false, false, false, false, false, false, false, false,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  false, false, false, false, false, false,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  false, false, false, false, true,
            false, true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  false, false, false, false, false
    };

    /**
     * Determines if character could be part of an SQL identifier.
     * <p/>
     * Characters > 127 are assumed to be unicode letters in other
     * languages than english which is reasonable in this application.
     * @param ch the character to test.
     * @return <code>boolean</code> true if ch in A-Z a-z 0-9 @ $ # _.
     */
    private static boolean isIdentifier(int ch) {
        return ch > 127 || identifierChar[ch];
    }

    /**
     * Constructs a new parser object to process the supplied SQL.
     *
     * @param sqlIn     the SQL statement to parse
     * @param paramList the parameter list array to populate or
     *                  <code>null</code> if no parameters are expected
     * @param connection the parent Connection object
     */
    private SQLParser(final String sqlIn, 
                      final ArrayList<ParamInfo> paramList, 
                      final ConnectionImpl connection) 
    {
        sql = sqlIn;
        in  = sql.toCharArray();
        len = in.length;
        out = new char[len + 256]; // Allow extra for curdate/curtime
        params = paramList;
        procName = "";

        this.connection = connection;
    }

    /**
     * Inserts a String literal in the output buffer.
     *
     * @param txt The text to insert.
     */
    private void copyLiteral(final String txt) throws SQLException {
        final int len = txt.length();

        for (int i = 0; i < len; i++) {
            final char c = txt.charAt(i);

            if (c == '?') {
                if (params == null) {
                    throw new SQLException(
                            Messages.get("error.parsesql.unexpectedparam",
                                    String.valueOf(s)),
                            "2A000");
                }
                // param marker embedded in escape
                ParamInfo pi = new ParamInfo(d, connection.getSendUnicode());
                params.add(pi);
            }

            out[d++] = c;
        }
    }

    /**
     * Copies over an embedded string literal unchanged.
     */
    private void copyString() {
        char saveTc = terminator;
        char tc = in[s];

        if (tc == '[') {
            tc = ']';
        }

        terminator = tc;

        out[d++] = in[s++];

        while (in[s] != tc) {
            out[d++] = in[s++];
        }

        out[d++] = in[s++];

        terminator = saveTc;
    }

    /**
     * Copies over possible SQL keyword eg 'SELECT'
     */
    private String copyKeyWord() {
        int start = d;

        while (s < len && isIdentifier(in[s])) {
            out[d++] = in[s++];
        }

        return String.valueOf(out, start, d - start).toLowerCase();
    }

    /**
     * Builds a new parameter item.
     *
     * @param name Optional parameter name or null.
     * @param pos The parameter marker position in the output buffer.
     */
    private void copyParam(final String name, final int pos) throws SQLException {
        if (params == null) {
            throw new SQLException(
                    Messages.get("error.parsesql.unexpectedparam",
                            String.valueOf(s)),
                    "2A000");
        }

        ParamInfo pi = new ParamInfo(pos, connection.getSendUnicode());
        pi.name = name;

        if (pos >= 0) {
            out[d++] = in[s++];
        } else {
            pi.isRetVal = true;
            s++;
        }

        params.add(pi);
    }

    /**
     * Copies an embedded stored procedure identifier over to the output buffer.
     *
     * @return The identifier as a <code>String</code>.
     */
    private String copyProcName() throws SQLException {
        int start = d;

        do {
            if (in[s] == '"' || in[s] == '[') {
                copyString();
            } else {
                char c = in[s++];

                while (isIdentifier(c) || c == ';') {
                    out[d++] = c;
                    c = in[s++];
                }

                s--;
            }

            if (in[s] == '.') {
                while (in[s] == '.') {
                    out[d++] = in[s++];
                }
            } else {
                break;
            }
        } while (true);

        if (d == start) {
            // Procedure name expected but found something else
            throw new SQLException(
                    Messages.get("error.parsesql.syntax",
                            "call",
                            String.valueOf(s)),
                    "22025");
        }

        return new String(out, start, d - start);
    }

    /**
     * Copies an embedded parameter name to the output buffer.
     *
     * @return The identifier as a <code>String</code>.
     */
    private String copyParamName() {
        int start = d;
        char c = in[s++];

        while (isIdentifier(c)) {
            out[d++] = c;
            c = in[s++];
        }

        s--;

        return new String(out, start, d - start);
    }

    /**
     * Copies over white space.
     */
    private void copyWhiteSpace() {
        while (s < in.length && Character.isWhitespace(in[s])) {
            out[d++] = in[s++];
        }
    }

    /**
     * Checks that the next character is as expected.
     *
     * @param c The expected character.
     * @param copy True if found character should be copied.
     * @throws SQLException if expected characeter not found.
     */
    private void mustbe(final char c, final boolean copy)
        throws SQLException {
        if (in[s] != c) {
            throw new SQLException(
                    Messages.get("error.parsesql.mustbe",
                            String.valueOf(s),
                            String.valueOf(c)),
                    "22019");
        }

        if (copy) {
            out[d++] = in[s++];
        } else {
            s++;
        }
    }

    /**
     * Skips embedded white space.
     */
    private void skipWhiteSpace() {
        while (Character.isWhitespace(in[s])) {
            s++;
        }
    }

    /**
     * Skips single-line comments.
     */
    private void skipSingleComments() {
        while (s < len && in[s] != '\n' && in[s] != '\r') {
            // comments should be passed on to the server
            out[d++] = in[s++];
        }
    }

    /**
     * Skips multi-line comments
     */
    private void skipMultiComments() throws SQLException {
        int block = 0;

        do {
            if (s < len - 1) {
                if (in[s] == '/' && in[s + 1] == '*') {
                    block++;
                } else if (in[s] == '*' && in[s + 1] == '/') {
                    block--;
                }
                // comments should be passed on to the server
                out[d++] = in[s++];
            } else {
                throw new SQLException(
                        Messages.get("error.parsesql.missing", "*/"),
                        "22025");
            }
        } while (block > 0);
        out[d++] = in[s++];
    }

    /**
     * Processes the JDBC {call procedure [(&#63;,&#63;,&#63;)]} type escape.
     *
     * @throws SQLException if an error occurs
     */
    private void callEscape() throws SQLException {
        // Insert EXECUTE into SQL so that proc can be called as normal SQL
        copyLiteral("EXECUTE ");
        keyWord = "execute";
        // Process procedure name
        procName = copyProcName();
        skipWhiteSpace();

        if (in[s] == '(') { // Optional ( )
            s++;
            terminator = ')';
            skipWhiteSpace();
        } else {
            terminator = '}';
        }

        out[d++] = ' ';

        // Process any parameters
        while (in[s] != terminator) {
            String name = null;

            if (in[s] == '@') {
                // Named parameter
                name = copyParamName();
                skipWhiteSpace();
                mustbe('=', true);
                skipWhiteSpace();

                if (in[s] == '?') {
                    copyParam(name, d);
                } else {
                    // Named param has literal value can't call as RPC
                    procName = "";
                }
            } else if (in[s] == '?') {
                copyParam(name, d);
            } else {
                // Literal parameter can't call as RPC
                procName = "";
            }

            // Now find terminator or comma
            while (in[s] != terminator && in[s] != ',') {
                if (in[s] == '{') {
                    escape();
                } else if (in[s] == '\'' || in[s] == '[' || in[s] == '"') {
                    copyString();
                } else {
                    out[d++] = in[s++];
                }
            }

            if (in[s] == ',') {
                out[d++] = in[s++];
            }

            skipWhiteSpace();
        }

        if (terminator == ')') {
            s++; // Elide
        }

        terminator = '}';
        skipWhiteSpace();
    }

    /**
     * Utility routine to validate date and time escapes.
     *
     * @param mask The validation mask
     * @return True if the escape was valid and processed OK.
     */
    private boolean getDateTimeField(final byte[] mask) throws SQLException {
        skipWhiteSpace();
        if (in[s] == '?') {
            // Allow {ts ?} type construct
            copyParam(null, d);
            skipWhiteSpace();
            return in[s] == terminator;
        }
        out[d++] = '\'';
        terminator = (in[s] == '\'' || in[s] == '"') ? in[s++] : '}';
        skipWhiteSpace();
        int ptr = 0;

        while (ptr < mask.length) {
            char c = in[s++];
            if (c == ' ' && out[d - 1] == ' ') {
                continue; // Eliminate multiple spaces
            }

            if (mask[ptr] == '#') {
                if (!Character.isDigit(c)) {
                    return false;
                }
            } else if (mask[ptr] != c) {
                return false;
            }

            if (c != '-') {
                out[d++] = c;
            }

            ptr++;
        }

        if (mask.length == 19) { // Timestamp
            int digits = 0;

            if (in[s] == '.') {
                out[d++] = in[s++];

                while (Character.isDigit(in[s])) {
                    if (digits < 3) {
                        out[d++] = in[s++];
                        digits++;
                    } else {
                        s++;
                    }
                }
            } else {
                out[d++] = '.';
            }

            for (; digits < 3; digits++) {
                out[d++] = '0';
            }
        }

        skipWhiteSpace();

        if (in[s] != terminator) {
            return false;
        }

        if (terminator != '}') {
            s++; // Skip terminator
        }

        skipWhiteSpace();
        out[d++] = '\'';

        return true;
    }

    /** Syntax mask for time escape. */
    private static final byte[] timeMask = {
        '#','#',':','#','#',':','#','#'
    };

    /** Syntax mask for date escape. */
    private static final byte[] dateMask = {
        '#','#','#','#','-','#','#','-','#','#'
    };

    /** Syntax mask for timestamp escape. */
    static final byte[] timestampMask = {
        '#','#','#','#','-','#','#','-','#','#',' ',
        '#','#',':','#','#',':','#','#'
    };

    /**
     * Processes the JDBC escape {oj left outer join etc}.
     *
     * @throws SQLException
     */
    private void outerJoinEscape()
        throws SQLException {
        while (in[s] != '}') {
            final char c = in[s];

            switch (c) {
                case '\'':
                case '"':
                case '[':
                    copyString();
                    break;
                case '{':
                    // Nested escape!
                    escape();
                    break;
                case '?':
                    copyParam(null, d);
                    break;
                default:
                    out[d++] = c;
                    s++;
                    break;
            }
        }
    }

    /** Map of jdbc to sybase function names. */
    private static HashMap<String,String> fnMap = new HashMap<String,String>();
    /** Map of jdbc to sql server function names. */
    private static HashMap<String,String> msFnMap = new HashMap<String,String>();
    /** Map of jdbc to server data types for convert */
    private static HashMap<String,String> cvMap = new HashMap<String,String>();

    // FIXME: ASA most likely needs is own function map
    static {
        // Microsoft only functions
        msFnMap.put("length", "len($)");
        msFnMap.put("truncate", "round($, 1)");
        // Common functions
        fnMap.put("user",     "user_name($)");
        fnMap.put("database", "db_name($)");
        fnMap.put("ifnull",   "isnull($)");
        fnMap.put("now",      "getdate($)");
        fnMap.put("atan2",    "atn2($)");
        fnMap.put("mod",      "($)");
        fnMap.put("length",   "char_length($)");
        fnMap.put("locate",   "charindex($)");
        fnMap.put("repeat",   "replicate($)");
        fnMap.put("insert",   "stuff($)");
        fnMap.put("lcase",    "lower($)");
        fnMap.put("ucase",    "upper($)");
        fnMap.put("concat",   "($)");
        fnMap.put("curdate",  "convert(datetime, convert(varchar, getdate(), 112))");
        fnMap.put("curtime",  "convert(datetime, convert(varchar, getdate(), 108))");
        fnMap.put("dayname",  "datename(weekday,$)");
        fnMap.put("dayofmonth", "datepart(day,$)");
        fnMap.put("dayofweek", "((datepart(weekday,$)+@@DATEFIRST-1)%7+1)"); // @@DATEFIRST unknown to ASA, function caldayofweek should be correct for any server type
        fnMap.put("dayofyear",  "datepart(dayofyear,$)");
        fnMap.put("hour",       "datepart(hour,$)");
        fnMap.put("minute",     "datepart(minute,$)");
        fnMap.put("second",     "datepart(second,$)");
        fnMap.put("year",       "datepart(year,$)");
        fnMap.put("quarter",    "datepart(quarter,$)");
        fnMap.put("month",      "datepart(month,$)");
        fnMap.put("week",       "datepart(week,$)");
        fnMap.put("monthname",  "datename(month,$)");
        fnMap.put("timestampadd", "dateadd($)");
        fnMap.put("timestampdiff", "datediff($)");
        // convert jdbc to sql types
        cvMap.put("binary", "varbinary");
        cvMap.put("char", "varchar");
        cvMap.put("date", "datetime");
        cvMap.put("double", "float");
        cvMap.put("longvarbinary", "image");
        cvMap.put("longvarchar", "text");
        cvMap.put("time", "datetime");
        cvMap.put("timestamp", "timestamp");
    }

    /**
     * Processes the JDBC escape {fn function()}.
     *
     * @throws SQLException
     */
    private void functionEscape() throws SQLException {
        char tc = terminator;
        skipWhiteSpace();
        StringBuffer nameBuf = new StringBuffer();
        //
        // Capture name
        //
        while (isIdentifier(in[s])) {
            nameBuf.append(in[s++]);
        }

        String name = nameBuf.toString().toLowerCase();
        //
        // Now collect arguments
        //
        skipWhiteSpace();
        mustbe('(', false);
        int parenCnt = 1;
        int argStart = d;
        int arg2Start = 0;
        terminator = ')';
        while (in[s] != ')' || parenCnt > 1) {
            final char c = in[s];

            switch (c) {
                case '\'':
                case '"':
                case '[':
                    copyString();
                    break;
                case '{':
                    // Process nested escapes!
                    escape();
                    break;
                case ',':
                    if (arg2Start == 0) {
                        arg2Start = d - argStart;
                    }
                    if (name.equals("concat")) {
                        out[d++] = '+'; s++;
                    } else if (name.equals("mod")) {
                        out[d++] = '%'; s++;
                    } else {
                        out[d++] = c; s++;
                    }
                    break;
                case '(':
                    parenCnt++;
                    out[d++] = c; s++;
                    break;
                case ')':
                    parenCnt--;
                    out[d++] = c; s++;
                    break;
                default:
                    out[d++] = c; s++;
                    break;
            }
        }

        String args = String.valueOf(out, argStart, d - argStart).trim();

        d = argStart;
        mustbe(')', false);
        terminator = tc;
        skipWhiteSpace();

        //
        // Process convert scalar function.
        // Arguments need to be reversed and the data type
        // argument converted to an SQL server type
        //
        if (name.equals("convert") && arg2Start < args.length() - 1) {
            String arg2 = args.substring(arg2Start + 1).trim().toLowerCase();
            String dataType = cvMap.get(arg2);

            if (dataType == null) {
                // Will get server error if invalid type passed
                dataType = arg2;
            }

            copyLiteral("convert(");
            copyLiteral(dataType);
            out[d++] = ',';
            copyLiteral(args.substring(0, arg2Start));
            out[d++] = ')';

            return;
        }

        //
        // See if function mapped
        //
        String fn;
        if (connection.getServerType() == TdsCore.SQLSERVER) {
            fn = msFnMap.get(name);
            if (fn == null) {
                fn = fnMap.get(name);
            }
        } else {
            fn = fnMap.get(name);
        }
        if (fn == null) {
            // Not mapped so assume simple case
            copyLiteral(name);
            out[d++] = '(';
            copyLiteral(args);
            out[d++] = ')';
            return;
        }
        //
        // Process timestamp interval constants
        //
        if (args.length() > 8
            && args.substring(0, 8).equalsIgnoreCase("sql_tsi_")) {
            args = args.substring(8);
            if (args.length() > 11
                && args.substring(0, 11).equalsIgnoreCase("frac_second")) {
                args = "millisecond" + args.substring(11);
            }
        }
        //
        // Substitute mapped function name and arguments
        //
        final int len = fn.length();
        for (int i = 0; i < len; i++) {
            final char c = fn.charAt(i);
            if (c == '$') {
                // Substitute arguments
                copyLiteral(args);
            } else {
                out[d++] = c;
            }
        }
    }

    /**
     * Processes the JDBC escape {escape 'X'}.
     *
     * @throws SQLException
     */
    private void likeEscape() throws SQLException {
        copyLiteral("escape ");
        skipWhiteSpace();

        if (in[s] == '\'' || in[s] == '"') {
            copyString();
        } else {
            mustbe('\'', true);
        }

        skipWhiteSpace();
    }

    /**
     * Processes the JDBC escape sequences.
     *
     * @throws SQLException
     */
    private void escape() throws SQLException {
        char tc = terminator;
        terminator = '}';
        StringBuffer escBuf = new StringBuffer();
        s++;
        skipWhiteSpace();

        if (in[s] == '?') {
            copyParam("@return_status", -1);
            skipWhiteSpace();
            mustbe('=', false);
            skipWhiteSpace();

            while (Character.isLetter(in[s])) {
                escBuf.append(Character.toLowerCase(in[s++]));
            }

            skipWhiteSpace();
            String esc = escBuf.toString();

            if (esc.equals("call")) {
                callEscape();
            } else {
                throw new SQLException(
                        Messages.get("error.parsesql.syntax",
                                "call",
                                String.valueOf(s)),
                        "22019");
            }
        } else {
            while (Character.isLetter(in[s])) {
                escBuf.append(Character.toLowerCase(in[s++]));
            }

            skipWhiteSpace();
            String esc = escBuf.toString();

            if (esc.equals("call")) {
                callEscape();
            } else if (esc.equals("t")) {
                if (!getDateTimeField(timeMask)) {
                    throw new SQLException(
                            Messages.get("error.parsesql.syntax",
                                         "time",
                                         String.valueOf(s)),
                            "22019");
                }
            } else if (esc.equals("d")) {
                if (!getDateTimeField(dateMask)) {
                    throw new SQLException(
                            Messages.get("error.parsesql.syntax",
                                         "date",
                                         String.valueOf(s)),
                            "22019");
                }
            } else if (esc.equals("ts")) {
                if (!getDateTimeField(timestampMask)) {
                    throw new SQLException(
                            Messages.get("error.parsesql.syntax",
                                         "timestamp",
                                         String.valueOf(s)),
                            "22019");
                }
            } else if (esc.equals("oj")) {
                outerJoinEscape();
            } else if (esc.equals("fn")) {
                functionEscape();
            } else if (esc.equals("escape")) {
                likeEscape();
            } else {
                throw new SQLException(
                        Messages.get("error.parsesql.badesc",
                                esc,
                                String.valueOf(s)),
                        "22019");
            }
        }

        mustbe('}', false);
        terminator = tc;
    }

    /**
     * Extracts the first table name following the keyword FROM.
     *
     * @return the table name as a <code>String</code>
     */
    private String getTableName() throws SQLException {
        StringBuffer name = new StringBuffer(128);
        copyWhiteSpace();
        char c = (s < len) ? in[s] : ' ';
        if (c == '{') {
            // Start of {oj ... } we can assume that there is
            // more than one table in select and therefore
            // it would not be updateable.
            return "";
        }
        //
        // Skip any leading comments before first table name
        //
        while (c == '/' || c == '-' && s + 1 < len) {
            if (c == '/') {
                if (in[s + 1] == '*') {
                    skipMultiComments();
                } else {
                    break;
                }
            } else {
                if (in[s + 1] == '-') {
                    skipSingleComments();
                } else {
                    break;
                }
            }
            copyWhiteSpace();
            c = (s < len) ? in[s] : ' ';
        }

        if (c == '{') {
            // See comment above
            return "";
        }
        //
        // Now process table name
        //
        while (s < len) {
            if (c == '[' || c == '"') {
                int start = d;
                copyString();
                name.append(String.valueOf(out, start, d - start));
                copyWhiteSpace();
                c = (s < len) ? in[s] : ' ';
            } else {
                int start = d;
                c = (s < len) ? in[s++] : ' ';
                while ((isIdentifier(c))
                       && c != '.'
                       && c != ',') {
                    out[d++] = c;
                    c = (s < len) ? in[s++] : ' ';
                }
                name.append(String.valueOf(out, start, d - start));
                s--;
                copyWhiteSpace();
                c = (s < len) ? in[s] : ' ';
            }
            if (c != '.') {
                break;
            }
            name.append(c);
            out[d++] = c; s++;
            copyWhiteSpace();
            c = (s < len) ? in[s] : ' ';
        }
        return name.toString();
    }

    /**
     * Parses the SQL statement processing JDBC escapes and parameter markers.
     *
     * @param extractTable true to return the first table name in the FROM clause of a select
     * @return The processed SQL statement, any procedure name, the first
     * SQL keyword and (optionally) the first table name as elements 0 1, 2 and 3 of the
     * returned <code>String[]</code>.
     * @throws SQLException
     */
    String[] parse(final boolean extractTable) throws SQLException {
        boolean isSelect   = false;
        boolean isModified = false;
        boolean isSlowScan = true;
        try {
            while (s < len) {
                final char c = in[s];

                switch (c) {
                    case '{':
                        escape();
                        isModified = true;
                        break;
                    case '[':
                    case '"':
                    case '\'':
                        copyString();
                        break;
                    case '?':
                        copyParam(null, d);
                        break;
                    case '/':
                        if (s+1 < len && in[s+1] == '*') {
                            skipMultiComments();
                        } else {
                            out[d++] = c; s++;
                        }
                        break;
                    case '-':
                        if (s+1 < len && in[s+1] == '-') {
                            skipSingleComments();
                        } else {
                            out[d++] = c; s++;
                        }
                        break;
                    default:
                        if (isSlowScan && Character.isLetter(c)) {
                            if (keyWord == null) {
                                keyWord = copyKeyWord();
                                if (keyWord.equals("select")) {
                                    isSelect = true;
                                }
                                isSlowScan = extractTable && isSelect;
                                break;
                            }
                            if (extractTable && isSelect) {
                                String sqlWord = copyKeyWord();
                                if (sqlWord.equals("from")) {
                                    // Ensure only first 'from' is processed
                                    isSlowScan = false;
                                    tableName = getTableName();
                                }
                                break;
                            }
                        }

                        out[d++] = c; s++;
                        break;
                }
            }

            //
            // Impose a reasonable maximum limit on the number of parameters
            // unless the connection is sending statements unprepared (i.e. by
            // building a plain query) and this is not a procedure call.
            //
            if (params != null && params.size() > 255
                    && connection.getDataSource().getPrepareSql() != TdsCore.UNPREPARED
                    && procName != null) {
                int limit = 255; // SQL 6.5 and Sybase < 12.50
                if (connection.getServerType() == TdsCore.SYBASE) {
                    if (connection.getMetaData().getDatabaseMajorVersion() > 12 ||
                            connection.getMetaData().getDatabaseMajorVersion() == 12 &&
                            connection.getMetaData().getDatabaseMinorVersion() >= 50) {
                        limit = 2000; // Actually 2048 but allow some head room
                    }
                } else if (connection.getServerType() == TdsCore.ANYWHERE) {
                    limit = 65536; // minimum possible value, (page size/4)^2
                }
                else {
                    if (connection.getMetaData().getDatabaseMajorVersion() == 7) {
                        limit = 1000; // Actually 1024
                    } else
                    if (connection.getMetaData().getDatabaseMajorVersion() > 7) {
                        limit = 2000; // Actually 2100
                    }

                }
                if (params.size() > limit) {
                    throw new SQLException(
                        Messages.get("error.parsesql.toomanyparams",
                                Integer.toString(limit)),
                        "22025");
                }
            }
            String result[] = new String[4];

            // return sql and procname
            result[0] = (isModified) ? new String(out, 0, d) : sql;
            result[1] = procName;
            result[2] = (keyWord == null) ? "" : keyWord;
            result[3] = tableName;
            return result;
        } catch (IndexOutOfBoundsException e) {
            // Should only come here if string is invalid in some way.
            throw new SQLException(
                    Messages.get("error.parsesql.missing",
                            String.valueOf(terminator)),
                    "22025");
        }
    }
}
