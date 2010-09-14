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
package net.sourceforge.jtds.util;

import java.sql.*;
import java.io.PrintWriter;
import java.io.FileOutputStream;
import java.io.IOException;

import net.sourceforge.jtds.jdbc.CommonDataSource;

/**
 * Class providing static methods to log diagnostics.
 * <p>
 * There are three ways to enable logging:
 * <ol>
 * <li>Pass a valid PrintWriter to DriverManager.setLogWriter().
 * <li>Pass a valid PrintWriter to DataSource.setLogWriter().
 * <li>For backwards compatibility call Logger.setActive();
 * </ol>
 *
 * @author Mike Hutchinson
 * @version $Id: Logger.java,v 1.1 2007-09-10 19:19:35 bheineman Exp $
 */
public class Logger {
    /** Print only error messages. */
    private final static int LEVEL_DEBUG  = 1;
    /** Print all debug messages. */
    private final static int LEVEL_TRACE  = 2;
    /** Print network packet dump. */
    private final static int LEVEL_PACKET = 3;
    /** PrintWriter stream set by DataSource. */
    private static PrintWriter log;
    /** The log level. */
    private static int level = LEVEL_DEBUG;
    /**
     * Set the logging PrintWriter stream.
     *
     * @param out the PrintWriter stream
     */
    public static void setLogWriter(PrintWriter out) {
        log = out;
    }

    /**
     * Get the logging PrintWriter Stream.
     *
     * @return the logging stream as a <code>PrintWriter</code>
     */
    public static PrintWriter getLogWriter() {
        return log;
    }

    /**
     * Initialize the logging subsystem using the connection properties.
     * @param ds the data source with the logging properties.
     * @throws SQLException
     */
    public static void  initialize(CommonDataSource ds) throws SQLException {
        PrintWriter writer = ds.getLogWriter();
        String logFile = ds.getLogFile();
        if (writer == null && log == null && logFile.length() > 0) {
            // Try to initialise a PrintWriter using supplied file name
            try {
                if (logFile.equals("System.out")) {
                    writer = new PrintWriter(System.out, true);
                } else
                if (logFile.equals("System.err")) {
                    writer = new PrintWriter(System.err, true);
                } else {
                    writer = new PrintWriter(new FileOutputStream(logFile), true);
                }
            } catch (IOException e) {
                System.err.println("jTDS: Failed to set log file " + e);
            }
        }
        synchronized (net.sourceforge.jtds.util.Logger.class) {
            if (writer != null) {
                log = writer;
            }
            level = ds.getLogLevel();
        }
    }
    
    /**
     * Retrieve the active status of the logger.
     *
     * @return <code>boolean</code> true if logging enabled
     */
    public static boolean isActive() {
        return(log != null || DriverManager.getLogWriter() != null);
    }

    /**
     * Retrieve the trace status of the logger.
     *
     * @return <code>boolean</code> true if trace logging enabled
     */
    public static boolean isTraceActive() {
        return(log != null || DriverManager.getLogWriter() != null && level > 1);
    }

    /**
     * Print a diagnostic message to the output stream provided by
     * the DataSource or the DriverManager.
     *
     * @param message the diagnostic message to print
     */
    public static void println(String message) {
        if (level >= LEVEL_DEBUG) {
            if (log != null) {
                log.println("jTDS: " + message);
            } else {
                DriverManager.println("jTDS: " + message);
            }
        }
    }
    
    /**
     * Print a diagnostic trace to the output stream provided by
     * the DataSource or the DriverManager.
     * @param message the message to display.
     */
    public static void printTrace(String message) {
        if (level >= LEVEL_TRACE && message != null) {
            println(message);
        }
    }
    
    /**
     * Print a diagnostic trace of a method call to the output stream provided by
     * the DataSource or the DriverManager.
     * 
     * @param obj the object owning the method.
     * @param method the method name or null for constructor.
     * @param args the arguments passed to this method.
     */
    public static void printMethod(Object obj, String method, Object args[]) {
        if (level >= LEVEL_TRACE && obj != null) {
            StringBuilder buf = new StringBuilder(128);
            buf.append(obj.getClass().getName());
            if (method != null) {
                buf.append('.').append(method);
            }
            buf.append('(');
            if (args != null) {
                for (int i = 0; i < args.length; i++) {
                    if (i > 0) {
                        buf.append(", ");
                    }
                    buf.append(((args[i] != null)? args[i].toString(): "null"));
                }
            }
            buf.append(')').append(((method == null)? " created.": " invoked."));
            println(buf.toString());
        }
    }

    /**
     * Print a diagnostic SQL trace to the output stream provided by
     * the DataSource or the DriverManager.
     * @param sql the SQL statement that is being sent to the server.
     */
    public static void printSql(String sql) {
        if (level >= LEVEL_TRACE && sql != null) {
            StringBuilder msg = new StringBuilder(80);
            msg.append("jTDS: ");
            int len = sql.length();
            for (int i = 0; i < len; i++) {
                char c = sql.charAt(i);
                if (c == '\n' || msg.length() > 77) {
                    if (log != null) {
                        log.println(msg.toString());
                    } else {
                        DriverManager.println(msg.toString());
                    }
                    msg.setLength(0);
                    msg.append("jTDS:-");
                } else {
                    if (c != '\r') {
                        msg.append(c);
                    }
                }
            }
            if (msg.length() > 6) {
                if (log != null) {
                    log.println(msg.toString());
                } else {
                    DriverManager.println(msg.toString());
                }
            }
        }
    }

    /**
     * Print a diagnostic SQL trace of an RPC Call to the output stream provided by
     * the DataSource or the DriverManager.
     * @param sp the SQL statement that is being sent to the server.
     */
    public static void printRPC(String sp) {
        if (level >= LEVEL_TRACE && sp != null) {
            String message = "jTDS: EXECUTE " + sp; 
            if (log != null) {
                log.println(message);
            } else {
                DriverManager.println(message);
            }
        }
    }

    private static final char hex[] =
    {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    /**
     * Print a dump of the current input or output network packet.
     *
     * @param in       true if this is an input packet
     * @param pkt      the packet data
     */
    public static void logPacket(boolean in, byte[] pkt) {
        if (level < LEVEL_PACKET) {
            // Packet logging not enabled
            return;
        }
        int len = ((pkt[2] & 0xFF) << 8)| (pkt[3] & 0xFF);

        StringBuffer line = new StringBuffer(80);

        line.append("----- Thread #");
        line.append(Thread.currentThread().toString());
        line.append(in ? " read" : " send");
        line.append((pkt[1] != 0) ? " last " : " ");

        switch (pkt[0]) {
            case 1:
                line.append("Request packet ");
                break;
            case 2:
                line.append("Login packet ");
                break;
            case 3:
                line.append("RPC packet ");
                break;
            case 4:
                line.append("Reply packet ");
                break;
            case 6:
                line.append("Cancel packet ");
                break;
            case 7:
                line.append("BCP packet ");
                break;
            case 14:
                line.append("XA control packet ");
                break;
            case 15:
                line.append("TDS5 Request packet ");
                break;
            case 16:
                line.append("MS Login packet ");
                break;
            case 17:
                line.append("NTLM Authentication packet ");
                break;
            case 18:
                line.append("MS Prelogin packet ");
                break;
            default:
                line.append("Invalid packet ");
                break;
        }

        println(line.toString());
        println("");
        line.setLength(0);

        for (int i = 0; i < len; i += 16) {
            if (i < 1000) {
                line.append(' ');
            }

            if (i < 100) {
                line.append(' ');
            }

            if (i < 10) {
                line.append(' ');
            }

            line.append(i);
            line.append(':').append(' ');

            int j = 0;

            for (; j < 16 && i + j < len; j++) {
                int val = pkt[i+j] & 0xFF;

                line.append(hex[val >> 4]);
                line.append(hex[val & 0x0F]);
                line.append(' ');
            }

            for (; j < 16 ; j++) {
                line.append("   ");
            }

            line.append('|');

            for (j = 0; j < 16 && i + j < len; j++) {
                int val = pkt[i + j] & 0xFF;

                if (val > 31 && val < 127) {
                    line.append((char) val);
                } else {
                    line.append(' ');
                }
            }

            line.append('|');
            println(line.toString());
            line.setLength(0);
        }

        println("");
    }

    /**
     * Print an Exception stack trace to the log.
     *
     * @param e the exception to log
     * @return the exception;
     */
    public static Exception logException(Exception e) {
        if (log != null) {
            if (level >= LEVEL_TRACE && !(e instanceof SQLWarning)) {
                if (e instanceof SQLException && DriverManager.getLogWriter() != null) {
                    return e; // Avoid logging exception twice
                }
                e.printStackTrace(log);
            } else {
                String msg = "jTDS: " + e.getClass().getName() + ": " +
                    e.getMessage();
                println(msg);
            }
        }
        return e;
    }
}