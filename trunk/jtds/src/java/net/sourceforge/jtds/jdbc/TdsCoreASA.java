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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.sql.SQLException;

import net.sourceforge.jtds.util.Logger;

/**
 * This class implements the Sybase TDS 5.0 protocol dialect implemented by
 * Sybase Adaptive Server Anywhere, now known as SQL Anywhere.
 *
 * @author Holger Rehn
 * @author Mike Hutchinson
 * @author Matt Brinkley
 * @author Alin Sinpalean
 * @author FreeTDS project
 * @version $Id: TdsCoreASA.java,v 1.1 2009-07-23 12:25:54 ickzon Exp $
 */
class TdsCoreASA extends TdsCore50 {

    /**
     * Construct a TdsCore object.
     *
     * @param connection The connection which owns this object.
     * @param socket The TDS socket instance.
     * @param serverType The appropriate server type constant.
     */
    TdsCoreASA(final ConnectionImpl connection,
               final TdsSocket socket,
               final int serverType) {
        super(connection, socket, serverType);
    }

    /**
     * Login to the Anywhere Server.
     *
     * @param cx         StatementImpl instance
     * @param serverName server host name
     * @param database   required database
     * @param user       user name
     * @param password   user password
     * @param domain     Windows NT domain (or null)
     * @param charset    required server character set
     * @param appName    application name
     * @param progName   library name
     * @param wsid       workstation ID
     * @param language   language to use for server messages
     * @param macAddress client network MAC address
     * @param packetSize required network packet size
     * @throws SQLException if an error occurs
     */
    void login(final StatementImpl cx,
               final String serverName,
               final String database,
               final String user,
               final String password,
               final String domain,
               final String charset,
               final String appName,
               final String progName,
               final String wsid,
               final String language,
               final String macAddress,
               final int packetSize)
        throws SQLException {
        Logger.printMethod(this, "login", null);
        try {
            send50LoginPkt(database, user, password,
                                charset, appName, progName, 
                                (wsid.length() == 0)? getHostName(): wsid,
                                language, packetSize);
            endOfResponse = false;
            nextToken(cx);

            while (!endOfResponse) {
                nextToken(cx);
            }

            cx.getMessages().checkErrors();
        } catch (IOException ioe) {
            SQLException sqle = new SQLException(
                    Messages.get(
                             "error.generic.ioerror", ioe.getMessage()),
                                 "08S01");
            sqle.initCause(ioe);
            throw sqle;
        }
    }

 // ---------------------- Private Methods from here ---------------------

    /**
     * ASA specific TDS 5.0 Login Packet.
     * <p>
     * @param database   required database
     * @param user       user name
     * @param password   user password
     * @param charset    required server character set
     * @param appName    application name
     * @param progName   library name
     * @param wsid       workstation ID
     * @param language   server language for messages
     * @param packetSize required network packet size
     * @throws IOException if an I/O error occurs
     */
    private void send50LoginPkt(final String database, 
                                final String user,
                                final String password,
                                final String charset,
                                final String appName,
                                final String progName,
                                final String wsid,
                                final String language,
                                final int packetSize)
        throws IOException 
    {
        final byte[] empty = new byte[0];

        out.setPacketType(LOGIN_PKT);
        putLoginString(wsid, 30);           // host name
        putLoginString(user, 30);           // user name
        putLoginString(password, 30);       // password
        putLoginString("00000123", 30);     // hostproc (offset 93 0x5d)

        out.write((byte) 3); // type of int2
        out.write((byte) 1); // type of int4
        out.write((byte) 6); // type of char
        out.write((byte) 10);// type of flt
        out.write((byte) 9); // type of date
        out.write((byte) 1); // notify of use db
        out.write((byte) 1); // disallow dump/load and bulk insert
        out.write((byte) 0); // sql interface type
        out.write((byte) 0); // type of network connection

        out.write(empty, 0, 7);

        putLoginString(appName, 30);  // appname
        putLoginString(database, 30); // database name

        out.write((byte)0); // remote passwords
        ByteBuffer bb = connection.getCharset().encode(password);
        byte buf[] = new byte[bb.remaining()];
        bb.get(buf);
        out.write((byte)buf.length);
        out.write(buf, 0, 253);
        out.write((byte) (buf.length + 2));

        out.write((byte) 5);  // tds version
        out.write((byte) 0);

        out.write((byte) 0);
        out.write((byte) 0);
        putLoginString(progName, 10); // prog name

        out.write((byte) 5);  // prog version
        out.write((byte) 0);
        out.write((byte) 0);
        out.write((byte) 0);

        out.write((byte) 0);  // auto convert short
        out.write((byte) 0x0D); // type of flt4
        out.write((byte) 0x11); // type of date4

        putLoginString(language, 30);  // language

        out.write((byte) 1);  // notify on lang change
        out.write((short) 0);  // security label hierachy
        out.write((byte) 0);  // security encrypted
        out.write(empty, 0, 8);  // security components
        out.write((short) 0);  // security spare

        putLoginString(charset, 30); // Character set

        out.write((byte) 1);  // notify on charset change
        if (packetSize > 0) {
            putLoginString(String.valueOf(packetSize), 6); // specified length of tds packets
        } else {
            putLoginString(String.valueOf(MIN_PKT_SIZE), 6); // Default length of tds packets
        }
        out.write(empty, 0, 4);
        //
        // Request capabilities
        //
        // jTDS sends   01 0B 4F FF 85 EE EF 65 7F FF FF FF D6
        // Sybase 11.92 01 0A    00 00 00 23 61 41 CF FF FF C6
        // Sybase 12.52 01 0A    03 84 0A E3 61 41 FF FF FF C6
        // Sybase 15.00 01 0B 4F F7 85 EA EB 61 7F FF FF FF C6
        //
        // Response capabilities
        //
        // jTDS sends   02 0A 00 00 04 06 80 06 48 00 00 00
        // Sybase 11.92 02 0A 00 00 00 00 00 06 00 00 00 00
        // Sybase 12.52 02 0A 00 00 00 00 00 06 00 00 00 00
        // Sybase 15.00 02 0A 00 00 04 00 00 06 00 00 00 00
        //
        byte capString[] = {
            // Request capabilities
            (byte)0x01,(byte)0x0B,(byte)0x4F,(byte)0xFF,(byte)0x85,(byte)0xEE,(byte)0xEF,
            (byte)0x65,(byte)0x7F,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xD6,
            // Response capabilities
            (byte)0x02,(byte)0x0A,(byte)0x00,(byte)0x02,(byte)0x04,(byte)0x06,
            (byte)0x80,(byte)0x06,(byte)0x48,(byte)0x00,(byte)0x00,(byte)0x0C
        };

        if (packetSize == 0) {
            // Tell the server we will use its packet size
            capString[17] = 0;
        }
        out.write(TDS_CAP_TOKEN);
        out.write((short)capString.length);
        out.write(capString);

        out.flush(); // Send the packet
    }
}
