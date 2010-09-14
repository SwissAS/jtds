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

import java.util.HashMap;
import java.nio.charset.*;
import java.sql.SQLException;

import net.sourceforge.jtds.util.Logger;

/**
 * Class to support the use of the java.nio.Charset class.
 *
 */
public class CharsetUtil {
    /** Table of common SQL Server character set aliases. */
    private static final HashMap<String, String> csAlias = new HashMap<String, String>();
    static {
        csAlias.put("ISO_1", "ISO-8859-1");
        csAlias.put("ISO15", "ISO-8859-15");
        csAlias.put("ASCII_7", "US-ASCII");
        csAlias.put("ASCII_8", "US-ASCII");
        csAlias.put("ROMAN8" , "ISO-8859-1");
        csAlias.put("MAC", "MacRoman");
        csAlias.put("GREEK8", "ISO-8859-7");
        csAlias.put("MACGRK2", "ISO-8859-7");
        csAlias.put("MAC_CYR", "ISO-8859-5");
        csAlias.put("SJIS", "Shift_JIS");
        csAlias.put("BIG5", "Big5");
        csAlias.put("BIG5HK", "Big5-HKSCS");
        csAlias.put("GB2312", "MS936");
        csAlias.put("GBK", "MS936");
        csAlias.put("KOI8", "KOI8-R");
        csAlias.put("TIS620", "TIS-620");
        csAlias.put("DECKANJI", "EUC_JP");
        csAlias.put("EUCCNS", "x-EUC-CN");
        csAlias.put("EUCJIS", "EUC-JP");
        csAlias.put("EUCGB", "x-EUC-CN");
        csAlias.put("EUCKSC", "EUC-KR");
        csAlias.put("UTF8", "UTF-8");
        csAlias.put("UNICODE", "UTF-16");
    }
    /** Table of locale ID to charset mappings. */
    private static final HashMap<Integer, String> lcidMap = new HashMap<Integer, String>();
    static {
        lcidMap.put(new Integer(1025), "Cp1256");
        lcidMap.put(new Integer(1026), "Cp1251");
        lcidMap.put(new Integer(1027), "Cp1252");
        lcidMap.put(new Integer(1028), "MS950");
        lcidMap.put(new Integer(1029), "Cp1250");
        lcidMap.put(new Integer(1030), "Cp1252");
        lcidMap.put(new Integer(1031), "Cp1252");
        lcidMap.put(new Integer(1032), "Cp1253");
        lcidMap.put(new Integer(1033), "Cp1252");
        lcidMap.put(new Integer(1034), "Cp1252");
        lcidMap.put(new Integer(1035), "Cp1252");
        lcidMap.put(new Integer(1036), "Cp1252");
        lcidMap.put(new Integer(1037), "Cp1255");
        lcidMap.put(new Integer(1038), "Cp1250");
        lcidMap.put(new Integer(1039), "Cp1252");
        lcidMap.put(new Integer(1040), "Cp1252");
        lcidMap.put(new Integer(1041), "MS932");
        lcidMap.put(new Integer(1042), "MS949");
        lcidMap.put(new Integer(1043), "Cp1252");
        lcidMap.put(new Integer(1044), "Cp1252");
        lcidMap.put(new Integer(1045), "Cp1250");
        lcidMap.put(new Integer(1046), "Cp1252");
        lcidMap.put(new Integer(1048), "Cp1250");
        lcidMap.put(new Integer(1049), "Cp1251");
        lcidMap.put(new Integer(1050), "Cp1250");
        lcidMap.put(new Integer(1051), "Cp1250");
        lcidMap.put(new Integer(1052), "Cp1250");
        lcidMap.put(new Integer(1053), "Cp1252");
        lcidMap.put(new Integer(1054), "MS874");
        lcidMap.put(new Integer(1055), "Cp1254");
        lcidMap.put(new Integer(1056), "Cp1256");
        lcidMap.put(new Integer(1057), "Cp1252");
        lcidMap.put(new Integer(1058), "Cp1251");
        lcidMap.put(new Integer(1059), "Cp1251");
        lcidMap.put(new Integer(1060), "Cp1250");
        lcidMap.put(new Integer(1061), "Cp1257");
        lcidMap.put(new Integer(1062), "Cp1257");
        lcidMap.put(new Integer(1063), "Cp1257");
        lcidMap.put(new Integer(1065), "Cp1256");
        lcidMap.put(new Integer(1066), "Cp1258");
        lcidMap.put(new Integer(1069), "Cp1252");
        lcidMap.put(new Integer(1071), "Cp1251");
        lcidMap.put(new Integer(1080), "Cp1252");
        lcidMap.put(new Integer(2049), "Cp1256");
        lcidMap.put(new Integer(2052), "MS936");
        lcidMap.put(new Integer(2055), "Cp1252");
        lcidMap.put(new Integer(2057), "Cp1252");
        lcidMap.put(new Integer(2058), "Cp1252");
        lcidMap.put(new Integer(2060), "Cp1252");
        lcidMap.put(new Integer(2064), "Cp1252");
        lcidMap.put(new Integer(2067), "Cp1252");
        lcidMap.put(new Integer(2068), "Cp1252");
        lcidMap.put(new Integer(2070), "Cp1252");
        lcidMap.put(new Integer(2074), "Cp1251");
        lcidMap.put(new Integer(2087), "Cp1257");
        lcidMap.put(new Integer(3073), "Cp1256");
        lcidMap.put(new Integer(3081), "Cp1252");
        lcidMap.put(new Integer(3082), "Cp1252");
        lcidMap.put(new Integer(3084), "Cp1252");
        lcidMap.put(new Integer(3097), "Cp1252");
        lcidMap.put(new Integer(3098), "Cp1251");
        lcidMap.put(new Integer(4097), "Cp1256");
        lcidMap.put(new Integer(4100), "MS936");
        lcidMap.put(new Integer(4103), "Cp1252");
        lcidMap.put(new Integer(4105), "Cp1252");
        lcidMap.put(new Integer(4106), "Cp1252");
        lcidMap.put(new Integer(4108), "Cp1252");
        lcidMap.put(new Integer(5121), "Cp1256");
        lcidMap.put(new Integer(5127), "Cp1252");
        lcidMap.put(new Integer(5129), "Cp1252");
        lcidMap.put(new Integer(5130), "Cp1252");
        lcidMap.put(new Integer(5132), "Cp1252");
        lcidMap.put(new Integer(5145), "Cp1256");
        lcidMap.put(new Integer(6153), "Cp1252");
        lcidMap.put(new Integer(6154), "Cp1252");
        lcidMap.put(new Integer(7169), "Cp1256");
        lcidMap.put(new Integer(7178), "Cp1252");
        lcidMap.put(new Integer(7717), "Cp1252");
        lcidMap.put(new Integer(8193), "Cp1256");
        lcidMap.put(new Integer(8201), "Cp1252");
        lcidMap.put(new Integer(8202), "Cp1252");
        lcidMap.put(new Integer(9217), "Cp1256");
        lcidMap.put(new Integer(9225), "Cp1252");
        lcidMap.put(new Integer(9226), "Cp1252");
        lcidMap.put(new Integer(10241), "Cp1256");
        lcidMap.put(new Integer(10250), "Cp1252");
        lcidMap.put(new Integer(11265), "Cp1256");
        lcidMap.put(new Integer(11274), "Cp1252");
        lcidMap.put(new Integer(12289), "Cp1256");
        lcidMap.put(new Integer(12298), "Cp1252");
        lcidMap.put(new Integer(13313), "Cp1256");
        lcidMap.put(new Integer(13322), "Cp1252");
        lcidMap.put(new Integer(14337), "Cp1256");
        lcidMap.put(new Integer(14346), "Cp1252");
        lcidMap.put(new Integer(15361), "Cp1256");
        lcidMap.put(new Integer(15370), "Cp1252");
        lcidMap.put(new Integer(16385), "Cp1256");
        lcidMap.put(new Integer(16394), "Cp1252");
        lcidMap.put(new Integer(66567), "Cp1252");
        lcidMap.put(new Integer(66574), "Cp1250");
        lcidMap.put(new Integer(66577), "MS932");
        lcidMap.put(new Integer(66578), "MS949");
        lcidMap.put(new Integer(66615), "Cp1252");
        lcidMap.put(new Integer(133124), "MS936");
        lcidMap.put(new Integer(197636), "MS950");
    }
    /** Table of sort code to charset mappings.*/
    private static final String[] sortMap = new String[256];
    static {
        sortMap[ 30] = "Cp437";
        sortMap[ 31] = "Cp437";
        sortMap[ 32] = "Cp437";
        sortMap[ 33] = "Cp437";
        sortMap[ 34] = "Cp437";
        sortMap[ 40] = "Cp850";
        sortMap[ 41] = "Cp850";
        sortMap[ 42] = "Cp850";
        sortMap[ 43] = "Cp850";
        sortMap[ 44] = "Cp850";
        sortMap[ 49] = "Cp850";
        sortMap[ 50] = "Cp1252";
        sortMap[ 51] = "Cp1252";
        sortMap[ 52] = "Cp1252";
        sortMap[ 53] = "Cp1252";
        sortMap[ 54] = "Cp1252";
        sortMap[ 55] = "Cp850";
        sortMap[ 56] = "Cp850";
        sortMap[ 57] = "Cp850";
        sortMap[ 58] = "Cp850";
        sortMap[ 59] = "Cp850";
        sortMap[ 60] = "Cp850";
        sortMap[ 61] = "Cp850";
        sortMap[ 71] = "Cp1252";
        sortMap[ 72] = "Cp1252";
        sortMap[ 80] = "Cp1250";
        sortMap[ 81] = "Cp1250";
        sortMap[ 82] = "Cp1250";
        sortMap[ 83] = "Cp1250";
        sortMap[ 84] = "Cp1250";
        sortMap[ 85] = "Cp1250";
        sortMap[ 86] = "Cp1250";
        sortMap[ 87] = "Cp1250";
        sortMap[ 88] = "Cp1250";
        sortMap[ 89] = "Cp1250";
        sortMap[ 90] = "Cp1250";
        sortMap[ 91] = "Cp1250";
        sortMap[ 92] = "Cp1250";
        sortMap[ 93] = "Cp1250";
        sortMap[ 94] = "Cp1250";
        sortMap[ 95] = "Cp1250";
        sortMap[ 96] = "Cp1250";
        sortMap[104] = "Cp1251";
        sortMap[105] = "Cp1251";
        sortMap[106] = "Cp1251";
        sortMap[107] = "Cp1251";
        sortMap[108] = "Cp1251";
        sortMap[112] = "Cp1253";
        sortMap[113] = "Cp1253";
        sortMap[114] = "Cp1253";
        sortMap[120] = "Cp1253";
        sortMap[121] = "Cp1253";
        sortMap[124] = "Cp1253";
        sortMap[128] = "Cp1254";
        sortMap[129] = "Cp1254";
        sortMap[130] = "Cp1254";
        sortMap[136] = "Cp1255";
        sortMap[137] = "Cp1255";
        sortMap[138] = "Cp1255";
        sortMap[144] = "Cp1256";
        sortMap[145] = "Cp1256";
        sortMap[146] = "Cp1256";
        sortMap[152] = "Cp1257";
        sortMap[153] = "Cp1257";
        sortMap[154] = "Cp1257";
        sortMap[155] = "Cp1257";
        sortMap[156] = "Cp1257";
        sortMap[157] = "Cp1257";
        sortMap[158] = "Cp1257";
        sortMap[159] = "Cp1257";
        sortMap[160] = "Cp1257";
        sortMap[183] = "Cp1252";
        sortMap[184] = "Cp1252";
        sortMap[185] = "Cp1252";
        sortMap[186] = "Cp1252";
        sortMap[192] = "MS932";
        sortMap[193] = "MS932";
        sortMap[194] = "MS949";
        sortMap[195] = "MS949";
        sortMap[196] = "MS950";
        sortMap[197] = "MS950";
        sortMap[198] = "MS936";
        sortMap[199] = "MS936";
        sortMap[200] = "MS932";
        sortMap[201] = "MS949";
        sortMap[202] = "MS950";
        sortMap[203] = "MS936";
        sortMap[204] = "MS874";
        sortMap[205] = "MS874";
        sortMap[206] = "MS874";
        sortMap[210] = "Cp1252";
        sortMap[211] = "Cp1252";
        sortMap[212] = "Cp1252";
        sortMap[213] = "Cp1252";
        sortMap[214] = "Cp1252";
        sortMap[215] = "Cp1252";
        sortMap[216] = "Cp1252";
        sortMap[217] = "Cp1252";        
    }
    
    /**
     * Retrieves the <code>CharsetInfo</code> instance asociated with the
     * specified server charset.
     *
     * @param name the server-specific character set name
     * @return the associated <code>Charset</code>
     */
    static Charset getCharset(String name) throws SQLException {
        name = name.toUpperCase();
        if (name.startsWith("ISO") && name.length() == 8) {
            name = "ISO-" + name.substring(3, 7) + "-" + name.substring(7);
        } else {
            String tmp = csAlias.get(name);
            if (tmp != null) {
                name = tmp;
            }
        }
        Charset cs = Charset.forName(name); 
        if (cs == null) {
            throw (SQLException)Logger.logException(new SQLException(
                    Messages.get("error.charset.nomapping", name), "2C000"));
        }

        return cs;
    }

    /**
     * Retrieves the <code>CharsetInfo</code> instance asociated with the
     * specified LCID.
     *
     * @param lcid the server LCID
     * @return the associated <code>Charset</code>
     */
    private static Charset getCharsetForLCID(final int lcid) throws SQLException {
        String name = lcidMap.get(new Integer(lcid));
        Charset cs = Charset.forName(name);
        if (cs == null) {
            throw (SQLException)Logger.logException(new SQLException(
                    Messages.get("error.charset.nomapping", "LCID_" + lcid), "2C000"));
        }
        return cs;
    }

    /**
     * Retrieves the <code>CharsetInfo</code> instance asociated with the
     * specified sort order.
     *
     * @param sortOrder the server sort order
     * @return the associated <code>CharsetInfo</code>
     */
    private static Charset getCharsetForSortOrder(final int sortOrder) {
        String name = sortMap[sortOrder];
        return Charset.forName(name);
    }

    /**
     * Retrieves the <code>CharsetInfo</code> instance asociated with the
     * specified collation.
     *
     * @param collation the server LCID
     * @return the associated <code>CharsetInfo</code>
     */
    static Charset getCharset(final byte[] collation)
            throws SQLException {
        Charset charset;

        if (collation[4] != 0) {
            // The charset is determined by the sort order
            charset = getCharsetForSortOrder(collation[4] & 0xFF);
        } else {
            // The charset is determined by the LCID
            charset = getCharsetForLCID(
                    (collation[2] & 0x0F) << 16
                    | (collation[1] & 0xFF) << 8
                    | (collation[0] & 0xFF));
        }

        if (charset == null) {
            throw new SQLException(Messages.get("error.charset.nocollation", 
                                                            Support.toHex(collation)));
        }
        return charset;
    }
}
