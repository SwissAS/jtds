// jTDS JDBC Driver for Microsoft SQL Server and Sybase
// Copyright (C) 2005 The jTDS Project
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
package java.sql;

/**
 * The class that defines the constants that are used to identify generic
 * SQL types, called JDBC types. The actual type constant values are equivalent
 * to those in XOPEN.
 * <p/>
 * This class is never instantiated.
 */
public class Types {

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type BIT.
     */
    public static final int BIT = -7;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type TINYINT.
     */
    public static final int TINYINT = -6;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type SMALLINT.
     */
    public static final int SMALLINT = 5;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type INTEGER.
     */
    public static final int INTEGER = 4;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type BIGINT.
     */
    public static final int BIGINT = -5;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type FLOAT.
     */
    public static final int FLOAT = 6;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type REAL.
     */
    public static final int REAL = 7;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type DOUBLE.
     */
    public static final int DOUBLE = 8;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type NUMERIC.
     */
    public static final int NUMERIC = 2;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type DECIMAL.
     */
    public static final int DECIMAL = 3;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type CHAR.
     */
    public static final int CHAR = 1;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type VARCHAR.
     */
    public static final int VARCHAR = 12;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type LONGVARCHAR.
     */
    public static final int LONGVARCHAR = -1;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type DATE.
     */
    public static final int DATE = 91;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type TIME.
     */
    public static final int TIME = 92;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type TIMESTAMP.
     */
    public static final int TIMESTAMP = 93;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type BINARY.
     */
    public static final int BINARY = -2;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type VARBINARY.
     */
    public static final int VARBINARY = -3;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type LONGVARBINARY.
     */
    public static final int LONGVARBINARY = -4;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type NULL.
     */
    public static final int NULL = 0;

    /**
     * The constant in the Java programming language that indicates that the SQL
     * type is database-specific and gets mapped to a Java object that can be
     * accessed via the methods <code>getObject</code> and
     * <code>setObject</code>.
     */
    public static final int OTHER = 1111;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type JAVA_OBJECT.
     */
    public static final int JAVA_OBJECT = 2000;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type DISTINCT.
     */
    public static final int DISTINCT = 2001;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type STRUCT.
     */
    public static final int STRUCT = 2002;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type ARRAY.
     */
    public static final int ARRAY = 2003;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type BLOB.
     */
    public static final int BLOB = 2004;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type CLOB.
     */
    public static final int CLOB = 2005;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type REF.
     */
    public static final int REF = 2006;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type BOOLEAN.
     */
    public static final int BOOLEAN = 16;

    /**
     * The constant in the Java programming language, sometimes referred to as
     * a type code, that identifies the generic SQL type DATALINK.
     */
    public static final int DATALINK = 70;

    /**
     * Pure static class.
     */
    private Types() {
    }
}
