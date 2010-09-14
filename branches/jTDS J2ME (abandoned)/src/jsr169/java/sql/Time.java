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

import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * A thin wrapper around the <code>java.util.Date class</code> that allows the
 * JDBC API to identify this as an SQL TIME value. The <code>Time</code> class
 * adds formatting and parsing operations to support the JDBC escape syntax for
 * time values.
 * <p/>
 * The date components should be set to the "zero epoch" value of
 * January 1, 1970 and should not be accessed.
 */
public class Time extends java.util.Date {

    /**
     * Constructs a <code>Time</code> object using a milliseconds time value.
     *
     * @param time milliseconds since January 1, 1970, 00:00:00 GMT; a negative
     *             number is milliseconds before January 1, 1970, 00:00:00 GMT
     */
    public Time(long time) {
        super(time);
    }

    /**
     * Sets a <code>Time</code> object using a milliseconds time value.
     *
     * @param time milliseconds since January 1, 1970, 00:00:00 GMT; a negative
     *             number is milliseconds before January 1, 1970, 00:00:00 GMT
     */
    public void setTime(long time) {
        super.setTime(time);
    }

    /**
     * Converts a string in JDBC time escape format to a <code>Time</code> value.
     *
     * @param s time in format "hh:mm:ss"
     * @return a corresponding <code>Time</code> object
     */
    public static Time valueOf(String s) {
        String errMsg = "Time must be of the form:  hh:mm:ss";
        if (s == null) {
            throw new IllegalArgumentException(errMsg);
        }
        int posDelim1 = s.indexOf(':');
        int posDelim2 = s.lastIndexOf(':');
        if (posDelim1 > 0 && posDelim2 != s.length() - 1 && posDelim2 - posDelim1 > 1) {
            int hour;
            int minute;
            int second;
            try {
                hour = Integer.parseInt(s.substring(0, posDelim1));
                minute = Integer.parseInt(s.substring(posDelim1 + 1, posDelim2));
                second = Integer.parseInt(s.substring(posDelim2 + 1));
            } catch (NumberFormatException _ex) {
                throw new IllegalArgumentException(errMsg);
            }
            Calendar cal = new GregorianCalendar();
            cal.clear();
            cal.set(1970, 0, 1, hour, minute, second);
            return new Time(cal.getTime().getTime());
        } else {
            throw new IllegalArgumentException(errMsg);
        }
    }

    /**
     * Formats a time in JDBC time escape format.
     *
     * @return a String in hh:mm:ss format
     */
    public String toString() {
        Calendar cal = new GregorianCalendar();
        cal.setTime(this);
        int hour = cal.get(11);
        int minute = cal.get(12);
        int second = cal.get(13);
        String theHour = hour < 10 ? "0" + hour : Integer.toString(hour);
        String theMinute = minute < 10 ? "0" + minute : Integer.toString(minute);
        String theSecond = second < 10 ? "0" + second : Integer.toString(second);
        return theHour + ":" + theMinute + ":" + theSecond;
    }
}
