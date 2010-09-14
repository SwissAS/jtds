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
 * A thin wrapper around a millisecond value that allows JDBC to identify this
 * as an SQL DATE value. A milliseconds value represents the number of
 * milliseconds that have passed since January 1, 1970 00:00:00.000 GMT.
 * <p/>
 * To conform with the definition of SQL DATE, the millisecond values wrapped by
 * a java.sql.Date instance must be 'normalized' by setting the hours, minutes,
 * seconds, and milliseconds to zero in the particular time zone with which the
 * instance is associated.
 */
public class Date extends java.util.Date {
    /**
     * Constructs a Date object using the given milliseconds time value. If the
     * given milliseconds value contains time information, the driver will set
     * the time components to the time in the default time zone (the time zone
     * of the Java virtual machine running the application) that corresponds to
     * zero GMT.
     *
     * @param date milliseconds since January 1, 1970, 00:00:00 GMT not to
     *             exceed the milliseconds representation for the year 8099. A
     *             negative number indicates the number of milliseconds before
     *             January 1, 1970, 00:00:00 GMT
     */
    public Date(long date) {
        super(date);
    }

    /**
     * Sets an existing Date object using the given milliseconds time value. If
     * the given milliseconds value contains time information, the driver will
     * set the time components to the time in the default time zone (the time
     * zone of the Java virtual machine running the application) that
     * corresponds to zero GMT.
     *
     * @param date milliseconds since January 1, 1970, 00:00:00 GMT not to
     *             exceed the milliseconds representation for the year 8099.
     *             A negative number indicates the number of milliseconds before
     *             January 1, 1970, 00:00:00 GMT.
     */
    public void setTime(long date) {
        super.setTime(date);
    }

    /**
     * Converts a string in JDBC date escape format to a <code>Date</code> value.
     *
     * @param s date in format "yyyy-mm-dd"
     * @return a <code>java.sql.Date</code> object representing the given date
     */
    public static Date valueOf(String s) {
        String errMsg = "Date must be of the form:  yyyy-mm-dd";
        if (s == null) {
            throw new IllegalArgumentException(errMsg);
        }
        int posDelim1 = s.indexOf('-');
        int posDelim2 = s.lastIndexOf('-');
        int dashDelim = s.lastIndexOf("--");
        if (dashDelim == posDelim2 - 1) {
            posDelim2 = dashDelim;
        }
        if (posDelim1 > 0 && posDelim2 != s.length() - 1 && posDelim2 - posDelim1 > 1) {
            int year;
            int month;
            int day;
            try {
                year = Integer.parseInt(s.substring(0, posDelim1));
                month = Integer.parseInt(s.substring(posDelim1 + 1, posDelim2)) - 1;
                day = Integer.parseInt(s.substring(posDelim2 + 1));
            } catch (NumberFormatException _ex) {
                throw new IllegalArgumentException(errMsg);
            }
            Calendar cal = new GregorianCalendar();
            cal.clear();
            cal.set(year, month, day);
            return new Date(cal.getTime().getTime());
        } else {
            throw new IllegalArgumentException(errMsg);
        }
    }

    /**
     * Formats a date in the date escape format yyyy-mm-dd.
     * <p/>
     * <b>NOTE:</b> To specify a date format for the class
     * <code>SimpleDateFormat</code>, use "yyyy.MM.dd" rather than "yyyy-mm-dd".
     * In the context of <code>SimpleDateFormat</code>, "mm" indicates minutes
     * rather than the month. For example:
     * <pre>
     * Format Pattern                         Result
     * --------------                         -------
     * "yyyy.MM.dd G 'at' hh:mm:ss z"    ->>  1996.07.10 AD at 15:08:56 PDT
     * </pre>
     *
     * @return a String in yyyy-mm-dd format
     */
    public String toString() {
        Calendar cal = new GregorianCalendar();
        cal.setTime(this);
        int year = cal.get(1);
        int month = cal.get(2) + 1;
        int day = cal.get(5);
        String theYear = Integer.toString(year);
        String theMonth = month < 10 ? "0" + month : Integer.toString(month);
        String theDay = day < 10 ? "0" + day : Integer.toString(day);
        return theYear + "-" + theMonth + "-" + theDay;
    }
}
