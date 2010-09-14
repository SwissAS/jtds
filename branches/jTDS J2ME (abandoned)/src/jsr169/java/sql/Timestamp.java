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
 * A thin wrapper around <code>java.util.Date</code> that allows the JDBC API to
 * identify this as an SQL TIMESTAMP value. It adds the ability to hold the
 * SQL TIMESTAMP nanos value and provides formatting and parsing operations to
 * support the JDBC escape syntax for timestamp values.
 * <p/>
 * <b>Note:</b> This type is a composite of a  and a
 * separate nanoseconds value. Only integral seconds are stored in the
 * <code>java.util.Date</code> component. The fractional seconds - the nanos -
 * are separate. The  method will return only integral
 * seconds. If a time value that includes the fractional seconds is desired, you
 * must convert nanos to milliseconds (nanos/1000000) and add this to the
 * <code>getTime</code> value. The <code>Timestamp.equals(Object)</code> method
 * never returns true when passed a value of type <code>java.util.Date</code>
 * because the nanos component of a date is unknown. As a result, the
 * <code>Timestamp.equals(Object)</code> method is not symmetric with respect
 * to the <code>java.util.Date.equals(Object)</code> method. Also, the hashcode
 * method uses the underlying <code>java.util.Data</code> implementation and
 * therefore does not include nanos in its computation. Due to the differences
 * between the <code>Timestamp</code> class and the <code>java.util.Date</code>
 * class mentioned above, it is recommended that code not view Timestamp values
 * generically as an instance of java.util.Date. The inheritance relationship
 * between <code>Timestamp</code> and <code>java.util.Date</code> really denotes
 * implementation inheritance, and not type inheritance.
 */
public class Timestamp extends java.util.Date {

    private int nanos;

    /**
     * Constructs a <code>Timestamp</code> object using a milliseconds time
     * value. The integral seconds are stored in the underlying date value; the
     * fractional seconds are stored in the nanos field of the
     * <code>Timestamp</code> object.
     *
     * @param time milliseconds since January 1, 1970, 00:00:00 GMT. A negative
     *             number is the number of milliseconds before
     *             January 1, 1970, 00:00:00 GMT.
     */
    public Timestamp(long time) {
        super((time / 1000L) * 1000L);
        nanos = (int) (time % 1000L) * 0xf4240;
        if (nanos < 0) {
            super.setTime(super.getTime() - 1000L);
            nanos += 0x3b9aca00;
        }
    }

    /**
     * Converts a <code>String</code> object in JDBC timestamp escape format to
     * a <code>Timestamp</code> value.
     *
     * @param s timestamp in format yyyy-mm-dd hh:mm:ss.fffffffff
     * @return corresponding <code>Timestamp</code> value
     * @throws IllegalArgumentException if the given argument does not have the
     *         format yyyy-mm-dd hh:mm:ss.fffffffff
     */
    public static Timestamp valueOf(String s) {
        int nano = 0;
        String nanoString = null;
        String errMsg = "Timestamp must be in the form:  yyyy-mm-dd hh:mm:ss.nnnnnnnnn";
        if (s == null || s.length() > "yyyy-mm-dd hh:mm:ss.nnnnnnnnn".length()) {
            throw new IllegalArgumentException(errMsg);
        }
        int posDelimSp = s.indexOf(' ');
        String dateString;
        String timeString;
        if (posDelimSp > 0) {
            dateString = s.substring(0, posDelimSp);
            timeString = s.substring(posDelimSp + 1);
        } else {
            throw new IllegalArgumentException(errMsg);
        }
        if (dateString == null || dateString.length() > "yyyy-mm-dd".length()) {
            throw new IllegalArgumentException(errMsg);
        }
        int posDelim1 = dateString.indexOf('-');
        int posDelim2 = dateString.lastIndexOf('-');
        int year;
        int month;
        int day;
        if (posDelim1 > 0 && posDelim2 != dateString.length() - 1 && posDelim2 - posDelim1 > 1) {
            year = Integer.parseInt(dateString.substring(0, posDelim1));
            month = Integer.parseInt(dateString.substring(posDelim1 + 1, posDelim2)) - 1;
            day = Integer.parseInt(dateString.substring(posDelim2 + 1));
        } else {
            throw new IllegalArgumentException(errMsg);
        }
        if (timeString == null) {
            throw new IllegalArgumentException(errMsg);
        }
        int posDelimPd = timeString.indexOf('.');
        if (posDelimPd > 0) {
            nanoString = timeString.substring(posDelimPd + 1);
            timeString = timeString.substring(0, posDelimPd);
        }
        if (timeString == null || timeString.length() > "hh:mm:ss".length()) {
            throw new IllegalArgumentException(errMsg);
        }
        posDelim1 = timeString.indexOf(':');
        posDelim2 = timeString.lastIndexOf(':');
        int hour;
        int minute;
        int second;
        if (posDelim1 > 0 && posDelim2 != s.length() - 1 && posDelim2 - posDelim1 > 1) {
            hour = Integer.parseInt(timeString.substring(0, posDelim1));
            minute = Integer.parseInt(timeString.substring(posDelim1 + 1, posDelim2));
            second = Integer.parseInt(timeString.substring(posDelim2 + 1));
        } else {
            throw new IllegalArgumentException(errMsg);
        }
        if (nanoString != null) {
            int nanoLen = nanoString.length();
            if (nanoLen < 9) {
                nanoString = nanoString + "000000000".substring(0, 9 - nanoLen);
            }
            nano = Integer.parseInt(nanoString);
        }
        Calendar cal = new GregorianCalendar();
        cal.clear();
        cal.set(year, month, day, hour, minute, second);
        Timestamp timestamp = new Timestamp(cal.getTime().getTime());
        timestamp.setNanos(nano);
        return timestamp;
    }

    /**
     * Formats a timestamp in JDBC timestamp escape format. NOTE: To specify a
     * timestamp format for the class <code>SimpleDateFormat</code>, use
     * "yyyy.MM.dd" rather than "yyyy-mm-dd". In the context of
     * <code>SimpleDateFormat</code>, "mm" indicates minutes rather than the
     * month. Note that <code>SimpleDateFormat</code> does not allw for the
     * nanoseconds components of a <code>Timestamp</code> object. For example:
     * <pre>
     *      Format Pattern                                Result
     *      --------------                                ------
     *  "yyyy.MM.dd G 'at' hh:mm:ss z"     -->  2002.07.10 AD at 15:08:56 PDT
     * </pre>
     *
     * @return a <code>String</code> object in yyyy-mm-dd hh:mm:ss.fffffffff
     *                                      format
     */
    public String toString() {
        Calendar cal = new GregorianCalendar();
        cal.setTime(this);
        int year = cal.get(1);
        int month = cal.get(2) + 1;
        int day = cal.get(5);
        int hour = cal.get(11);
        int minute = cal.get(12);
        int second = cal.get(13);
        String theYear = Integer.toString(year);
        String theMonth = month < 10 ? "0" + month : Integer.toString(month);
        String theDay = day < 10 ? "0" + day : Integer.toString(day);
        String theHour = hour < 10 ? "0" + hour : Integer.toString(hour);
        String theMinute = minute < 10 ? "0" + minute : Integer.toString(minute);
        String theSecond = second < 10 ? "0" + second : Integer.toString(second);
        String theNano = Integer.toString(nanos);
        if (nanos != 0) {
            int nanoLen = theNano.length();
            int i = 0;
            theNano = "000000000".substring(0, 9 - nanoLen) + theNano;
            for (char nanoArr[] = theNano.toCharArray(); i < nanoArr.length; i++) {
                if (nanoArr[nanoArr.length - i - 1] != '0') {
                    break;
                }
            }

            if (i > 0) {
                theNano = theNano.substring(0, 9 - i);
            }
        }
        return theYear + "-" + theMonth + "-" + theDay + " " + theHour + ":" + theMinute + ":"
                + theSecond
                + "."
                + theNano;
    }

    /**
     * Gets this <code>Timestamp</code> object's nanos value.
     *
     * @return this <code>Timestamp</code> object's fractional seconds component
     * @see #setNanos(int)
     */
    public int getNanos() {
        return nanos;
    }

    /**
     * Sets this <code>Timestamp</code> object's nanos field to the given value.
     *
     * @param n the new fractional seconds component
     * @throws java.lang.IllegalArgumentException if the given argument is
     *                                            greater than 999999999 or less
     *                                            than 0
     * @see #getNanos()
     */
    public void setNanos(int n) {
        if (n < 0 || n > 0x3b9ac9ff) {
            throw new IllegalArgumentException("Invalid nano value");
        } else {
            nanos = n;
            return;
        }
    }

    /**
     * Tests to see if this <code>Timestamp</code> object is equal to the given
     * <code>Timestamp</code> object.
     *
     * @param ts the <code>Timestamp</code> value to compare with
     * @return true if the given <code>Timestamp</code> object is equal to this
     *         <code>Timestamp</code> object; false otherwise
     */
    public boolean equals(Timestamp ts) {
        return super.equals(ts) && nanos == ts.nanos;
    }

    /**
     * Tests to see if this <code>Timestamp</code> object is equal to the given
     * object. This version of the method equals has been added to fix the
     * incorrect signature of <code>Timestamp.equals(Timestamp)</code> and to
     * preserve backward compatibility with existing class files. Note: This
     * method is not symmetric with respect to the <code>equals(Object)</code>
     * method in the base class.
     *
     * @param ts the <code>Object</code> value to compare with
     * @return true if the given <code>Object</code> instance is equal to this
     *         <code>Timestamp</code> object; false otherwise
     */
    public boolean equals(Object ts) {
        if (ts instanceof Timestamp) {
            return equals((Timestamp) ts);
        } else {
            return false;
        }
    }

    /**
     * Indicates whether this <code>Timestamp</code> object is earlier than the
     * given <code>Timestamp</code> object.
     *
     * @param ts the <code>Timestamp</code> value to compare with
     * @return true if this <code>Timestamp</code> object is earlier; false
     *         otherwise
     */
    public boolean before(Timestamp ts) {
        long lTime = getTime();
        long rTime = ts.getTime();
        if (lTime < rTime) {
            return true;
        }
        if (lTime > rTime) {
            return false;
        }
        return nanos < ts.nanos;
    }

    /**
     * Indicates whether this <code>Timestamp</code> object is later than the
     * given <code>Timestamp</code> object.
     *
     * @param ts the <code>Timestamp</code> value to compare with
     * @return true if this <code>Timestamp</code> object is later; false
     *         otherwise
     */
    public boolean after(Timestamp ts) {
        long lTime = getTime();
        long rTime = ts.getTime();
        if (lTime > rTime) {
            return true;
        }
        if (lTime < rTime) {
            return false;
        }
        return nanos > ts.nanos;
    }

    /**
     * Compares this <code>Timestamp</code> to another Object. If the Object is
     * a <code>Timestamp</code>, this function behaves like
     * <code>compareTo(Timestamp)</code>. Otherwise, it throws
     * <code>aClassCastException</code> (as <code>Timestamp</code> are comparable
     * only to other <code>Timestamps</code>)
     *
     * @param o the object to be compared
     * @return the value 0 if the argument is a <code>Timestamp</code> equal to
     *         this <code>Timestamp</code>; a value less than 0 if the argument
     *         is a <code>Timestamp</code> after this <code>Timestamp</code>;
     *         and a value greater than 0 if the argument is a
     *         <code>Timestamp</code> before this <code>Timestamp</code>.
     * @throws java.lang.ClassCastException if the argument is not a
     *                                      <code>Timestamp</code>.
     */
    public int compareTo(Object o) {
        return compareTo((Timestamp) o);
    }

    /**
     * Compares two <code>Timestamps</code> for ordering.
     *
     * @param ts the <code>Timestamp</code> to be compared.
     * @return the value 0 if the argument <code>Timestamp</code> is equal to
     *         this <code>Timestamp</code>; a value less than 0 if this
     *         <code>Timestamp</code> is before the <code>Date</code> argument;
     *         and a value greater than 0 if this <code>Timestamp</code> is after
     *         the <code>Timestamp</code> argument.
     */
    public int compareTo(Timestamp ts) {
        if (equals(ts)) {
            return 0;
        }
        return !before(ts) ? 1 : -1;
    }

    /**
     * Returns the number of milliseconds since January 1, 1970, 00:00:00 GMT
     * represented by this <code>Timestamp</code> object.
     *
     * @return the number of milliseconds since January 1, 1970, 00:00:00 GMT
     *         represented by this date.
     * @see #setTime(long)
     */
    public long getTime() {
        return super.getTime() + (long) (nanos / 0xf4240);
    }

    /**
     * Sets this <code>Timestamp</code> object to represent a point in time that
     * is time milliseconds after January 1, 1970 00:00:00 GMT.
     *
     * @param time the number of milliseconds.
     * @see #getTime()
     * @see #Timestamp(long time)
     */
    public void setTime(long time) {
        super.setTime((time / 1000L) * 1000L);
        nanos = (int) (time % 1000L) * 0xf4240;
        if (nanos < 0) {
            super.setTime(super.getTime() - 1000L);
            nanos += 0x3b9aca00;
        }
    }
}
