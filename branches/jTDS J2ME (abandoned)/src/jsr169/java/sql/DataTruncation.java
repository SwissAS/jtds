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
 * An exception that reports a <code>DataTruncation</code> warning (on reads) or
 * throws a <code>DataTruncation</code> exception (on writes) when JDBC
 * unexpectedly truncates a data value.
 * <p/>
 * The SQLState for a <code>DataTruncation</code> is <code>01004</code>.
 */
public class DataTruncation extends SQLWarning {
    /** The index of the column or parameter that was truncated. */
    private int index;
    /** whether the value truncated was a parameter or a column. */
    private boolean parameter;
    /** Whether or not the value was truncated on a read. */
    private boolean read;
    /** The original size of the data in bytes. */
    private int dataSize;
    /** The size after truncation in bytes. */
    private int transferSize;

    /**
     * Creates a <code>DataTruncation</code> object with the SQLState
     * initialized to 01004, the reason set to "Data truncation", the vendorCode
     * set to the <code>SQLException</code> default, and the other fields set to
     * the given values.
     *
     * @param index        the index of the parameter or column value
     * @param parameter    <code>true</code> if a parameter value was truncated
     * @param read         <code>true</code> if a read was truncated
     * @param dataSize     the original size of the data
     * @param transferSize the size after truncation
     */
    public DataTruncation(int index, boolean parameter, boolean read,
                          int dataSize, int transferSize) {
        super("Data truncation", "01004");

        this.index = index;
        this.parameter = parameter;
        this.read = read;
        this.dataSize = dataSize;
        this.transferSize = transferSize;
    }

    /**
     * Retrieves the index of the column or parameter that was truncated.
     * <p/>
     * This may be <code>-1</code> if the column or parameter index is unknown,
     * in which case the <code>parameter</code> and <code>read</code> fields
     * should be ignored.
     *
     * @return the index of the truncated paramter or column value
     */
    public int getIndex() {
        return index;
    }

    /**
     * Indicates whether the value truncated was a parameter value or a column
     * value.
     *
     * @return <code>true</code> if the value truncated was a parameter;
     *         <code>false</code> if it was a column value
     */
    public boolean getParameter() {
        return parameter;
    }

    /**
     * Indicates whether or not the value was truncated on a read.
     *
     * @return <code>true</code> if the value was truncated when read from the
     *         database; <code>false</code> if the data was truncated on a write
     */
    public boolean getRead() {
        return read;
    }

    /**
     * Gets the number of bytes of data that should have been transferred. This
     * number may be approximate if data conversions were being performed. The
     * value may be <code>-1</code> if the size is unknown.
     *
     * @return the number of bytes of data that should have been transferred
     */
    public int getDataSize() {
        return dataSize;
    }

    /**
     * Gets the number of bytes of data actually transferred. The value may be
     * <code>-1</code> if the size is unknown.
     *
     * @return the number of bytes of data actually transferred
     */
    public int getTransferSize() {
        return transferSize;
    }
}
