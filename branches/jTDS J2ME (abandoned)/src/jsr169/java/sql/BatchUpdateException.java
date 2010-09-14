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

import java.io.Serializable;

/**
 * An exception thrown when an error occurs during a batch update operation.
 * In addition to the information provided by {@link SQLException}, a
 * <code>BatchUpdateException</code> provides the update counts for all
 * commands that were executed successfully during the batch update, that is,
 * all commands that were executed before the error occurred. The order of
 * elements in an array of update counts corresponds to the order in which
 * commands were added to the batch.
 * <p/>
 * After a command in a batch update fails to execute properly and a
 * <code>BatchUpdateException</code> is thrown, the driver may or may not
 * continue to process the remaining commands in the batch. If the driver
 * continues processing after a failure, the array returned by the method
 * <code>BatchUpdateException.getUpdateCounts</code> will have an element for
 * every command in the batch rather than only elements for the commands that
 * executed successfully before the error. In the case where the driver
 * continues processing commands, the array element for any command that failed
 * is <code>Statement.EXECUTE_FAILED</code>.
 */
public class BatchUpdateException extends SQLException
        implements Serializable {
    /**
     * An array of <code>int</code>, with each element indicating the update
     * count for a SQL command that executed successfully before the exception
     * was thrown.
     */
    private int[] updateCounts;

    /**
     * Constructs a fully-specified <code>BatchUpdateException</code> object,
     * initializing it with the given values.
     *
     * @param reason       a description of the error
     * @param SQLState     an X/OPEN code identifying the error
     * @param vendorCode   an exception code used by a particular database
     *                     vendor
     * @param updateCounts an array of <code>int</code>, with each element
     *                     indicating the update count for a SQL command that
     *                     executed successfully before the exception was
     *                     thrown
     */
    public BatchUpdateException(String reason, String SQLState, int vendorCode,
                                int[] updateCounts) {
        super(reason, SQLState, vendorCode);
        this.updateCounts = updateCounts;
    }

    /**
     * Constructs a <code>BatchUpdateException</code> initialized with the
     * given arguments (<code>reason</code>, <code>SQLState</code>, and
     * <code>updateCounts</code>) and 0 for the vendor code.
     *
     * @param reason       a description of the error
     * @param SQLState     an X/OPEN code identifying the error
     * @param updateCounts an array of <code>int</code>, with each element
     *                     indicating the update count for a SQL command that
     *                     executed successfully before the exception was
     *                     thrown
     */
    public BatchUpdateException(String reason, String SQLState,
                                int[] updateCounts) {
        this(reason, SQLState, 0, updateCounts);
    }

    /**
     * Constructs a <code>BatchUpdateException</code> initialized with
     * <code>reason</code>, <code>updateCounts</code> and <code>null</code> for
     * the <code>SQLState</code> and <code>0</code> for the
     * <code>vendorCode</code>.
     *
     * @param reason       a description of the error
     * @param updateCounts an array of <code>int</code>, with each element
     *                     indicating the update count for a SQL command that
     *                     executed successfully before the exception was
     *                     thrown
     */
    public BatchUpdateException(String reason, int[] updateCounts) {
        this(reason, null, 0, updateCounts);
    }

    /**
     * Constructs a <code>BatchUpdateException</code> initialized to
     * <code>null</code> for the <code>reason</code> and <code>SQLState</code>
     * and <code>0</code> for the <code>vendorCode</code>.
     *
     * @param updateCounts an array of <code>int</code>, with each element
     *                     indicating the update count for a SQL command that
     *                     executed successfully before the exception was
     *                     thrown
     */
    public BatchUpdateException(int[] updateCounts) {
        this(null, null, 0, updateCounts);
    }

    /**
     * Constructs a <code>BatchUpdateException</code> object with the
     * <code>reason</code>, <code>SQLState</code>, and update count initialized
     * to <code>null</code> and the vendor code initialized to <code>0</code>.
     */
    public BatchUpdateException() {
        this(null, null, 0, null);
    }

    /**
     * Retrieves the update count for each update statement in the batch
     * update that executed successfully before this exception occurred. A
     * driver that implements batch updates may or may not continue to process
     * the remaining commands in a batch when one of the commands fails to
     * execute properly. If the driver continues processing commands, the array
     * returned by this method will have as many elements as there are commands
     * in the batch; otherwise, it will contain an update count for each
     * command that executed successfully before the
     * <code>BatchUpdateException</code> was thrown.
     * <p/>
     * The possible return values for this method were modified for the Java 2
     * SDK, Standard Edition, version 1.3.  This was done to accommodate the
     * new option of continuing to process commands in a batch update after a
     * <code>BatchUpdateException</code> object has been thrown.
     *
     * @return an array of <code>int</code> containing the update counts for
     *         the updates that were executed successfully before this error
     *         occurred. Or, if the driver continues to process commands after
     *         an error, one of the following for every command in the batch:
     *         <ol>
     *           <li>an update count
     *           <li><code>Statement.SUCCESS_NO_INFO</code> to indicate that
     *             the command executed successfully but the number of rows
     *             affected is unknown
     *           <li><code>Statement.EXECUTE_FAILED</code> to indicate that the
     *             command failed to execute successfully
     *         </ol>
     */
    public int[] getUpdateCounts() {
        return updateCounts;
    }
}
