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
package javax.sql;

import java.util.EventObject;

/**
 * An <code>Event</code> object generated when an event occurs to a
 * <code>RowSet</code> object. A <code>RowSetEvent</code> object is generated
 * when a single row in a rowset is changed, the whole rowset is changed, or the
 * rowset cursor moves.
 * <p/>
 * When an event occurs on a <code>RowSet</code> object, one of the
 * <code>RowSetListener</code> methods will be sent to all registered listeners
 * to notify them of the event. An <code>Event</code> object is supplied to the
 * <code>RowSetListener</code> method so that the listener can use it to find
 * out which <code>RowSet</code> object is the source of the event.
 */
public class RowSetEvent extends EventObject {

    /**
     * Constructs a <code>RowSetEvent</code> object initialized with the given
     * <code>RowSet</code> object.
     *
     * @param source the <code>RowSet</code> object whose data has changed or
     *               whose cursor has moved
     */
    public RowSetEvent(RowSet source) {
        super(source);
    }
}
