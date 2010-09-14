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

import java.util.EventListener;

/**
 * An interface that must be implemented by a component that wants to be
 * notified when a significant event happens in the life of a
 * <code>RowSet</code> object. A component becomes a listener by being
 * registered with a <code>RowSet</code> object via the method
 * <code>RowSet.addRowSetListener</code>. How a registered component implements
 * this interface determines what it does when it is notified of an event.
 */
public interface RowSetListener extends EventListener {

    /**
     * Notifies registered listeners that a <code>RowSet</code> object in the
     * given <code>RowSetEvent</code> object has changed its entire contents.
     * <p/>
     * The source of the event can be retrieved with the method
     * <code>event.getSource</code>.
     *
     * @param event a <code>RowSetEvent</code> object that contains the
     *              <code>RowSet</code> object that is the source of the event
     */
    void rowSetChanged(RowSetEvent event);

    /**
     * Notifies registered listeners that a <code>RowSet</code> object has had a
     * change in one of its rows.
     * <p/>
     * The source of the event can be retrieved with the method
     * <code>event.getSource</code>.
     *
     * @param event a <code>RowSetEvent</code> object that contains the
     *              <code>RowSet</code> object that is the source of the event
     */
    void rowChanged(RowSetEvent event);

    /**
     * Notifies registered listeners that a <code>RowSet</code> object's cursor
     * has moved.
     * <p/>
     * The source of the event can be retrieved with the method
     * <code>event.getSource</code>.
     *
     * @param event a <code>RowSetEvent</code> object that contains the
     *              <code>RowSet</code> object that is the source of the event
     */
    void cursorMoved(RowSetEvent event);
}
