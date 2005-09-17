//jTDS JDBC Driver for Microsoft SQL Server and Sybase
//Copyright (C) 2004 The jTDS Project
//
//This library is free software; you can redistribute it and/or
//modify it under the terms of the GNU Lesser General Public
//License as published by the Free Software Foundation; either
//version 2.1 of the License, or (at your option) any later version.
//
//This library is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//Lesser General Public License for more details.
//
//You should have received a copy of the GNU Lesser General Public
//License along with this library; if not, write to the Free Software
//Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
package net.sourceforge.jtds.jdbc;

/**
 * Simple semaphore class used to serialize access requests over the network
 * connection.
 * <p/>
 * Based on the code originally written by Doug Lea. Once JDK 1.5 is the
 * standard this class can be replaced by the
 * <code>java.util.concurrent.Sempahore</code> class.
 *
 * @author  Mike Hutchinson
 * @version $Id: Semaphore.java,v 1.1.4.1 2005-09-17 10:58:59 alin_sinpalean Exp $
 */
public class Semaphore {
    /**
     * Current number of available permits.
     */
    protected long permits;

    /**
     * Create a Semaphore with the given initial number of permits. Using a
     * seed of one makes the semaphore act as a mutual exclusion lock. Negative
     * seeds are also allowed, in which case no acquires will proceed until the
     * number of releases has pushed the number of permits past 0.
     */
    public Semaphore(long initialPermits) {
        permits = initialPermits;
    }

    /**
     * Wait until a permit is available, and take one.
     */
    public void acquire() throws InterruptedException {
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }

        synchronized (this) {
            try {
                while (permits <= 0) {
                    wait();
                }
                --permits;
            } catch (InterruptedException ex) {
                notify();
                throw ex;
            }
        }
    }

    /**
     * Release a permit.
     */
    public synchronized void release() {
        ++permits;
        notify();
    }
}
