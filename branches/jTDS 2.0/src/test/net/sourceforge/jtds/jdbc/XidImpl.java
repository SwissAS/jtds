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

import java.util.Arrays;

import javax.transaction.xa.XAException;
import javax.transaction.xa.Xid;

import net.sourceforge.jtds.jdbc.Messages;
import net.sourceforge.jtds.jdbc.Support;
import net.sourceforge.jtds.util.Logger;

/**
 * jTDS implementation of the <code>Xid</code> interface.
 *
 * @version $Id: XidImpl.java,v 1.1 2007-09-10 19:19:35 bheineman Exp $
 */
class XidImpl implements Xid {
    /** The size of an XID in bytes. */
    public static final int XID_SIZE = 140;

    /** The global transaction ID. */
    private final byte gtran[];
    /** The branch qualifier ID. */
    private final byte bqual[];
    /** The format ID. */
    private final int fmtId;
    /** Precalculated hash value. */
    private int hash;
    /** True if hash has been calculated. */
    private boolean isHashed; 

    /**
     * Construct an XID using an offset into a byte buffer.
     *
     * @param buf the byte buffer
     * @param pos the offset
     */
    XidImpl(byte[] buf, int pos) {
        fmtId = (buf[pos] & 0xFF) |
                ((buf[pos+1] & 0xFF) << 8) |
                ((buf[pos+2] & 0xFF) << 16) |
                ((buf[pos+3] & 0xFF) << 24);
        int t = buf[pos+4];
        int b = buf[pos+8];
        gtran = new byte[t];
        bqual = new byte[b];
        System.arraycopy(buf, 12+pos, gtran, 0, t);
        System.arraycopy(buf, 12+t+pos, bqual, 0, b);
    }

    /**
     * Construct an XID using two byte arrays.
     *
     * @param global the global transaction id
     * @param branch the transaction branch
     */
    XidImpl(byte[] global, byte[] branch) {
        fmtId = 0;
        gtran = global;
        bqual = branch;
    }

    /**
     * Construct an XID as a clone of another XID.
     */
    XidImpl(Xid xid) throws XAException {
        if (xid == null) {
            XAException e = new XAException(Messages.get("error.xasupport.nullxid"));
            e.errorCode = XAException.XAER_RMFAIL;
            Logger.logException(e);
            throw e;
        }
        fmtId = xid.getFormatId();
        gtran = new byte[xid.getGlobalTransactionId().length];
        System.arraycopy(xid.getGlobalTransactionId(), 0, gtran, 0, gtran.length);
        bqual = new byte[xid.getBranchQualifier().length];
        System.arraycopy(xid.getBranchQualifier(), 0, bqual, 0, bqual.length);
    }

    /**
     * Get the hash code for this object.
     *
     * @return the hash value of this object as a <code>int</code>
     */
    public int hashCode() {
        if (!isHashed) {
            String x = Integer.toString(fmtId)+ new String(gtran) + new String(bqual);
            hash = x.hashCode();
            isHashed = true;
        }
        return hash;
    }

    /**
     * Test for equality.
     *
     * @param obj the object to test for equality with this
     * @return <code>boolean</code> true if the parameter equals this
     */
    public boolean equals(Object obj) {
        if (obj == this)
            return true;

        if (obj instanceof XidImpl) {
            XidImpl xobj = (XidImpl)obj;

            if (gtran.length + bqual.length == xobj.gtran.length + xobj.bqual.length
                    && fmtId == xobj.fmtId 
                    && Arrays.equals(gtran, xobj.gtran)
                    && Arrays.equals(bqual, xobj.bqual)) {
                return true;
            }
        }
        return false;
    }

    //
    // ------------------- javax.transaction.xa.Xid interface methods -------------------
    //

    public int getFormatId() {
        return fmtId;
    }

    public byte[] getBranchQualifier() {
        return bqual;
    }

    public byte[] getGlobalTransactionId() {
        return gtran;
    }

    public String toString() {
        StringBuffer txt = new StringBuffer(256);
        txt.append("XID[Format=").append(fmtId).append(", Global=0x");
        txt.append(Support.toHex(gtran)).append(", Branch=0x");
        txt.append(Support.toHex(bqual)).append(']');
        return txt.toString();
    }
}
