//                                                                            
// Copyright 1998 CDS Networks, Inc., Medford Oregon                          
//                                                                            
// All rights reserved.                                                       
//                                                                            
// Redistribution and use in source and binary forms, with or without         
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright          
//    notice, this list of conditions and the following disclaimer.           
// 2. Redistributions in binary form must reproduce the above copyright       
//    notice, this list of conditions and the following disclaimer in the     
//    documentation and/or other materials provided with the distribution.    
// 3. All advertising materials mentioning features or use of this software   
//    must display the following acknowledgement:                             
//      This product includes software developed by CDS Networks, Inc.        
// 4. The name of CDS Networks, Inc.  may not be used to endorse or promote   
//    products derived from this software without specific prior              
//    written permission.                                                     
//                                                                            
// THIS SOFTWARE IS PROVIDED BY CDS NETWORKS, INC. ``AS IS'' AND              
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE      
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
// ARE DISCLAIMED.  IN NO EVENT SHALL CDS NETWORKS, INC. BE LIABLE            
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS    
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)      
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY  
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF     
// SUCH DAMAGE.                                                               
//                                                                            

package com.internetcds.jdbc.tds;

/**   
 *   This class provides support for canceling queries. 
 *  <p>
 *   Basically all threads can be divided into two groups, workers and
 *   cancelers.  The canceler can cancel at anytime, even when there is no
 *   outstanding query to cancel.  A worker can be in one of 4 states-
 *  <p>
 *     1) Not doing anything DB related.<br>
 *     2) currently sending a request to the database. (Note-  any time
 *        a request is sent to the DB the DB will send a response.  This
 *        means a thread in state 2 must go to state 3.)<br>
 *     3) waiting for a response from DB<br>
 *     4) reading the response from DB<br>
 *  <p>
 *   I can easily make it so that only one thread at a time can be in state
 *   2, 3, or 4.
 *  <p>
 *   The way that a cancel works in TDS is you send a cancel packet to
 *   server.  The server will then stop whatever it might be doing and
 *   reply with END_OF_DATA packet with the cancel flag set.  (It sends
 *   this packet even if it wasn't doing anything.)  I will call this
 *   packet a CANCEL_ACK packet
 *  <p>
 *   All that I really need is to do is make sure that I try to read as
 *   many CANCEL_ACKs as I request and the I make sure that some thread is
 *   out there ready to read any CANCEL_ACKs that i request.
 *  <p>
 *   Clearly if all my worker threads are in state 1 then the cancel
 *   request could be just a nop.
 *  <p>
 *   If I have some worker thread in state 2, 3, or 4 I think I will be fine
 *   if I just make sure that the thread reads until the CANCEL_ACK packet.
 *  <p>
 *   I think I will just have a control object that has one boolean,
 *   readInProgress and two integers, cancelsRequested and
 *   cancelsProcessed.
 *  <p>
 *  <p>
 *   The doCancel() method will-
 *     a) lock the object
 *     b) if there is no read in progress it will unlock and return.
 *     c) otherwise it will send the CANCEL packet,
 *     d) increment the cancelsRequested
 *     e) unlock object and wait until notified that the 
 *        cancel was ack'd
 *  <p>
 *   Whenever the worker thread wants to read a response from the DB it
 *   must-
 *     a) lock the control object,<b>
 *     b) set the queryOutstanding flag<b>
 *     c) unlock the control object<b>
 *     d) call the Tds.processSubPacket() method.<b>
 *     e) lock the control object<b>
 *     f) If the packet was a cancel ack it will increment
 *        cancelsProcessed <b>
 *     g) notify any threads that are waiting for cancel acknowledgment<b>
 *     h) unlock the control object.<b>
 * 
 * @version  $Id: CancelController.java,v 1.2 2001-08-31 12:47:20 curthagenlocher Exp $
 @ @author Craig Spannring
 */
public class CancelController 
{
   public static final String cvsVersion = "$Id: CancelController.java,v 1.2 2001-08-31 12:47:20 curthagenlocher Exp $";


   boolean    awaitingData     = false;
   int        cancelsRequested = 0;
   int        cancelsProcessed = 0;
   
   public synchronized void setQueryInProgressFlag()
   {
      awaitingData = true;
   }

   private synchronized void clearQueryInProgressFlag()
   {
      awaitingData = false;
   }

   public synchronized void finishQuery(
      boolean wasCanceled,
      boolean moreResults)
   {
      // XXX Do we want to clear the query in progress flag if 
      // there are still more results for multi result set query?
      // Whatever mechanism is used to handle outstanding query 
      // requires knowing if there is any thread out there that could
      // still process the query acknowledgment.  Prematurely clearing
      // could cause data to be thrown out before the thread expecting
      // the data gets a chance to process it.  That could cause the
      // thread to read some other threads query.
      //
      // Is it good enough to just look at the MORERESULTS bit in the
      // TDS_END* packet and not clear the flag if we have more
      // results?
      if (! moreResults)
      {
         clearQueryInProgressFlag();
      }

      if (wasCanceled)
      {
         handleCancelAck();
      }

      // XXX Should we see if there are any more cancels pending and
      // try to read the cancel acknowledgments?
   }


   public synchronized void doCancel(TdsComm comm)
      throws java.io.IOException
   {
      if (awaitingData)
      {
         comm.startPacket(TdsComm.CANCEL);
         comm.sendPacket();
         cancelsRequested++;


         while(cancelsRequested > cancelsProcessed)
         {
            try
            {
               wait();
               // XXX If there are cancels pending but nobody is is
               // awaiting data on this connection, should we go out
               // and try to get the CANCELACK packet?
            }
            catch(java.lang.InterruptedException e)
            {
               // nop
            }
         }
      }
      else
      {
         // if we aren't waiting for anything from 
         // the server then we have nothing to cancel

         // nop
      }
   }



   private synchronized void handleCancelAck()
   {
      cancelsProcessed++;
      notify(); 
   }
}
