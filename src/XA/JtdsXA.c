/* 
 * jTDS JDBC Driver for Microsoft SQL Server and Sybase
 * Copyright (C) 2004 The jTDS Project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * --- How to compile this code.
 *
 * 1. You will need a Microsoft compatible compiler such as Visual C++ 6.
 * 2. You will need a copy of the Microsoft Platform SDK to obtain the 
 *    required header files and libraries.
 * 3. The code must be linked with xolehlp.lib, xaswitch.lib and opends60.lib.
 */

/*
 * --- How to install this code.
 * 
 * 1. Copy the JtdsXA.dll file into the SQL Server binary directory
 *    e.g. C:\Program Files\Microsoft SQL Server\MSSQL\Binn.
 * 2. Log on to the SQL Server as administrator and execute the following 
 *    statements:
 *    sp_addextendedproc 'xp_jtdsxa', 'jtdsXA.dll'
 *    go
 *    grant execute on xp_jtdsxa to public
 *    go
 *
 * The DLL can be unloaded without restarting the SQL Server by executing
 * the following command:
 *    dbcc JtdsXA(free)
 */

/*
 * --- Principle of operation.
 *
 * First a caveat. The Microsoft documentation in this area is very poorly 
 * organised and incomplete. This code is the result of a lot of guesswork 
 * and experimentation. By their very nature distributed transactions and 
 * supporting software components are very difficult to test completely.
 * 
 * Please DO NOT use this code in any business critical application until 
 * you have satisfied yourself that it works correctly. You have been warned!
 * 
 * The Microsoft Distributed Transaction Coordinator (DTC) can act as an XA 
 * compatible resource manager proxy for SQL Server as it implements the 
 * required XA Switch routines such as xa_start, xa_end etc. The XA 
 * transactions are internally mapped to Microsoft's proprietary transaction 
 * protocol.
 *
 * The DTC requires that each transaction runs on its own Windows thread of 
 * execution and whilst that is easy to achieve in an external server process, 
 * it is more problematical in an SQL Server extended procedure DLL. This is 
 * because SQL Server will call the extended procedure on it's own thread but 
 * this thread will not necessarily have a one to one correspondence with the 
 * external JDBC connection. Therefore a more sophisticated solution is 
 * required to achieve the correct association in the DTC between a Windows 
 * thread and the XA transaction.
 * 
 * In this implementation a pool of worker threads is used to manage each 
 * active XA transaction from start through to prepare, commit or rollback. 
 * This is a reasonably complex solution and hopefully there is someone out 
 * there who knows of a better way to achieve the same result.
 * 
 * There is a further consideration which, is the need to prevent threads 
 * being orphaned by their associated JDBC connection failing before it can
 * execute a prepare commit or rollback. The approach taken here is to allow 
 * worker threads to timeout and be reused after a period of time. 
 * The transaction timeout value can be set from the driver by calling the 
 * setTransactionTimeout() method on the XAResource. 
 * By default the timeout is set to 10 minutes in the jTDS driver.
 * This approach should ensure that if connections crash the worker
 * threads can still be reused and transactions will not be left hanging.
 * 
 * The final piece of the puzzle is that, having allocated a MTS transaction 
 * to the external XA transaction, we need a way of telling the SQL server to 
 * enlist on this transaction. This is achieved by exporting an MTS transaction
 * cookie, sending it to the JDBC driver and then passing it back once more to 
 * the SQL Server in a special TDS packet. This is the equivalent of the ODBC 
 * SQLSetConnectOption  SQL_COPT_SS_ENLIST_IN_DTC method.
 *
 * Some final comments on this XA implementation are in order.
 *
 * Starting from SQL Server 7, Microsoft introduced the User Mode Scheduler (UMS) 
 * to SQL Server. This component attempts to keep thread scheduling out of the 
 * kernel to boost performance and make SQL server more scalable. This is largely 
 * achieved by using cooperative multi tasking on a limited number of threads 
 * rather than allowing the kernel to pre-emptively multi task. 
 * 
 * As Microsoft cannot rely on an extended procedure cooperatively multitasking, 
 * the UMS has to allocate a normal thread to the session for the purposes of 
 * executing the extended procedure. 
 * This has the unfortunate result of disrupting the UMS's ability to manage 
 * scheduling and leads to a drop in performance and scalability.
 *
 * This is one of the reasons why Microsoft has been steadily deprecating more and 
 * more of the open data services API used by extended procedures. There is 
 * therefore no guarantee that extended procedures will be supported much longer 
 * especially as in SQL 2005 procedures can be written in any of the managed .NET 
 * languages.
 *
 * The thread performance issue is further impacted in this application by the need 
 * to schedule additional threads to host transactions. Although the extended procedure 
 * approach leads to a simple implementation from the JDBC point of view, it is not 
 * likely to be as efficient or scalable as the dedicated external server process used 
 * by some of the commercial drivers.
 * 
 * The final obvious message on performance is that distributed transactions are very 
 * expensive to manage when compared to local transactions and should only be used when 
 * absolutely necessary.
 */

#define INITGUID
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>
#include <process.h>
#include <srv.h>
#include <txdtc.h>
#include <xolehlp.h>
#include <xa.h>
#include "JtdsXA.h"

/*
 * Shared variables accessed by all threads
 */
static volatile int       nThreads = 0;            // Number of threads in pool
static CRITICAL_SECTION   csThreadPool;            // Critical section to synch access to pool
static THREAD_CB *pFreeThreadList = NULL;          // Head of chain of free threads
static THREAD_CB *pThreadList = NULL;              // Head of chain of in use threads
static int                globalConnID = INIT_CONNID;  // Initial Connection ID value 
static int                serverVersion;           // Server version (sent from jTDS).

// 
// xa_open / xa_close info string moved here from the java side for simplicity.
// The TM parameter identifies JTDS as the transaction manager although in practice
// this is actually the J2EE container eg JBOSS.
// The RmRecoveryGuid is the unique identifier for this resource manager.
// The guid used here is generated specially for jTDS and should not clash with other RMs.
//
static char         *szOpenInfo = "TM=JTDS,RmRecoveryGuid=434CDE1A-F747-4942-9584-04937455CAB4";

#ifdef _DEBUG
static FILE         *fp_log = NULL;         // Trace log file
#endif

/*
 * XA Switch structure in DTC Proxy MSDTCPRX.DLL
 */
extern xa_switch_t  msqlsrvxa1;

/*
 * This function is entered when the DLL is loaded and unloaded.
 * Ideally the worker threads should execute and terminate tidily.
 * Unfortunately DLLMain is protected by a mutex and there is
 * no way that we can wait for the child threads to die as they will
 * not be able to reenter this routine. 
 * We get round this by forcibly terminating the threads.
 * All handles are closed to avoid resource leaks when this dll 
 * is unloaded by the DBCC JtdsXA(free) command.
 */
BOOL WINAPI DllMain( HINSTANCE hinstDLL,  // handle to DLL module
                     DWORD fdwReason,     // reason for calling function
                     LPVOID lpvReserved)  // reserved
{
    switch (fdwReason) {

        case DLL_PROCESS_ATTACH:
            InitializeCriticalSection(&csThreadPool);
        break;
    
        case DLL_PROCESS_DETACH:
            TRACE("Process Detach\n");
            EnterCriticalSection(&csThreadPool);
            // Kill in use threads
            while (pThreadList != NULL) {
                DestroyThread(&pThreadList, pThreadList);
            }
            // Kill free threads
            while (pFreeThreadList != NULL) {
                DestroyThread(&pFreeThreadList, pFreeThreadList);
            }
            LeaveCriticalSection(&csThreadPool);
            DeleteCriticalSection(&csThreadPool);
            TRACE("JtdsXA unloaded\n");
#ifdef _DEBUG
            if (fp_log != NULL) {
                fclose(fp_log);
            }
#endif
        break;
    }
    return TRUE;
}

/*
 * Defining this function is recommended by Microsoft to allow the 
 * server to check for version compatibility.
 */
__declspec(dllexport) ULONG __GetXpVersion() 
{
    return ODS_VERSION;
}

/*
 * Main entry point for the extended stored procedure.
 * The SQL signature is:
 * exec @retval = xp_jtdsxa @cmd int, @connid int, 
 *                          @flags int, @timeout, 
 *                          @xid varbinary(8000) output 
 */
__declspec(dllexport) SRVRETCODE xp_jtdsxa(SRV_PROC *pSrvProc)
{
    int  xaCmd   = 0;       // XA Command to execute 
    int  connID  = 0;       // Connection ID
    int  xaFlags = 0;       // XA Flags
    BYTE *xid    = NULL;    // XID
    long cbXid   = 0;       // Length of data in XID
    int  timeout = 0;       // Timeout value
    DWORD threadID;         // Thread ID of caller

    THREAD_CB *pThread;     // Pointer to worker thread
    int  rc  = XAER_RMFAIL; // Default return code
    int  i;                 // Misc loop variable
#ifdef _DEBUG
    char buf[128];          // Work buffer for message formatting
#endif

    BYTE bType;             // TDS data type
    long cbMaxLen;          // Maximum length of variable types
    long cbActualLen;       // Actual length of parameter
    BOOL fNull;             // True if parameter was null
    //
    // Check the parameter count.
    //
    if (srv_rpcparams(pSrvProc) != NUM_PARAMS) {
        //
        // Send error message and return
        //
        ReportError(pSrvProc, "xp_jtdsxa: wrong number of parameters");
        return rc;
    }
    //
    // Validate parameter types
    //
    for (i = 0; i < NUM_PARAMS-1; i++) {
        // Use srv_paraminfo to get data type and length information.
        if (FAIL == srv_paraminfo(pSrvProc, i+1, &bType, &cbMaxLen, 
            &cbActualLen, NULL, &fNull))
        {
            ReportError (pSrvProc, "xp_jtdsxa: srv_paraminfo failed");
            return rc;    
        }
        // These should be int input params
        if (bType != SRVINTN && bType != SRVINT4) {
            ReportError(pSrvProc, "xp_jtdsxa: integer parameter expected");
            return rc;    
        }
    }
    //
    // Use srv_paraminfo to get data type and length information.
    //
    if (FAIL == srv_paraminfo(pSrvProc, NUM_PARAMS, &bType, &cbMaxLen, 
	        &cbActualLen, NULL, &fNull))
    {
        ReportError (pSrvProc, "xp_jtdsxa: srv_paraminfo failed");
        return rc;    
    }
    // Should be varbinary type
    if (bType != SRVVARBINARY && bType != SRVBIGVARBINARY) {
        ReportError(pSrvProc, "xp_jtdsxa: last parameter should be varbinary");
        return rc;    
    }
    // Should be a return (OUTPUT) parameter
    if ((srv_paramstatus(pSrvProc, NUM_PARAMS) & SRV_PARAMRETURN) == FAIL) {
        ReportError(pSrvProc, "xp_jtdsxa: last parameter should be output");
        return rc;    
    }
    // Check that input data length does not exceed maximum size of an XID 
    if (cbActualLen > sizeof(XID)) {
        ReportError(pSrvProc, "xp_jtdsxa: XID parameter is longer than 140 bytes");
        return rc;    
    }
    //
    // Extract input parameters
    //
    // @cmd
    if (FAIL == srv_paraminfo(pSrvProc, 1, &bType, &cbMaxLen, 
            &cbActualLen, (BYTE*)&xaCmd, &fNull))
    {
        ReportError (pSrvProc, "xp_jtdsxa: srv_paraminfo failed on @cmd");
        return rc;
    }
    // @rmid
    if (FAIL == srv_paraminfo(pSrvProc, 2, &bType, &cbMaxLen, 
            &cbActualLen, (BYTE*)&connID, &fNull))
    {
        ReportError (pSrvProc, "xp_jtdsxa: srv_paraminfo failed on @rmid");
        return rc;
    }
    // validate @connid
    if (connID <= 0 && xaCmd != XAN_OPEN) {
        ReportError (pSrvProc, "xp_jtdsxa: Connection ID is invalid");
        return rc;
    }
    // @timeout
    if (FAIL == srv_paraminfo(pSrvProc, 3, &bType, &cbMaxLen, 
            &cbActualLen, (BYTE*)&timeout, &fNull))
    {
        ReportError (pSrvProc, "xp_jtdsxa: srv_paraminfo failed on @timeout");
        return rc;
    }
    // Earlier versions of jTDS will send 1 for this value (it used to be a dummy RMID)
    // so set the timeout to it's default of 0
    if (timeout == 1) {
        timeout = 0;
        TRACE("xp_jtdsxa called from old version of jTDS\r\n");
    }
    // @flags 
    if (FAIL == srv_paraminfo(pSrvProc, 4, &bType, &cbMaxLen, 
            &cbActualLen, (BYTE*)&xaFlags, &fNull))
    {
        ReportError (pSrvProc, "xp_jtdsxa: srv_paraminfo failed on @flags");
        return rc;
    }
    // @xid 
    xid = (BYTE*)malloc(sizeof(XID));
    if (xid == NULL) {
        ReportError(pSrvProc, "xp_jtdsxa: unable to allocate buffer memory for XID");
        return rc;    
    }
    memset(xid, 0, sizeof(XID)); // Zero fill as XID may be truncated  

    if (FAIL == srv_paraminfo(pSrvProc, NUM_PARAMS, &bType, &cbMaxLen, 
            &cbXid, xid, &fNull))
    {
        ReportError (pSrvProc, "xp_jtdsxa: srv_paraminfo failed on @xid");
        free(xid);
        return rc;
    }

#ifdef _DEBUG
    if (xaCmd == XAN_OPEN) {
        if (connID != 0 && fp_log == NULL) {
           // Enable tracing if the JDBC driver sends non zero here
           fp_log = fopen(LOG_PATH, "wt");
           setvbuf(fp_log, NULL, _IONBF, 0);
        }
    } else {
        sprintf(buf, "ID = %d\n", connID);
        TRACE(buf);
    }
#endif
    //
    // If not executing xa_start or xa_end we need to log this thread into
    // the MSDTC. Following execution the thread will be logged out again as
    // we cannot rely on the server calling this procedure on the same thread
    // for every execution. Experimentation reveals that the time taken to 
    // execute xa_open followed by xa_close is around 0.5 msec on a 2Ghz PC.
    // This overhead is not ideal but is not the end of the world either as
    // the original jTDS design used worker threads instead, implying
    // a context switch. The new design is more stable and probably faster.
    // The current thread id is used as the value of the RMID parameter as 
    // this should ensure unique values for the MSDTC on this computer.
    //
    threadID = GetCurrentThreadId();
    if (xaCmd != XAN_START && xaCmd != XAN_END) {
        TRACE("Server thread - xa_open\n");
        rc = (msqlsrvxa1.xa_open_entry)(szOpenInfo, threadID, TMNOFLAGS);
        if (rc != XA_OK) {
            free(xid);
            return rc;
        }
    }
    //
    // Switch execution to the correct XA routine
    //
    switch (xaCmd) {
        //
        // xa_open - Connect this thread to the MSDTC
        // We are already connected so just allocate connection ID etc here.
        //
        case XAN_OPEN:
            EnterCriticalSection(&csThreadPool);
            // Allocate a new ID for this connection. 
            connID = globalConnID++;
            if (globalConnID < 0) {
                // Problems will result if more than 2,147,483,647 connections 
                // are made before the server is rebooted. This is very unlikely 
                // requiring many years depending on connection rate!
                connID = globalConnID = INIT_CONNID;
            }
            // Save server version (supplied by jTDS) as this may
            // be useful for customising behaviour later.
            // I can't find any way of finding this out from the DLL...
            serverVersion = timeout;
            LeaveCriticalSection(&csThreadPool);
            // Set the output parameter to the value of the allocated Connection ID.
            srv_paramsetoutput(pSrvProc, NUM_PARAMS, (char*)&connID, sizeof(int), FALSE);
#ifdef _DEBUG
            sprintf(buf, "ID = %d\nServerVersion = %d\n", connID, serverVersion);
            TRACE(buf);
#endif
            break;
        //
        // xa_close - Disconnect the worker thread from the MSTDC
        // We will disconnect at the end anway so do nothing.
        //
        case XAN_CLOSE:
            // At present there is not much point in the client calling xa_close 
            // given that the server thread is automatically logged out at the 
            // end of each call. In future the code may be extended to look
            // for any active transactions owned by this connection and 
            // roll them back.
            break;  
        //
        // xa_start - MSDTC requires each transaction to execute on 
        // it's own Windows thread. This requirement is satisfied by
        // allocating a pooled worker thread for the duration of the 
        // transaction. According to this article
        // http://support.microsoft.com/default.aspx?scid=kb;en-us;318818
        // there is now an additional switch that can be supplied to xa_open 
        // which removes the need to for xa_start and xa_end to execute in 
        // the same thread. In addition Windows server 2003 introduces the 
        // IXATransLookup2 interface, which should remove the need for 
        // transaction threads altogether.
        // Unfortunatly the exact details of how to do this are unknown at present.
        //
        case XAN_START:
            if ((xaFlags & TMRESUME) != 0) {
                TRACE("Server thread - xa_start(TMRESUME)\n");
                //
                // Locate the correct thread to resume using the connID and the XID
                //
                pThread = FindThread(connID, (XID *)xid);
                if (pThread == NULL) {
                    ReportError(pSrvProc, 
                               "xp_jtdsxa: xa_start - Can't find thread for specified XID");
                    break;
                }
            } else {
#ifdef _DEBUG
                if ((xaFlags & TMJOIN) != 0) {
	                TRACE("Server thread - xa_start(TMJOIN)\n");
                } else {
	                TRACE("Server thread - xa_start\n");
                }
#endif
                //
                // Check that the XID is not already active on a thread
                //
                if ((xaFlags & TMJOIN) == 0) {
                    pThread = FindThread(-1, (XID *)xid);
                    if (pThread != NULL) {
                        ReportError(pSrvProc, 
                               "xp_jtdsxa: xa_start - There is already an active thread for the specified XID");
                        break;
                    }
                }
                // 
                // Find a free thread to host the transaction
                //
                pThread = AllocateThread(connID);
                if (pThread == NULL) {
                    ReportError(pSrvProc, 
                               "xp_jtdsxa: xa_start - Maximum number of worker threads in use");
                    break;
                }
            }
            //
            // Initialise the thread control block
            //
            pThread->szMsg    = NULL;
            pThread->timeout  = timeout;
            memcpy(&pThread->xid, xid, sizeof(XID));
            //
            // Execute the xa_start command on the worker thread
            //
            rc = ThreadExecute(pThread, pSrvProc, xaCmd, xaFlags);

            if (rc != XA_OK || cbMaxLen < pThread->cbCookie) {
#ifdef _DEBUG
                sprintf(buf, "Server thread - Command failed %d\n", rc);
                TRACE(buf);                
#endif
                if (pThread->szMsg != NULL) {
                    ReportError(pSrvProc, pThread->szMsg);
                } else 
                if (cbMaxLen < pThread->cbCookie) {
                    ReportError(pSrvProc, "xp_jtdsxa: xa_start - Output parameter is too short");
                }
                //
                // Free the cookie memory now
                //
                if (pThread->pCookie != NULL) {
                    free(pThread->pCookie);
                    pThread->pCookie = NULL;
                }
                if (rc == XAER_TIMEOUT) {
                    DestroyThread(&pThreadList, pThread);
                } else {
                    FreeThread(pThread);
                }
            } else {
                // Set the output parameter to the value of the OLE Cookie.
                srv_paramsetoutput(pSrvProc, NUM_PARAMS, pThread->pCookie,
                                            pThread->cbCookie, FALSE);                
                //
                // Free the cookie memory now
                //
                if (pThread->pCookie != NULL) {
                    free(pThread->pCookie);
                    pThread->pCookie = NULL;
                }
            }
            break;
        //
        // xa_end - Use the XID to locate the worker thread that we started the
        // transaction on then get it to execute xa_end.
        //
        case XAN_END:
#ifdef _DEBUG
            if ((xaFlags & TMSUSPEND) != 0) {
               TRACE("Server thread - xa_end(TMSUSPEND)\n");
            } else {
               TRACE("Server thread - xa_end\n");
            }
#endif
            //
            // Locate the correct thread using the connID and the XID
            //
            pThread = FindThread(connID, (XID *)xid);
            if (pThread == NULL) {
                ReportError(pSrvProc, 
                            "xp_jtdsxa: xa_end - Can't find thread for specified XID");
                break;
            }
            //
            // Execute the xa_end on the worker thread
            //
            rc = ThreadExecute(pThread, pSrvProc, xaCmd, xaFlags);
            if (rc == XAER_TIMEOUT) {
                DestroyThread(&pThreadList, pThread);
            }  
            break;
        //
        // xa_prepare - First part of two phase commit.
        //
        case XAN_PREPARE:
            TRACE("Server thread - xa_prepare\n");
            //
            // Locate the correct thread(s) using the XID and free them
            //
            while ((pThread = FindThread(-1, (XID *)xid)) != NULL) {
                FreeThread(pThread);
			}
            rc = (msqlsrvxa1.xa_prepare_entry)((XID *)xid, threadID, xaFlags);
            break;
        //
        // xa_rollback - Abort transaction.
        //
        case XAN_ROLLBACK:
            TRACE("Server thread - xa_rollback\n");
            //
            // Locate the correct thread(s) using the XID and free them
            //
            while ((pThread = FindThread(-1, (XID *)xid)) != NULL) {
                FreeThread(pThread);
            }
            rc = (msqlsrvxa1.xa_rollback_entry)((XID *)xid, threadID, xaFlags); 
            break;
        //
        // xa_commit - Second part of two phase commit.
        //
        case XAN_COMMIT:
            TRACE("Server thread - xa_commit\n");
            //
            // Locate the correct thread(s) using the XID and free them
            // (if already prepared then no threads will be freed here)
            //
            while ((pThread = FindThread(-1, (XID *)xid)) != NULL) {
                FreeThread(pThread);
            }
            rc = (msqlsrvxa1.xa_commit_entry)((XID *)xid, threadID, xaFlags); 
            break;
        //
        // xa_recover - Ask the MSTDC to return a list of uncompleted transaction IDs.
        // The complete list is sent back as a result set.
        //
        case XAN_RECOVER:
            TRACE("Server thread - xa_recover\n");
            xid = (BYTE*)malloc(sizeof(XID));
            if (xid == NULL) {
                rc = XAER_RMFAIL;
                ReportError(pSrvProc, "xp_jtdsxa: Out of memory allocating XID buffer");
                break;
            }
            //
            // Describe the single column in result set as XID BINARY(140)
            //
            if (0 == srv_describe(pSrvProc, 
                                  1, 
                                  "XID", 
                                  SRV_NULLTERM, 
                                  SRVBINARY, 
                                  sizeof(XID), 
                                  SRVBINARY, 
                                  sizeof(XID), 
                                  xid)) 
            {
                rc = XAER_RMFAIL;
                ReportError(pSrvProc, "xp_jtdsxa: Failed to descibe XID result set");
                break;
            }
            i = 0;
            //
            // Obtain first XID to recover
            //
            rc = (msqlsrvxa1.xa_recover_entry)((XID *)xid, 1, threadID, TMSTARTRSCAN);
            if (rc < 0) {
                break;
            }
            //
            // Now loop to obtain remaining XIDs
            // TODO: this is not very efficient we should ask MSTDC for 
            // more XIDs in each call. There is a bug in older versions of MSTDC
            // that causes xa_recover to return only the first XID when used this way.
            // This bug is fixed with NT4 SP6a.
            // There is also a bug that causes MSTDC to fail if xa_recover is invoked
            // from more than one thread concurrently. This is unlikely to be a problem
            // unless the transaction manager invokes xa_recover on more than one thread
            // at a time eg WebLogic. See http://support.microsoft.com/?id=883955
            //
            while (rc > 0) {
                if (FAIL == srv_sendrow(pSrvProc)) {
                    break;
                }
                i++;
                rc = (msqlsrvxa1.xa_recover_entry)((XID *)xid, 1, threadID, TMNOFLAGS);
            }
            // 
            // Tidy up by telling MSDTC we have finished the scan for XIDs
            //
            rc = (msqlsrvxa1.xa_recover_entry)((XID *)xid, 1, threadID, TMENDRSCAN);
            //
            srv_senddone(pSrvProc, (SRV_DONE_COUNT | SRV_DONE_MORE), 0, i);
            // 
            // RC is the number of XID's found.
            rc = i;
            break;
        //
        // xa_forget - Ask the MSDTC to forget a heuristically completed transaction.
        //
        case XAN_FORGET:
            TRACE("Server thread - xa_forget\n");
            //
            // Locate the correct thread(s) using the XID and free them
            //
            while ((pThread = FindThread(-1, (XID *)xid)) != NULL) {
                FreeThread(pThread);
            }
            rc = (msqlsrvxa1.xa_forget_entry)((XID *)xid, threadID, xaFlags);
            break;
        //
        // Wait for an asynchronous operation to complete.
        // As Java does not require asynchronous operations this
        // is just a dummy operation.
        //
        case XAN_COMPLETE:
            TRACE("Server thread - xa_complete\n");
            rc = XAER_PROTO;
            break;
        default:
            ReportError(pSrvProc, "xp_jtdsxa: Invalid XA command");
            break;
    }
    //
    // Free the XID buffer
    //
    if (xid != NULL) {
        free(xid);
    }
    //
    // If not doing xa_start or xa_end we now need to disconnect from MSTDC
    //
    if (xaCmd != XAN_START && xaCmd != XAN_END) {
        TRACE("Server thread - xa_close\n");
        (msqlsrvxa1.xa_close_entry)(szOpenInfo, threadID, TMNOFLAGS);
    } 
    //
    // Return value will be < 0 if an error has occured
    //
    return rc;
}

/*
 * Invoke the XA command on the worker thread.
 */
int ThreadExecute(THREAD_CB *tcb, SRV_PROC *pSrvProc, int xaCmd, int xaFlags)
{
    tcb->xaCmd   = xaCmd;
    tcb->xaFlags = xaFlags;
    // unsignal the event that this thread will sleep on
    ResetEvent(tcb->evDone);
    // Signal the event that the worker thread is sleeping on
    SetEvent(tcb->evSuspend);
    // Wait for worker thread to execute.
    if (WaitForSingleObject(tcb->evDone, EXECUTE_TIMEOUT) != WAIT_OBJECT_0) {
        ReportError(pSrvProc, "xp_jtdsxa: Worker Thread timed out executing command");
        tcb->rc = XAER_TIMEOUT;
    }
    return tcb->rc;
}

/*
 * Destroy a thread
 */
void DestroyThread(THREAD_CB **ppThread, THREAD_CB *pThread) {
    TRACE("DestroyThread()\n");
    EnterCriticalSection(&csThreadPool);
    //
    // Stop the thread
    //
    TerminateThread(pThread->hThread, 0);
    //
    // Remove from linked list
    //
    UnlinkThread(ppThread, pThread);
    //
    // Free other handles
    //
    CloseHandle(pThread->evDone);
    CloseHandle(pThread->evSuspend);
    CloseHandle(pThread->hThread);
    //
    // Free the thread memory
    //
    free(pThread);
    //
    // Decrement thread count
    //
    nThreads--;
    LeaveCriticalSection(&csThreadPool);
}

/*
 * Unlink a thread from a linked list of threads
 */
void UnlinkThread(THREAD_CB **ppThread, THREAD_CB *pThread) {
    THREAD_CB *p;
    while (*ppThread != NULL && *ppThread != pThread) {
        p = *ppThread;
        ppThread = &p->pNext;
    }
    if (*ppThread != NULL) {
        p = *ppThread;
        *ppThread = p->pNext;
        p->pNext = NULL;
        TRACE("UnlinkThread - Thread unlinked\n");
    } else {
        TRACE("UnlinkThread - Thread not on in use list!\n");
    }
}

/*
 * Locate the thread allocated to this transaction.
 */
THREAD_CB *FindThread(int connID, XID *xid)
{
    THREAD_CB *pThread = NULL;
    int nt = -1;
    TRACE("FindThread()\n");
    EnterCriticalSection(&csThreadPool);
    // Find thread for this transaction
	pThread = pThreadList;
    if (connID < 0) {
        // Just match on XID
        while (pThread != NULL 
               && memcmp(&pThread->xid, xid, sizeof(XID)) != 0) {
            pThread = pThread->pNext;
        }
    } else {
        // Include the connID (used by xa_end & xa_start(TMRESUME))
        // Look for this connection's thread
        while (pThread != NULL 
               && (pThread->connID != connID ||
               memcmp(&pThread->xid, xid, sizeof(XID)) != 0)) {
            pThread = pThread->pNext;
        }
    }
    LeaveCriticalSection(&csThreadPool);
    return pThread;
}

/*
 * Locate a free worker thread or create a new one.
 * This routine is synchronized by using a critical
 * section to protect the thread table.
 */
THREAD_CB *AllocateThread(int connID)
{
    THREAD_CB *pThread = NULL;
    int nt = -1;
    TRACE("GetWorkerThread()\n");
    EnterCriticalSection(&csThreadPool);

    pThread = pFreeThreadList;
    if (pThread != NULL) {
        pFreeThreadList = pThread->pNext;
        pThread->pNext = NULL;
    }

    if (pThread == NULL && nThreads < MAX_THREADS) {
        // No threads so create one
        pThread = (THREAD_CB *)malloc(sizeof(THREAD_CB));
        if (pThread != NULL) {
            pThread->pNext   = NULL;
            pThread->evDone  = CreateEvent(NULL, TRUE, FALSE, NULL);
            pThread->evSuspend = CreateEvent(NULL, TRUE, FALSE, NULL);
            ResetEvent(pThread->evSuspend);
#ifdef _DEBUG
            pThread->hThread = 
                (HANDLE)_beginthreadex(NULL,
                               0,
                               (LPTHREAD_START_ROUTINE)WorkerThread,
                               pThread,
                               0,
                               &pThread->threadID);
#else
            pThread->hThread = 
                 (HANDLE)CreateThread(NULL,
                                0,
                                (LPTHREAD_START_ROUTINE)WorkerThread,
                                pThread,
                                0,
                                &pThread->threadID);
#endif
            if (pThread->hThread != NULL) {
                nThreads++;
                TRACE("GetWorkerThread() - New thread allocated\n");
            } else {
                TRACE("GetWorkerThread() - failed to allocated new thread\n");
                free(pThread);
                pThread = NULL;
            }
        }
    }
    //
    // Link to in use list
    //
    if (pThread != NULL) {
        pThread->szMsg  = NULL;
        pThread->connID = connID;
        pThread->bOpen  = FALSE;
        pThread->pNext  = pThreadList;
        pThreadList     = pThread;
        pThread->bInUse = TRUE;
        pThread->bActive = FALSE;
    }
    LeaveCriticalSection(&csThreadPool);
    return pThread;
}

/*
 * Free a worker thread for reuse.
 */
void FreeThread(THREAD_CB *pThread)
{
    TRACE("FreeThread()\n");
    EnterCriticalSection(&csThreadPool);
    pThread->bInUse = FALSE;
    UnlinkThread(&pThreadList, pThread);
    pThread->pNext = pFreeThreadList;
    pFreeThreadList = pThread;
    LeaveCriticalSection(&csThreadPool);
}

/*
 * Report an error message back to the user in a TDS error
 * packet.
 */
void ReportError(SRV_PROC *pSrvProc, char *szErrorMsg)
{
    TRACE("ReportError('");
    TRACE(szErrorMsg);
    TRACE("')\n");
    srv_sendmsg(pSrvProc, SRV_MSG_ERROR, XP_JTDS_ERROR, SRV_INFO, 1,
                NULL, 0, (DBUSMALLINT) 0, 
                szErrorMsg,
                SRV_NULLTERM);

    srv_senddone(pSrvProc, (SRV_DONE_ERROR | SRV_DONE_MORE), 0, 0);
}

/*
 * Worker thread created to handle each XA transaction.
 * The Thread sleeps on an Event object in the control block 
 * until released by the controlling thread to execute the xa function.
 * The transaction timeout feature is implemented here as well.
 */
DWORD WINAPI WorkerThread(LPVOID lpParam) 
{
    THREAD_CB *tcb = (THREAD_CB *)lpParam;
    int cmd;
#ifdef _DEBUG
    char buf[80];
#endif
    TRACE("WorkerThread created\n");

    //
    // Initially suspended until released by creating thread
    //
    WaitForSingleObject(tcb->evSuspend, INFINITE);

    while (tcb->xaCmd != XAN_SHUTDOWN) {
        cmd = tcb->xaCmd;
        tcb->xaCmd = XAN_SLEEP;
        // Unsignal event ready for next sleep
        ResetEvent(tcb->evSuspend);
        //
        // Connect this worker thread to the MSDTC
        //
        if (tcb->bOpen == FALSE) {
            TRACE("WorkerThread - executing xa_open\n");
            // 
            // We use the thread id as the RMID as this is 
            // globally unique on any Windows system and there
            // could be more than one SQL Server instance.
            //
            tcb->rc = (msqlsrvxa1.xa_open_entry)(szOpenInfo, tcb->threadID, TMNOFLAGS);
            if (tcb->rc == XA_OK) {
                tcb->bOpen = TRUE;
            } else {
            TRACE("xa_open failed in worker thread\n");
            }
        } else {
            tcb->rc = XA_OK;
        }
        //
        // Now execute requested command
        //
        if (tcb->bOpen) {
            if (cmd == XAN_START) {
                // xa_start
                TRACE("WorkerThread - executing xa_start\n");
                XAStartCmd(tcb);
                if (tcb->rc == XA_OK) {
                    tcb->bActive = TRUE;
                }
            } else 
            if (cmd == XAN_END) {
                // xa_end
                TRACE("WorkerThread - executing xa_end\n");
                tcb->rc = (msqlsrvxa1.xa_end_entry)(&tcb->xid, tcb->threadID, tcb->xaFlags);
                if ((tcb->xaFlags & TMSUSPEND) == 0) {
                    tcb->bActive = FALSE;
                }
            }
        }
#ifdef _DEBUG
        if (tcb->rc != XA_OK) {
            sprintf(buf, "WorkerThread - Command failed %d\n", tcb->rc);
            TRACE(buf);
        }
#endif
        if (tcb->bOpen && (tcb->rc == XAER_RMERR || tcb->rc == XAER_RMFAIL)) {
            // This type of error may indicate a failure of the MSDTC.
            // The best thing we can do is try to execute xa_close and then force
            // this thread to execute xa_open next time it is used.
            if (tcb->rc != XAER_RMFAIL) {
                TRACE("WorkerThread - executing xa_close\n");
                (msqlsrvxa1.xa_close_entry)(szOpenInfo, tcb->threadID, TMNOFLAGS);
            }
            tcb->bOpen = FALSE;
        }
        // Free the sleeping controlling thread
        SetEvent(tcb->evDone);
        // 
        // If there is a transaction timeout then enter a timed wait and rollback 
        // the transaction if the timeout expires.
        //
        if (tcb->bOpen && tcb->rc == XA_OK && tcb->timeout > 0) {
            //
            // Sleep with timeout to abort if distributed transaction times out.
            //
            if (WAIT_OBJECT_0 != WaitForSingleObject(tcb->evSuspend, tcb->timeout)) {
                if (tcb->xaCmd != XAN_SLEEP) {
                    // Race condition sleep up at same time as new command executed
                    continue;
                }
                //
                // Time's up rollback transaction 
                //
                if (tcb->bInUse) {
                    TRACE("WorkerThread - transaction timed out\n");
                    // End the transaction
                    if (tcb->bActive == TRUE) {
                        TRACE("WorkerThread - executing xa_end\n");
                        tcb->rc = (msqlsrvxa1.xa_end_entry)(&tcb->xid, tcb->threadID, TMSUCCESS);
                        tcb->bActive = FALSE;
                    }
#ifdef _DEBUG
                    if (tcb->rc != XA_OK) {
                        sprintf(buf, "WorkerThread - Command failed %d\n", tcb->rc);
                        TRACE(buf);
                    }
#endif
                    // Rollback the transaction
                    TRACE("WorkerThread - executing xa_rollback\n");
                    tcb->rc = (msqlsrvxa1.xa_rollback_entry)(&tcb->xid, tcb->threadID, TMNOFLAGS);
#ifdef _DEBUG
                    if (tcb->rc != XA_OK) {
                        sprintf(buf, "WorkerThread - Command failed %d\n", tcb->rc);
	                    TRACE(buf);
                    }
#endif
                    //
                    // Put thread back on free list
                    //
                    FreeThread(tcb);
                }
                // Unsignal event ready for next sleep
                ResetEvent(tcb->evSuspend);
                // Sleep until woken by controlling thread
                WaitForSingleObject(tcb->evSuspend, INFINITE);
            }
        } else {
            // Sleep until woken by controlling thread
            WaitForSingleObject(tcb->evSuspend, INFINITE);
        }
    }
    //
    // Thread is closing down 
    // The idea is that executing the thread with XAN_SHUTDOWN will cause
    // tidy termination. This is not actually used at present see the comment
    // in the DLLMain method for one reason why.
    //
    TRACE("WorkerThread shutdown\n");
    return 0;
}

/*
 * Issue an XA Start transaction command.
 * Any OLE errors are returned as a string in the thread
 * control block so that they can be passed to the client
 * in an SQL error reply.
 * This OLE stuff is much easier to do in C++ but this
 * DLL has been written in C for maximum portability.
 */
void XAStartCmd(THREAD_CB *tcb)
{
    IXATransLookup                  *pXATransLookup;
    ITransaction                    *pTransaction;
    ITransactionExportFactory       *pTranExportFactory;
    ITransactionImportWhereabouts   *pTranWhere;
    ITransactionExport              *pTranExport;
    BYTE    whereabouts[128];
    ULONG   cbWhereabouts;
    HRESULT	hr;
    //
    // Register the XID with MSDTC
    //
    tcb->rc = (msqlsrvxa1.xa_start_entry)(&tcb->xid, tcb->threadID, tcb->xaFlags);
    if (tcb->rc != XA_OK) {
        return;
    }
    //
    // Now comes the tricky bit, we need to obtain the OLE transaction ID
    // so that we can pass it back to the driver which in turn will pass
    // it to the SQL Server. This will allow us to enlist the SQL server
    // in the transaction in the same way as the ODBC SQLSetConnectOption 
    // SQL_COPT_SS_ENLIST_IN_DTC.
    //
    // Obtain the IXATransLookup interface
    // by calling DtcGetTransactionManager()
    //
    hr = DtcGetTransactionManagerC(
                                    NULL,
                                    NULL,
                                    &IID_IXATransLookup,
                                    0,
                                    0,
                                    NULL,
                                    (void **)&pXATransLookup
                                   );

    if (FAILED(hr))
    {
        tcb->szMsg = "xp_jtdsxa: DtcGetTransactionManager failed";
        tcb->rc = XAER_RMFAIL;
        return;
    }
    //
    // Obtain the OLE transaction that has been mapped to our XID.
    //
    pXATransLookup->lpVtbl->Lookup(pXATransLookup, &pTransaction);
    if (FAILED (hr))
    {
        hr = pXATransLookup->lpVtbl->Release(pXATransLookup);
        tcb->szMsg = "xp_jtdsxa: IXATransLookup->Lookup() failed";
        tcb->rc = XAER_RMFAIL;
        return;
    }
    //
    // It appears that under certain circumstances a null transaction handle
    // can be returned even though the call above seems to work OK. As using
    // this handle will cause a memory fault we trap this error here.
    // This 'feature' appears to be undocumented!
    //
    if (pTransaction == NULL) {
        hr = pXATransLookup->lpVtbl->Release(pXATransLookup);
        tcb->szMsg = "xp_jtdsxa: IXATransLookup->Lookup() returned null transaction handle";
        tcb->rc = XAER_RMFAIL;
        return;
    }
    //
    // Now obtain the ITransactionImportWhereabouts interface.
    // We need this one to obtain a whereabouts structure for use
    // in exporting the transaction cookie.
    //
    hr = DtcGetTransactionManagerC(
                                    NULL,
                                    NULL,
                                    &IID_ITransactionImportWhereabouts,
                                    0,
                                    0,
                                    NULL,
                                    (void **)&pTranWhere
                                  );
    if (FAILED (hr))
    {
        pTransaction->lpVtbl->Release(pTransaction);
        pXATransLookup->lpVtbl->Release(pXATransLookup);
        tcb->szMsg = "xp_jtdsxa: ITransactionImportWhereabouts failed";
        tcb->rc = XAER_RMFAIL;
        return;
    }
    //
    // Now obtain the ITransactionExportFactory interface.
    // We need this to create an ITransactionExport interface 
    // which we will use to obtain the OLE transaction cookie.
    //
    hr = DtcGetTransactionManagerC(
                                    NULL,
                                    NULL,
                                    &IID_ITransactionExportFactory,
                                    0,
                                    0,
                                    NULL,
                                    (void **)&pTranExportFactory
                                  );
    if (FAILED (hr))
    {
        pTranWhere->lpVtbl->Release(pTranWhere);
        pTransaction->lpVtbl->Release(pTransaction);
        pXATransLookup->lpVtbl->Release(pXATransLookup);
        tcb->szMsg = "xp_jtdsxa: ITransactionExportFactory failed";
        tcb->rc = XAER_RMFAIL;
        return;
    }
    //
    // Now obtain the whereabouts structure.
    //
    hr = pTranWhere->lpVtbl->GetWhereabouts(pTranWhere, 
                                            sizeof(whereabouts), 
                                            whereabouts, 
                                            &cbWhereabouts);
    if (FAILED (hr))
    {
        pTranExportFactory->lpVtbl->Release(pTranExportFactory);
        pTranWhere->lpVtbl->Release(pTranWhere);
        pTransaction->lpVtbl->Release(pTransaction);
        pXATransLookup->lpVtbl->Release(pXATransLookup);
        tcb->szMsg = "xp_jtdsxa: ITransactionImportWhereabouts->get failed";
        tcb->rc = XAER_RMFAIL;
        return;
    }
    //
    // Now create the ITransactionExport interface
    //
    hr = pTranExportFactory->lpVtbl->Create(pTranExportFactory, 
                                            cbWhereabouts, 
                                            whereabouts, 
                                            &pTranExport);
    if (FAILED (hr))
    {
        pTranExportFactory->lpVtbl->Release(pTranExportFactory);
        pTranWhere->lpVtbl->Release(pTranWhere);
        pTransaction->lpVtbl->Release(pTransaction);
        pXATransLookup->lpVtbl->Release(pXATransLookup);
        tcb->szMsg = "xp_jtdsxa: ITransactionExportFactory->create failed";
        tcb->rc = XAER_RMFAIL;
        return;
    }

    //
    // Marshal the transaction for export and obtain 
    // the size of the cookie to be exported
    //
    hr  = pTranExport->lpVtbl->Export(pTranExport,
                                      (IUnknown *)pTransaction, 
                                      &tcb->cbCookie);
    if (FAILED (hr) || tcb->cbCookie > COOKIE_SIZE)
    {
        pTranExport->lpVtbl->Release(pTranExport);
        pTranExportFactory->lpVtbl->Release(pTranExportFactory);
        pTranWhere->lpVtbl->Release(pTranWhere);
        pTransaction->lpVtbl->Release(pTransaction);
        pXATransLookup->lpVtbl->Release(pXATransLookup);
        if (FAILED(hr)) {
            tcb->szMsg = "xp_jtdsxa: ITransactionExport->Export failed";
        } else {
            tcb->szMsg = "xp_jtdsxa: Export transaction cookie failed, buffer too smalll";
        }
        tcb->rc = XAER_RMFAIL;
        return;
    }
    //
    // Allocate the cookie buffer
    //
    tcb->pCookie  = (BYTE *)malloc(tcb->cbCookie);
    if (tcb->pCookie == NULL) {
        pTranExport->lpVtbl->Release(pTranExport);
        pTranExportFactory->lpVtbl->Release(pTranExportFactory);
        pTranWhere->lpVtbl->Release(pTranWhere);
        pTransaction->lpVtbl->Release(pTransaction);
        pXATransLookup->lpVtbl->Release(pXATransLookup);
        tcb->szMsg = "xp_jtdsxa: Failed to allocate cookie buffer";
        tcb->rc = XAER_RMFAIL;
        return;
    }    
    //
    // Now obtain the OLE transaction cookie.
    //
    hr = pTranExport->lpVtbl->GetTransactionCookie( pTranExport, 
                                                    (IUnknown *)pTransaction, 
                                                    tcb->cbCookie, 
                                                    tcb->pCookie, 
                                                    &tcb->cbCookie);
    if (FAILED (hr))
    {
        pTranExport->lpVtbl->Release(pTranExport);
        pTranExportFactory->lpVtbl->Release(pTranExportFactory);
        pTranWhere->lpVtbl->Release(pTranWhere);
        pTransaction->lpVtbl->Release(pTransaction);
        pXATransLookup->lpVtbl->Release(pXATransLookup);
        free(tcb->pCookie);
        tcb->szMsg = "xp_jtdsxa: ITransactionExport->GetTransactionCookie failed";
        tcb->rc = XAER_RMFAIL;
        return;
    }
    //
    // Free the OLE handles
    //
    pTranExport->lpVtbl->Release(pTranExport);
    pTranExportFactory->lpVtbl->Release(pTranExportFactory);
    pTranWhere->lpVtbl->Release(pTranWhere);
    pTransaction->lpVtbl->Release(pTransaction);
    pXATransLookup->lpVtbl->Release(pXATransLookup);
    return;
}
