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

#define MAX_THREADS         64          // This limits the number of active transactions
#define EXECUTE_TIMEOUT     300000      // 5 minutes
#define COOKIE_SIZE         128         // Normally 80 bytes 
#define MAX_SERVER_ERROR    20000       // Ensure our errors outside server range
#define XP_JTDS_ERROR MAX_SERVER_ERROR+100
#define NUM_PARAMS          5           // xp_jtdsxa must have NUM_PARAMS
#define LOG_PATH            "c:\\temp\\jtdslog.txt"
#define INIT_CONNID         1           // Initial Connection ID

/*
 * Indexes of our command mapping
 */
#define XAN_SHUTDOWN 0
#define XAN_OPEN     1
#define XAN_CLOSE    2
#define XAN_START    3
#define XAN_END      4
#define XAN_ROLLBACK 5
#define XAN_PREPARE  6
#define XAN_COMMIT   7
#define XAN_RECOVER  8
#define XAN_FORGET   9
#define XAN_COMPLETE 10
#define XAN_SLEEP    11
/*
 * Execute timeout error
 */
#define XAER_TIMEOUT (-99)

#ifdef _DEBUG
#define TRACE(s) if (fp_log != NULL) fprintf(fp_log, s);
#else
#define TRACE(s)
#endif

/*
 * Thread control block
 */
typedef struct _threadcb {
	struct _threadcb *pNext;        // Pointer to next thread CB in chain
    volatile BYTE   bInUse;         // Indicates state of thread eg free etc
    BYTE            bOpen;          // Thread has been connected to MSDTC
    BYTE            bActive;        // Transaction is started
    HANDLE          hThread;        // The Windows thread HANDLE
    int             threadID;       // Windows thread identifier
    HANDLE          evDone;         // Event object for synchronization
    HANDLE          evSuspend;      // Event object for synchronization
    int             xaCmd;          // XA Command to execute
    int             connID;         // JDBC Connection ID
    int             xaFlags;        // XA Flags for command
    int             timeout;        // Transaction timeout in msec
    XID             xid;            // Global transaction ID
    int             rc;             // Return code from XA function
    char            *szMsg;         // Optional error message
    int             cbCookie;       // Cookie buffer size
    BYTE            *pCookie;       // Returned TX cookie
} THREAD_CB;


/*
 * Forward declarations
 */
static DWORD WINAPI WorkerThread(LPVOID);
static THREAD_CB *AllocateThread(int);
static void  FreeThread(THREAD_CB *);
static int   ThreadExecute(THREAD_CB *, SRV_PROC *, int, int);
static THREAD_CB *FindThread(int, XID *);
static void  DestroyThread(THREAD_CB **, THREAD_CB *);
static void  UnlinkThread(THREAD_CB **, THREAD_CB *);
static void  ReportError(SRV_PROC *, char *);
static void  XAStartCmd(THREAD_CB *);
