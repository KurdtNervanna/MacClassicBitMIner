#include "dnr.h"
#include <Resources.h>
#include <Files.h>
#include <Gestalt.h>
#include <Memory.h>
#include <Devices.h>
#include <Events.h>
#include <string.h>

#ifndef kOnSystemDisk
#define kOnSystemDisk (-32768)
#endif
#ifndef gestaltFindFolderPresent
#define gestaltFindFolderPresent 0
#endif

#define OPENRESOLVER  1L
#define CLOSERESOLVER 2L
#define STRTOADDR     3L

#define kCacheFault   (-23042)
#define kInProgress   1L

typedef OSErr (*DnrProc)(long, ...);
static DnrProc gDnr = 0;
static Handle  gCode = 0;

/* Look inside one folder for a file of the given type/creator that holds 'dnrp'. */
static short search_folder(short vRef, long dirID, OSType type, OSType creator)
{
    CInfoPBRec pb; Str255 name; short i;
    for (i = 1; ; i++) {
        short rf;
        memset(&pb, 0, sizeof pb);
        name[0] = 0;
        pb.hFileInfo.ioNamePtr = name;
        pb.hFileInfo.ioVRefNum = vRef;
        pb.hFileInfo.ioDirID = dirID;
        pb.hFileInfo.ioFDirIndex = i;
        if (PBGetCatInfoSync(&pb) != noErr) return -1;
        if (pb.hFileInfo.ioFlAttrib & 0x10) continue;                 /* directory */
        if (pb.hFileInfo.ioFlFndrInfo.fdType != type ||
            pb.hFileInfo.ioFlFndrInfo.fdCreator != creator) continue;
        rf = HOpenResFile(vRef, dirID, name, fsRdPerm);
        if (rf == -1) continue;
        if (Count1Resources('dnrp') > 0 || GetIndResource('dnrp', 1)) return rf;
        CloseResFile(rf);
    }
}

static short open_our_rf(void)
{
    long resp; short vRef; long dirID; short rf;
    /* MacTCP 1.1: Control Panels, 'cdev'/'ztcp';  1.0.x: 'cdev'/'mtcp' */
    if (Gestalt(gestaltFindFolderAttr, &resp) == noErr &&
        (resp & (1L << gestaltFindFolderPresent)) &&
        FindFolder(kOnSystemDisk, kControlPanelFolderType, false, &vRef, &dirID) == noErr) {
        if ((rf = search_folder(vRef, dirID, 'cdev', 'ztcp')) != -1) return rf;
        if ((rf = search_folder(vRef, dirID, 'cdev', 'mtcp')) != -1) return rf;
    }
    {   /* MacTCP 1.0.x keeps the file in the System Folder */
        long sysDir; short v;
        if (FindFolder(kOnSystemDisk, kSystemFolderType, false, &v, &sysDir) == noErr &&
            (rf = search_folder(v, sysDir, 'cdev', 'mtcp')) != -1) return rf;
    }
    return -1;
}

OSErr DnrOpen(void)
{
    short rf; OSErr rc;
    if (gDnr) return noErr;
    rf = open_our_rf();                        /* may legitimately be -1 (code in System) */
    gCode = GetIndResource('dnrp', 1);
    if (!gCode) { if (rf != -1) CloseResFile(rf); return resNotFound; }
    DetachResource(gCode);
    if (rf != -1) CloseResFile(rf);
    MoveHHi(gCode); HLock(gCode);
    gDnr = (DnrProc)*gCode;
    rc = (*gDnr)(OPENRESOLVER, (char *)0);
    if (rc != noErr) { HUnlock(gCode); DisposeHandle(gCode); gCode = 0; gDnr = 0; }
    return rc;
}

OSErr DnrClose(void)
{
    if (!gDnr) return notOpenErr;
    (*gDnr)(CLOSERESOLVER);
    HUnlock(gCode); DisposeHandle(gCode);
    gCode = 0; gDnr = 0;
    return noErr;
}

static void done_proc(DnrHostInfo *hi, char *userData)
{
    (void)hi;
    *(volatile char *)userData = 1;
}

OSErr DnrResolve(const char *host, unsigned long *ip)
{
    static DnrHostInfo hi;                    /* must stay valid for async completion */
    static volatile char done;
    OSErr rc; long start;
    if (!gDnr) return notOpenErr;
    memset(&hi, 0, sizeof hi);
    done = 0;
    hi.rtnCode = kInProgress;
    rc = (*gDnr)(STRTOADDR, (char *)host, &hi, (long)done_proc, (char *)&done);
    if (rc == kCacheFault) {
        start = TickCount();
        while (!done && (TickCount() - start) < 60L * 20) SystemTask();   /* 20 s */
        if (!done) return -1;
        rc = (OSErr)hi.rtnCode;
    }
    if (rc == noErr) { *ip = hi.addr[0]; if (!*ip) rc = -2; }
    return rc;
}
