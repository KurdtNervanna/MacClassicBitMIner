/*
 * MacClassicBitMiner 2.0 - Stratum v1 Bitcoin pool miner for classic Mac OS
 * (68k, System 6.0.8+, MacTCP).  Built with Retro68 from this C source; the
 * mining logic lives in ../minercore.c and is shared with the host test tools.
 *
 * UI: four text fields (wallet, pool host:port, worker, password), Connect /
 * Disconnect / Self-Test buttons, and a status block.
 */
#include <Quickdraw.h>
#include <Fonts.h>
#include <Windows.h>
#include <Menus.h>
#include <TextEdit.h>
#include <Dialogs.h>
#include <Events.h>
#include <Devices.h>
#include <OSUtils.h>
#include <ToolUtils.h>
#include <Memory.h>
#include <Multiverse.h>   /* Retro68 multiversal: holds the MacTCP definitions */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../minercore.h"
#include "dnr.h"

#define TCP_BUF_SIZE 8192            /* MacTCP receive buffer (>= 4096)      */
#define HASHES_PER_TICK 200          /* nonces tried between event polls     */

typedef enum { ST_STOPPED, ST_CONNECTING, ST_STRATUM, ST_MINING } AppState;

static WindowPtr gWin;
static Boolean   gDone;
static TEHandle  gWalletTE, gPoolTE, gWorkerTE, gPassTE, gActiveTE;
static Rect      gWalletR, gPoolR, gWorkerR, gPassR, gConnectR, gDiscR, gTestR;

static AppState  gState = ST_STOPPED;
static mc_session gSess;
static short     gDrv;               /* .IPP refnum                         */
static Boolean   gDrvOpen, gDnrOpen;
static StreamPtr gStream;
static char      gRcvBuf[TCP_BUF_SIZE];   /* given to MacTCP: must never move */
static char      gAcc[MC_MAX_LINE];  static int gAccLen;
static long      gStartTick;
static int       gSelfTest = -1;     /* -1 not run, 0 fail, 1 pass          */
static char      gMsg[100];

/* ---------------------------------------------------------------- text */
static void te_get(TEHandle te, char *out, int max)
{
    int n = (**te).teLength;
    if (n > max - 1) n = max - 1;
    BlockMoveData(*(**te).hText, out, n);
    out[n] = 0;
}

static void set_msg(const char *m) { strncpy(gMsg, m, sizeof gMsg - 1); gMsg[sizeof gMsg - 1] = 0; }

/* ----------------------------------------------------------- MacTCP I/O */
static void zero_pb(TCPiopb *pb)
{
    memset(pb, 0, sizeof *pb);
    pb->ioCRefNum = gDrv;
}

static OSErr tcp_connect(unsigned long ip, unsigned short port)
{
    TCPiopb pb; OSErr err;
    zero_pb(&pb);
    pb.csCode = TCPCreate;
    pb.csParam.create.rcvBuff = gRcvBuf;
    pb.csParam.create.rcvBuffLen = TCP_BUF_SIZE;
    if ((err = PBControlSync((ParmBlkPtr)&pb)) != noErr) return err;
    gStream = pb.tcpStream;

    zero_pb(&pb);
    pb.csCode = TCPActiveOpen;
    pb.tcpStream = gStream;
    pb.csParam.open.ulpTimeoutValue = 20;
    pb.csParam.open.ulpTimeoutAction = 1;
    pb.csParam.open.validityFlags = 0xC0;      /* timeout value + action are valid */
    pb.csParam.open.remoteHost = ip;
    pb.csParam.open.remotePort = port;
    err = PBControlSync((ParmBlkPtr)&pb);
    if (err != noErr) {
        zero_pb(&pb); pb.csCode = TCPRelease; pb.tcpStream = gStream;
        PBControlSync((ParmBlkPtr)&pb);
        gStream = 0;
    }
    return err;
}

static void tcp_close(void)
{
    TCPiopb pb;
    if (!gStream) return;
    zero_pb(&pb); pb.csCode = TCPClose; pb.tcpStream = gStream;
    pb.csParam.close.ulpTimeoutValue = 5; pb.csParam.close.ulpTimeoutAction = 1;
    pb.csParam.close.validityFlags = 0xC0;
    PBControlSync((ParmBlkPtr)&pb);
    zero_pb(&pb); pb.csCode = TCPRelease; pb.tcpStream = gStream;
    PBControlSync((ParmBlkPtr)&pb);
    gStream = 0;
}

static void tcp_send_line(void *user, const char *line)
{
    static char out[1100];
    wdsEntry wds[2]; TCPiopb pb; size_t n = strlen(line);
    (void)user;
    if (!gStream || n > sizeof out - 2) return;
    memcpy(out, line, n); out[n++] = '\n';
    wds[0].length = (unsigned short)n; wds[0].ptr = out;
    wds[1].length = 0; wds[1].ptr = 0;
    zero_pb(&pb);
    pb.csCode = TCPSend; pb.tcpStream = gStream;
    pb.csParam.send.ulpTimeoutValue = 10; pb.csParam.send.ulpTimeoutAction = 1;
    pb.csParam.send.validityFlags = 0xC0;
    pb.csParam.send.pushFlag = 1;
    pb.csParam.send.wdsPtr = (Ptr)wds;
    if (PBControlSync((ParmBlkPtr)&pb) != noErr) set_msg("send failed");
}

static void disconnect(const char *why)
{
    tcp_close();
    gState = ST_STOPPED;
    if (why) set_msg(why);
}

/* Drain whatever MacTCP has buffered and dispatch complete lines. */
static void pump_network(void)
{
    TCPiopb pb; static char tmp[1024]; int avail, i;
    if (!gStream) return;
    zero_pb(&pb); pb.csCode = TCPStatus; pb.tcpStream = gStream;
    if (PBControlSync((ParmBlkPtr)&pb) != noErr) { disconnect("status error"); return; }
    avail = pb.csParam.status.amtUnreadData;
    if (avail > 0) {
        if (avail > (int)sizeof tmp) avail = sizeof tmp;
        zero_pb(&pb); pb.csCode = TCPRcv; pb.tcpStream = gStream;
        pb.csParam.receive.commandTimeoutValue = 1;
        pb.csParam.receive.rcvBuff = tmp;
        pb.csParam.receive.rcvBuffLen = avail;
        if (PBControlSync((ParmBlkPtr)&pb) == noErr) {
            int n = pb.csParam.receive.rcvBuffLen;
            for (i = 0; i < n; i++) {
                if (tmp[i] == '\n') {
                    gAcc[gAccLen] = 0;
                    if (gAccLen) mc_handle_line(&gSess, gAcc);
                    gAccLen = 0;
                } else if (gAccLen < MC_MAX_LINE - 1) gAcc[gAccLen++] = tmp[i];
            }
        }
    } else {
        /* connection state 8 = established; anything else (closing/closed) = dropped */
        if (pb.csParam.status.connectionState != 8) disconnect("pool closed the connection");
    }
    if (gState == ST_STRATUM && gSess.authorized && gSess.have_job) {
        gState = ST_MINING; gStartTick = TickCount(); gSess.hashes = 0;
    }
    if (gSess.last_error[0]) set_msg(gSess.last_error);
}

/* ------------------------------------------------------------- connect */
static int split_pool(char *in, char *host, int hmax, unsigned short *port)
{
    char *p = strstr(in, "://"), *c; long v = 0;
    if (p) in = p + 3;
    c = strchr(in, ':');
    if (!c) return 0;
    *c = 0;
    strncpy(host, in, hmax - 1); host[hmax - 1] = 0;
    for (c++; *c >= '0' && *c <= '9'; c++) v = v * 10 + (*c - '0');
    if (v < 1 || v > 65535) return 0;
    *port = (unsigned short)v;
    return 1;
}

static int numeric_ip(const char *h, unsigned long *ip)
{
    unsigned long a = 0; int dots = 0, oct = 0, have = 0;
    for (; *h; h++) {
        if (*h >= '0' && *h <= '9') { oct = oct * 10 + (*h - '0'); have = 1; if (oct > 255) return 0; }
        else if (*h == '.' && have) { a = (a << 8) | oct; oct = 0; have = 0; dots++; }
        else return 0;
    }
    if (dots != 3 || !have) return 0;
    *ip = (a << 8) | oct;
    return 1;
}

static void do_connect(void)
{
    char wallet[96], pool[160], worker[48], pass[48], host[128];
    unsigned short port; unsigned long ip; OSErr err;

    te_get(gWalletTE, wallet, sizeof wallet);
    te_get(gPoolTE, pool, sizeof pool);
    te_get(gWorkerTE, worker, sizeof worker);
    te_get(gPassTE, pass, sizeof pass);
    if (!wallet[0]) { set_msg("Enter your Bitcoin wallet address"); return; }
    if (!split_pool(pool, host, sizeof host, &port)) { set_msg("Pool must look like host:port"); return; }

    if (!gDrvOpen) {
        if ((err = OpenDriver("\p.IPP", &gDrv)) != noErr) { set_msg("MacTCP not installed (.IPP)"); return; }
        gDrvOpen = true;
    }
    if (!numeric_ip(host, &ip)) {
        if (!gDnrOpen) {
            if (DnrOpen() != noErr) { set_msg("No DNS (MacTCP DNR) - use a numeric IP"); return; }
            gDnrOpen = true;
        }
        set_msg("Resolving..."); gState = ST_CONNECTING;
        InvalRect(&gWin->portRect);
        if ((err = DnrResolve(host, &ip)) != noErr) { gState = ST_STOPPED; set_msg("DNS lookup failed"); return; }
    }
    gState = ST_CONNECTING; set_msg("Connecting...");
    if ((err = tcp_connect(ip, port)) != noErr) { gState = ST_STOPPED; set_msg("TCP connect failed"); return; }

    mc_session_init(&gSess, tcp_send_line, 0, wallet, worker, pass);
    gAccLen = 0; set_msg("");
    gState = ST_STRATUM;
    mc_start(&gSess);
}

/* ------------------------------------------------------------------ UI */
static void draw_str(short x, short y, const char *s)
{
    MoveTo(x, y); DrawText((Ptr)s, 0, (short)strlen(s));
}

static void draw_button(const Rect *r, const char *label)
{
    FrameRoundRect(r, 10, 10);
    MoveTo(r->left + (r->right - r->left - TextWidth((Ptr)label, 0, (short)strlen(label))) / 2, r->top + 16);
    DrawText((Ptr)label, 0, (short)strlen(label));
}

static void draw_window(void)
{
    char b[120]; long secs; static const char *names[] = {
        "Disconnected", "Connecting...", "Subscribing / authorizing...", "Mining" };
    SetPort(gWin); EraseRect(&gWin->portRect);
    draw_str(10, 43, "Wallet:");   TEUpdate(&gWalletR, gWalletTE); FrameRect(&gWalletR);
    draw_str(10, 83, "Pool:");     TEUpdate(&gPoolR, gPoolTE);     FrameRect(&gPoolR);
    draw_str(10, 123, "Worker:");   TEUpdate(&gWorkerR, gWorkerTE); FrameRect(&gWorkerR);
    draw_str(10, 163, "Password:"); TEUpdate(&gPassR, gPassTE);     FrameRect(&gPassR);
    draw_button(&gConnectR, "Connect"); draw_button(&gDiscR, "Disconnect"); draw_button(&gTestR, "Self-Test");

    sprintf(b, "Status: %s", names[gState]); draw_str(10, 240, b);
    if (gMsg[0]) draw_str(260, 240, gMsg);
    if (gSess.have_job) {
        sprintf(b, "Job: %s    Difficulty: %lu", gSess.job_id, (unsigned long)gSess.difficulty);
        draw_str(10, 260, b);
        secs = (TickCount() - gStartTick) / 60;
        sprintf(b, "Hashes: %lu", (unsigned long)gSess.hashes); draw_str(10, 280, b);
        if (gState == ST_MINING && secs > 0) {
            sprintf(b, "Rate: ~%lu H/s", (unsigned long)gSess.hashes / (unsigned long)secs);
            draw_str(10, 300, b);
        }
        sprintf(b, "Shares found: %lu", (unsigned long)gSess.shares_found); draw_str(10, 320, b);
        sprintf(b, "Accepted: %lu", (unsigned long)gSess.shares_ok);       draw_str(10, 340, b);
        sprintf(b, "Rejected: %lu", (unsigned long)gSess.shares_bad);      draw_str(10, 360, b);
    }
    draw_str(10, 390, gSelfTest < 0 ? "Self-Test: not run (click Self-Test to verify crypto)"
                    : gSelfTest   ? "Self-Test: PASS (SHA-256d, byte order, difficulty verified)"
                                  : "Self-Test: FAILED - crypto path is wrong!");
    draw_str(10, 415, "MacClassicBitMiner 2.0 - Stratum v1 on Mac OS 6");
}

static TEHandle te_make(const Rect *r, const char *txt)
{
    TEHandle te = TENew(r, r);
    TESetText((Ptr)txt, (long)strlen(txt), te);
    return te;
}

static void init_ui(void)
{
    Rect r;
    InitGraf(&qd.thePort); InitFonts(); InitWindows(); InitMenus(); TEInit();
    InitDialogs(0); InitCursor();
    SetRect(&r, 30, 50, 30 + 520, 50 + 440);
    gWin = NewWindow(0, &r, "\pBitcoin Pool Miner", true, documentProc, (WindowPtr)-1, true, 0);
    SetPort(gWin);
    SetRect(&gWalletR, 140, 30, 500, 46);  gWalletTE = te_make(&gWalletR, "");
    SetRect(&gPoolR, 140, 70, 500, 86);    gPoolTE   = te_make(&gPoolR, "solo.ckpool.org:3333");
    SetRect(&gWorkerR, 140, 110, 360, 126);gWorkerTE = te_make(&gWorkerR, "mac1");
    SetRect(&gPassR, 140, 150, 360, 166);  gPassTE   = te_make(&gPassR, "x");
    gActiveTE = gWalletTE; TEActivate(gActiveTE);
    SetRect(&gConnectR, 140, 190, 240, 214);
    SetRect(&gDiscR, 250, 190, 360, 214);
    SetRect(&gTestR, 380, 190, 500, 214);
}

static void set_active(TEHandle te)
{
    if (te == gActiveTE) return;
    TEDeactivate(gActiveTE); gActiveTE = te; TEActivate(te);
}

static void do_mouse(EventRecord *e)
{
    WindowPtr w; short part = FindWindow(e->where, &w);
    if (part == inContent) {
        Point p;
        if (w != FrontWindow()) { SelectWindow(w); return; }
        p = e->where; GlobalToLocal(&p);
        if (PtInRect(p, &gWalletR)) { set_active(gWalletTE); TEClick(p, (e->modifiers & shiftKey) != 0, gWalletTE); }
        else if (PtInRect(p, &gPoolR)) { set_active(gPoolTE); TEClick(p, (e->modifiers & shiftKey) != 0, gPoolTE); }
        else if (PtInRect(p, &gWorkerR)) { set_active(gWorkerTE); TEClick(p, (e->modifiers & shiftKey) != 0, gWorkerTE); }
        else if (PtInRect(p, &gPassR)) { set_active(gPassTE); TEClick(p, (e->modifiers & shiftKey) != 0, gPassTE); }
        else if (PtInRect(p, &gConnectR)) { if (gState == ST_STOPPED) do_connect(); }
        else if (PtInRect(p, &gDiscR)) { disconnect("Disconnected"); }
        else if (PtInRect(p, &gTestR)) { gSelfTest = mc_selftest(); }
        InvalRect(&gWin->portRect);
    } else if (part == inDrag) {
        DragWindow(w, e->where, &qd.screenBits.bounds);
    } else if (part == inGoAway) {
        if (TrackGoAway(w, e->where)) gDone = true;
    }
}

static void do_key(EventRecord *e)
{
    char c = (char)(e->message & charCodeMask);
    if (c == '\t') {
        TEHandle order[4]; int i;
        order[0] = gWalletTE; order[1] = gPoolTE; order[2] = gWorkerTE; order[3] = gPassTE;
        for (i = 0; i < 4; i++) if (order[i] == gActiveTE) { set_active(order[(i + 1) % 4]); break; }
    } else if (c == '\r' || c == 3) {
        if (gState == ST_STOPPED) do_connect();
    } else TEKey(c, gActiveTE);
    InvalRect(&gWin->portRect);
}

static void do_event(EventRecord *e)
{
    switch (e->what) {
    case mouseDown: do_mouse(e); break;
    case keyDown: case autoKey: do_key(e); break;
    case updateEvt:
        BeginUpdate((WindowPtr)e->message); draw_window(); EndUpdate((WindowPtr)e->message); break;
    }
}

int main(void)
{
    EventRecord e;
    init_ui();
    set_msg("");
    while (!gDone) {
        SystemTask();
        TEIdle(gActiveTE);
        if (gStream) pump_network();
        if (gState == ST_MINING) {
            mc_mine(&gSess, HASHES_PER_TICK);
            if (GetNextEvent(everyEvent, &e)) do_event(&e);
            if ((TickCount() & 15) == 0) InvalRect(&gWin->portRect);
        } else {
            if (WaitNextEvent(everyEvent, &e, 10, 0)) do_event(&e);
        }
    }
    tcp_close();
    if (gDnrOpen) DnrClose();
    return 0;
}
