/* Minimal MacTCP Domain Name Resolver glue (original code; behaviour follows
 * Apple's documented 'dnrp' resource interface).  UNVERIFIED on real MacTCP. */
#ifndef DNR_H
#define DNR_H
#include <MacTypes.h>

#define DNR_NUM_ALT_ADDRS 4

typedef struct DnrHostInfo {
    long           rtnCode;
    char           cname[256];
    unsigned short addrType;
    unsigned short addrLen;
    unsigned long  addr[DNR_NUM_ALT_ADDRS];
} DnrHostInfo;

OSErr DnrOpen(void);
OSErr DnrClose(void);
/* Blocking resolve of a C-string hostname.  Calls SystemTask while waiting. */
OSErr DnrResolve(const char *host, unsigned long *ip);
#endif
