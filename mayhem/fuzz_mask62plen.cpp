// Ported from the legacy mayhemheroes/tcpdump integration: feeds a 16-byte IPv6 netmask to
// libnetdissect's mask62plen() (util-print.c), which OLSR's HNA6 printer calls on wire data.
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

extern "C" int mask62plen(const u_char *);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // mask62plen() reads exactly 16 bytes (an IPv6 address-sized mask, netdissect.h); shorter inputs
    // are outside its contract (the legacy harness read uninitialised heap for them).
    if (size < 16)
        return -1;
    u_char mask[16];
    memcpy(mask, data, sizeof(mask));
    mask62plen(mask);
    return 0;
}
