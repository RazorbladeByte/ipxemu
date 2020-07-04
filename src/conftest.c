/*
Author: Jelle Geerts

Usage of the works is permitted provided that this instrument is
retained with the works, so that any entity that uses the works is
notified of this instrument.

DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
*/

#include "targets/thipx32/thipx32.h"
#include "my_nspapi.h"
#include "my_wsipx.h"
#include "my_wsnwlink.h"
#include <stdio.h>
#include <stdlib.h>

#undef assert
#define assert(expr) (void)((expr) ? (void)0 : _assert(#expr, __FILE__, __LINE__))

static int one_or_more_tests_failed = 0;

static void _assert(const char *expr, const char *file, int line)
{
    fprintf(stderr, "Assertion failed: %s, file %s, line %d\n", expr, file,
            line);
    one_or_more_tests_failed = 1;
}

int main(void)
{
    assert(sizeof(unsigned short) == 2);
    assert(sizeof(unsigned int) == 4);

    /* my_wsipx.h */
    assert(sizeof(struct sockaddr_ipx) == 14);
    assert(sizeof(struct sockaddr_in) == 16);

    /* my_nspapi.h */
    assert(sizeof(PROTOCOL_INFO) == 32);

    /* my_wsnwlink.h */
    assert(sizeof(IPX_ADDRESS_DATA) == 24);

    /* thipx32.h */
    assert(sizeof(broadcast_signature_t) == 4);

    if (one_or_more_tests_failed) {
        fprintf(stderr, "One or more tests failed.\n");
        return EXIT_FAILURE;
    }

    printf("All tests succeeded.\n");
    return EXIT_SUCCESS;
}
