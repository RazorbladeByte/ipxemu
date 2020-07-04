/*
Author: Jelle Geerts

Usage of the works is permitted provided that this instrument is
retained with the works, so that any entity that uses the works is
notified of this instrument.

DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
*/

#ifndef CONFIRM_H
#define CONFIRM_H

#ifdef _WIN32
# include <tchar.h>
#else /* !defined(_WIN32) */
typedef char TCHAR;
#endif /* !defined(_WIN32) */

enum {
    CONFIRM_UNDEFINED,
    CONFIRM_ERROR,
    CONFIRM_NO,
    CONFIRM_YES
};

int confirm(int default_answer, int *default_answer_used,
        const TCHAR *fmt, ...);

#endif /* !defined(CONFIRM_H) */
