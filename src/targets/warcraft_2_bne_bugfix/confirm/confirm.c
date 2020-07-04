/*
Author: Jelle Geerts

Usage of the works is permitted provided that this instrument is
retained with the works, so that any entity that uses the works is
notified of this instrument.

DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
*/

#include "confirm.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* We need _vftprintf() for portability. It is an alias to either the ANSI or
 * wide-character version of vfprintf(). On Unices, `confirm.h' defines TCHAR
 * as simply `char'. Therefore, it is safe to alias `_vftprintf' to `vfprintf'
 * on Unices.
 */
#ifndef _WIN32
# define _vftprintf vfprintf
#endif /* !defined(_WIN32) */

static int cmpistr(const char *s1, const char *s2)
{
    int c1, c2;
    if (s1 == s2)
        return 0;
    while (c1 = tolower(*s1++), c2 = tolower(*s2++), c1 && c1 == c2)
        ;
    return c1-c2 < 0 ? -1 : c1-c2 > 0 ? 1 : 0;
}

static int interpret_answer(const char *input, int default_answer,
        int *default_answer_used)
{
    char answer;

    if (default_answer_used)
        *default_answer_used = 0;

    answer = input[0];
    if (cmpistr(input, "y\n") == 0 || cmpistr(input, "yes\n") == 0)
        return CONFIRM_YES;
    else if (cmpistr(input, "n\n") == 0 || cmpistr(input, "no\n") == 0)
        return CONFIRM_NO;
    else if (answer == '\n')
    {
        if (default_answer_used)
            *default_answer_used = 1;
        return default_answer;
    }

    return CONFIRM_UNDEFINED;
}

static int read_stdin_until_newline(void)
{
    for (;;)
    {
        int c;

        c = getchar();
        if (c == EOF)
            return 0;
        else if (c == '\n')
            return 1;
    }
}

/* Displays a message, appends the valid input range ('[y/n]'), and appends a
 * newline.
 *
 * Parameters:
 *   default_answer [in]
 *     The default answer. Used if and only if the user enters RETURN. Specify
 *     CONFIRM_UNDEFINED to require the user to manually enter the answer (in
 *     which case entering RETURN has no effect).
 *   default_answer_used [in, optional]
 *     A pointer to a variable that is set to 1 or 0 depending on whether the
 *     default answer is used. If this parameter is a null pointer, it is
 *     ignored.
 *   fmt [in]
 *     See printf().
 *   ... [in]
 *     See printf().
 *
 * Returns:
 *   If the function succeeds, the return value is one of the CONFIRM_*
 *   constants except CONFIRM_ERROR.
 *   If the function fails, the return value is CONFIRM_ERROR.
 *
 * Remarks:
 *   The user has to supply valid input. The input must be either:
 *       - RETURN (unless CONFIRM_UNDEFINED was specified for `default_answer')
 *       - Y or YES (both case insensitive)
 *       - N or NO (both case insensitive)
 *
 *   If RETURN is entered, 'default_answer' is returned. The input
 *   validation is case-insensitive.
 *
 *   If invalid input is entered, the confirmation message is repeated.
 */
int confirm(int default_answer, int *default_answer_used,
        const TCHAR *fmt, ...)
{
    char input[5];
    va_list ap;

    for (;;)
    {
        int answer;

        va_start(ap, fmt);
        _vftprintf(stdout, fmt, ap);
        va_end(ap);
        if (default_answer == CONFIRM_YES)
            printf(" [yes]\n");
        else if (default_answer == CONFIRM_NO)
            printf(" [no]\n");
        else
            printf(" [yes or no]\n");

        if (!fgets(input, sizeof input, stdin))
            return CONFIRM_ERROR;

        answer = interpret_answer(input, default_answer, default_answer_used);
        if (answer == CONFIRM_YES || answer == CONFIRM_NO)
            return answer;

        /* Discard invalid input if necessary. */
        if (!strchr(input, '\n'))
        {
            /* No newline read yet, there must still be one in the buffer,
             * unless an end-of-file error occurred and no newline was read.
             * So, discard all the invalid data by reading it.
             */
            if (!read_stdin_until_newline())
                return CONFIRM_ERROR;
        }
    }

    /* NOTREACHED */
}

#ifdef TEST
# ifdef NDEBUG
#  error "Compile without NDEBUG defined."
# endif /* defined(NDEBUG) */

#include <assert.h>
#include <stdlib.h>

int main(void)
{
    assert(interpret_answer("\n", CONFIRM_YES, NULL) == CONFIRM_YES);
    assert(interpret_answer("\n", CONFIRM_NO, NULL) == CONFIRM_NO);

    assert(interpret_answer("n\n", CONFIRM_YES, NULL) == CONFIRM_NO);
    assert(interpret_answer("N\n", CONFIRM_YES, NULL) == CONFIRM_NO);
    assert(interpret_answer("No\n", CONFIRM_YES, NULL) == CONFIRM_NO);
    assert(interpret_answer("nO\n", CONFIRM_YES, NULL) == CONFIRM_NO);

    assert(interpret_answer("y\n", CONFIRM_NO, NULL) == CONFIRM_YES);
    assert(interpret_answer("Y\n", CONFIRM_NO, NULL) == CONFIRM_YES);
    assert(interpret_answer("Yes\n", CONFIRM_NO, NULL) == CONFIRM_YES);
    assert(interpret_answer("yES\n", CONFIRM_NO, NULL) == CONFIRM_YES);

    assert(interpret_answer("Noo\n", CONFIRM_YES, NULL) == CONFIRM_UNDEFINED);
    assert(interpret_answer("Yess\n", CONFIRM_NO, NULL) == CONFIRM_UNDEFINED);

    printf("confirm() = %d\n",
            confirm(CONFIRM_UNDEFINED, NULL, "foo %s?", "bar"));

    printf("All tests succeeded.\n");
    return EXIT_SUCCESS;
}

#endif /* !defined(TEST) */
