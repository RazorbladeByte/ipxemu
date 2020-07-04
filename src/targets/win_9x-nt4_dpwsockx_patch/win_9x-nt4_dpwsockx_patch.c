/*
Author: Jelle Geerts

Usage of the works is permitted provided that this instrument is
retained with the works, so that any entity that uses the works is
notified of this instrument.

DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
*/

#include "resource_ids.h"
#include <windows.h>
#include <tchar.h>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#define DPWSOCKX_ESUCCESS      0
#define DPWSOCKX_EOPEN         1
#define DPWSOCKX_EIO           2
#define DPWSOCKX_EUNRECOGNIZED 3

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* Large enough to hold a message plus a filename. */
#define MSG_BUF_SIZE (MAX_PATH + 256)

#define DLL_WITH_SLASH TEXT("\\dpwsockx.dll")
static TCHAR dpwsockx_filename[MAX_PATH + sizeof(DLL_WITH_SLASH)];

static const char dpwsockx_orig_data[] = "\0\0WSOCK32.dll\0";
static const char dpwsockx_patch_data[] = "\0\0ipxemuw.dll\0";
static size_t dpwsockx_data_size = sizeof(dpwsockx_orig_data) - 1;

static int cmpistr(const char *s1, const char *s2)
{
    int c1, c2;
    if (s1 == s2)
        return 0;
    while (c1 = tolower(*s1++), c2 = tolower(*s2++), c1 && c1 == c2)
        ;
    return c1-c2 < 0 ? -1 : c1-c2 > 0 ? 1 : 0;
}

static void *file_read_all(FILE *fp, unsigned long *fsize)
{
    int ok = 0;
    unsigned long l_fsize;
    void *buf = NULL;

    if (fseek(fp, 0, SEEK_END))
        goto done;
    l_fsize = ftell(fp);
    if ((signed)l_fsize == -1L)
        goto done;
    if (fseek(fp, 0, SEEK_SET))
        goto done;

    buf = malloc(l_fsize);
    if (!buf)
        goto done;
    if (fread(buf, 1, l_fsize, fp) != l_fsize)
        goto done;

    if (fsize)
        *fsize = l_fsize;

    ok = 1;

done:
    if (!ok && buf) {
        free(buf);
        buf = NULL;
    }
    return buf;
}

static int dpwsockx_get_info(int *error, const TCHAR *filename,
    unsigned long *offset)
{
    int is_patched = 0;
    FILE *fp = NULL;
    char *buf = NULL;
    unsigned long patch_offset = -1UL;
    unsigned long fsize;
    unsigned long i;

    *error = DPWSOCKX_ESUCCESS;

    fp = fopen(filename, "rb");
    if (!fp) {
        *error = DPWSOCKX_EOPEN;
        goto done;
    }

    buf = file_read_all(fp, &fsize);
    if (!buf) {
        *error = DPWSOCKX_EIO;
        goto done;
    }

    for (i = 0; i < fsize; ++i) {
        int is_orig;

        is_orig = 1;
        is_patched = 1;

        if (is_orig && buf[i] != dpwsockx_orig_data[0])
            is_orig = 0;
        if (is_orig && buf[i + 1] != dpwsockx_orig_data[1])
            is_orig = 0;
        if (is_orig && cmpistr(&buf[i + 2], &dpwsockx_orig_data[2]) != 0)
            is_orig = 0;
        if (is_orig && buf[i + 13] != dpwsockx_orig_data[13])
            is_orig = 0;

        if (is_patched && buf[i] != dpwsockx_patch_data[0])
            is_patched = 0;
        if (is_patched && buf[i + 1] != dpwsockx_patch_data[1])
            is_patched = 0;
        if (is_patched && cmpistr(&buf[i + 2], &dpwsockx_patch_data[2]) != 0)
            is_patched = 0;
        if (is_patched && buf[i + 13] != dpwsockx_patch_data[13])
            is_patched = 0;

        if (!is_orig && !is_patched)
            continue;

        patch_offset = i;
        break;
    }
    if (patch_offset == -1UL) {
        *error = DPWSOCKX_EUNRECOGNIZED;
        goto done;
    }

    if (offset)
        *offset = patch_offset;

done:
    if (buf)
        free(buf);
    if (fp)
        fclose(fp);
    return is_patched;
}

static const TCHAR *dpwsockx_get_error(int error, const TCHAR *filename)
{
    static TCHAR msg[MSG_BUF_SIZE];

    switch (error) {
    case DPWSOCKX_EOPEN:
        _tcscpy(msg, TEXT("Failed to open `"));
        _tcscat(msg, filename);
        _tcscat(msg, TEXT("' (file not found or access denied)."));
        break;

    case DPWSOCKX_EIO:
        _tcscpy(msg, TEXT("Error while performing I/O operation on `"));
        _tcscat(msg, filename);
        _tcscat(msg, TEXT("'."));
        break;

    case DPWSOCKX_EUNRECOGNIZED:
        _tcscpy(msg, TEXT("Unrecognized version of `"));
        _tcscat(msg, filename);
        _tcscat(msg, TEXT("'."));
        break;

    default:
        return NULL;
    }

    return msg;
}

static int dpwsockx_patch(int *error, const TCHAR *filename, int patch)
{
    int ret = 0;
    FILE *fp = NULL;
    int is_patched;
    unsigned long patch_offset;
    TCHAR msgbuf[MSG_BUF_SIZE];
    const TCHAR *msg = msgbuf;
    int have_msg = 0;

    *error = DPWSOCKX_ESUCCESS;

    /* Get info again, don't rely on earlier retrieved info to still be
     * correct.
     */
    is_patched = dpwsockx_get_info(error, filename, &patch_offset);
    if (*error != DPWSOCKX_ESUCCESS) {
        goto done;
    } else if (patch == is_patched) {
        _tcscpy(msgbuf, TEXT("`"));
        _tcscat(msgbuf, filename);
        _tcscat(msgbuf, TEXT("' is already "));
        _tcscat(msgbuf, is_patched ? TEXT("patched.") : TEXT("restored."));
        have_msg = 1;
    } else {
        fp = fopen(filename, "rb+");
        if (!fp) {
            _tcscpy(msgbuf, TEXT("Failed to open `"));
            _tcscat(msgbuf, filename);
            _tcscat(msgbuf, TEXT("' for writing (file not found or access denied)."));
            have_msg = 1;

            *error = DPWSOCKX_EOPEN;
            goto done;
        }

        if (fseek(fp, patch_offset, SEEK_SET)) {
            *error = DPWSOCKX_EIO;
            goto done;
        }

        if (fwrite(patch ? dpwsockx_patch_data : dpwsockx_orig_data,
                    1, dpwsockx_data_size, fp) != dpwsockx_data_size) {
            *error = DPWSOCKX_EIO;
            goto done;
        }

        _tcscpy(msgbuf, TEXT("`"));
        _tcscat(msgbuf, filename);
        _tcscat(msgbuf, TEXT("' successfully "));
        _tcscat(msgbuf, patch ? TEXT("patched.") : TEXT("restored."));
        have_msg = 1;
    }

    ret = 1;

done:
    if (fp)
        fclose(fp);
    if (!have_msg) {
        msg = dpwsockx_get_error(*error, filename);
        if (!msg) {
            assert(0);
            _tcscpy(msgbuf, TEXT("Failed to patch `"));
            _tcscat(msgbuf, filename);
            _tcscat(msgbuf, TEXT("' (unknown error)."));
            msg = msgbuf;
        }
    }
    (void)MessageBox(NULL, msg, ret ? TEXT("Success") : NULL,
            (ret ? MB_ICONINFORMATION : MB_ICONSTOP) | MB_OK);
    return ret;
}

static void set_status(HWND hwndStatus)
{
    int patched;
    int error;
    const TCHAR *t = NULL;

    patched = dpwsockx_get_info(&error, dpwsockx_filename, NULL);
    if (error != DPWSOCKX_ESUCCESS) {
        t = dpwsockx_get_error(error, TEXT("dpwsockx.dll"));
    } else {
        t = patched ?
            TEXT("`dpwsockx.dll' is already patched.") :
            TEXT("`dpwsockx.dll' is not yet patched.");
    }

    assert(t);
    (void)SetWindowText(hwndStatus, t);
}

static void edit_ctrl_append(HWND hwndEdit, const TCHAR *text)
{
    int len;

    len = GetWindowTextLength(hwndEdit);
    (void)SendMessage(hwndEdit, EM_SETSEL, len, len);
    (void)SendMessage(hwndEdit, EM_REPLACESEL, FALSE, (LPARAM)text);
}

static int is_windows_millenium_edition(void)
{
    OSVERSIONINFO info;

    info.dwOSVersionInfoSize = sizeof(info);
    if (!GetVersionEx(&info))
        return -1;

    return info.dwMajorVersion == 4 && info.dwMinorVersion == 90;
}

static int is_safe_mode_on(void)
{
    return GetSystemMetrics(SM_CLEANBOOT) != 0;
}

static INT_PTR CALLBACK dialog_proc(HWND hwndDlg, UINT uMsg, WPARAM wParam,
        LPARAM lParam)
{
    (void)lParam;

    switch (uMsg) {
    case WM_INITDIALOG:
        edit_ctrl_append(GetDlgItem(hwndDlg, DLG_INFO),
                TEXT("\
This program patches `dpwsockx.dll' (in the system directory, usually\r\n\
`%windir%\\system') so that it loads `ipxemuw.dll' instead of `wsock32.dll'.\r\n\
\r\n\
After patching the `dpwsockx.dll' library, one should manually copy the ipxemu\r\n\
`wsock32.dll' library, rename it to `ipxemuw.dll', and put it in the same\r\n"));
        edit_ctrl_append(GetDlgItem(hwndDlg, DLG_INFO),
                TEXT("\
directory as the game executable. Or, if one so desires, one can put\r\n\
`ipxemuw.dll' in the system directory (the directory where `dpwsockx.dll'\r\n\
resides); it won't cause problems as only the patched `dpwsockx.dll' will use\r\n\
the `ipxemuw.dll' library.\r\n"));
        edit_ctrl_append(GetDlgItem(hwndDlg, DLG_INFO),
                TEXT("\
\r\n\
The patch is needed to make games that use DirectPlay for IPX work on\r\n\
Windows 9x and Windows NT4. Because when the DirectPlay IPX socket library\r\n\
`dpwsockx.dll' is loaded, Windows 9x and Windows NT4 first look in the\r\n\
directory of that library to find `wsock32.dll', instead of looking in the\r\n\
directory of the caller process (the game) executable. Hence, instead of the\r\n\
ipxemu `wsock32.dll' library, the system `wsock32.dll' library will be loaded."));

        set_status(GetDlgItem(hwndDlg, DLG_STATUS));

        SetFocus(GetDlgItem(hwndDlg, IDCANCEL));
        return FALSE;

    case WM_COMMAND: {
        int id = LOWORD(wParam);

        switch (id) {
        case DLG_PATCH:
        case DLG_RESTORE: {
            int error;
            int patch = id == DLG_PATCH;
            int ok = 1;

            /* Clear status so it cannot contradict the message shown by
             * dpwsockx_patch(), as the user might not immediately close the
             * message box.
             */
            (void)SetWindowText(GetDlgItem(hwndDlg, DLG_STATUS), "");

            /* Check for Windows Me. Windows Me protects system files by
             * restoring them when modified. System-file protection is turned
             * off in safe mode, so suggest the user to reboot in safe mode.
             */
            if (patch &&
                    is_windows_millenium_edition() == 1 &&
                    !is_safe_mode_on()) {
                if (MessageBox(hwndDlg,
                            TEXT(
"Windows Millenium Edition was detected. You should restart Windows in safe "
"mode and perform the patch there, otherwise Windows will restore the "
"original `dpwsockx.dll' library. It is not recommended to continue. Continue "
"anyway? (You should probably choose No.)"),
                            TEXT("Please restart Windows in safe mode"),
                            MB_ICONSTOP | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
                    ok = 0;
                }
            }

            if (ok)
                (void)dpwsockx_patch(&error, dpwsockx_filename, patch);

            set_status(GetDlgItem(hwndDlg, DLG_STATUS));

            break;
        }

        case IDCANCEL: /* Escape key or cancel button. */
            (void)SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;

        default:
            break;
        }
        return 0;
    }

    case WM_CLOSE:
        (void)EndDialog(hwndDlg, 1);
        return 0;

    default:
        break;
    }

    return FALSE;
}

int main(void)
{
    int ret;

    if (!GetSystemDirectory(dpwsockx_filename,
                ARRAY_SIZE(dpwsockx_filename) -
                (sizeof(DLL_WITH_SLASH) - sizeof(dpwsockx_filename[0])))) {
        (void)MessageBox(NULL,
                TEXT("Could not retrieve system directory path."), NULL,
                MB_ICONSTOP | MB_OK);
        return EXIT_FAILURE;
    }
    _tcscat(dpwsockx_filename, DLL_WITH_SLASH);

    ret = DialogBoxParam(NULL, MAKEINTRESOURCE(DLG),
            NULL, dialog_proc, (LPARAM)NULL);
    if (ret == 0 || ret == -1) {
        assert(0);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
