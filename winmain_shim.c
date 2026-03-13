/*
 * winmain_shim.c — bridges MinGW's crtexewin.o startup (which calls WinMain) to
 * ServiceMain.c's wmain() entry point.
 *
 * With MXE's static G++ link, crtexewin.o is pulled in and expects WinMain.
 * __argc / __argv are set by the CRT before WinMain is called, so we can
 * forward directly to wmain() with the already-parsed argument vector.
 */
#include <windows.h>
#include <stdlib.h>  /* __argc, __argv */

extern int wmain(int argc, char *argv[]);

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow)
{
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nCmdShow;
    return wmain(__argc, __argv);
}
