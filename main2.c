#define XHL_FILES_IMPL

#include <signal.h>
#include <stdio.h>
#include <xhl/debug.h>
#include <xhl/files.h>

int  g_running = 1;
void ctrl_c_callback(int code)
{
    fprintf(stderr, "Terminating\n");
    g_running = 0;
}

int my_cb(enum XFILES_WATCH_TYPE type, const char* path, void* udata)
{
    switch (type)
    {
    case XFILES_WATCH_CONTINUE:
        fprintf(stderr, "Continue %s\n", path);
        break;
    case XFILES_WATCH_CREATED:
        fprintf(stderr, "Created %s\n", path);
        break;
    case XFILES_WATCH_DELETED:
        fprintf(stderr, "Deleted %s\n", path);
        break;
    case XFILES_WATCH_MODIFIED:
        fprintf(stderr, "Modified %s\n", path);
        break;
    }
    return g_running;
}

int main()
{
    fprintf(stderr, "Press Crtl+C to exit\n");
    g_running = 1;
    signal(SIGINT, ctrl_c_callback);

    xfiles_watch(WATCH_DIR, 50, NULL, my_cb);

    return 0;
}