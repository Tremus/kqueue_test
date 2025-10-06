#define XHL_ALLOC_IMPL
#define XHL_FILES_IMPL

#define XARR_REALLOC xrealloc
#define XARR_FREE    xfree

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <xhl/alloc.h>
#include <xhl/array.h>
#include <xhl/debug.h>
#include <xhl/files.h>

/* A simple routine to return a string for a set of flags. */
char* flagstring(int flags)
{
    static char ret[512];
    char*       or = "";

    ret[0] = '\0'; // clear the string.
    if (flags & NOTE_DELETE)
    {
        strcat(ret, or);
        strcat(ret, "NOTE_DELETE");
        or = "|";
    }
    if (flags & NOTE_WRITE)
    {
        strcat(ret, or);
        strcat(ret, "NOTE_WRITE");
        or = "|";
    }
    if (flags & NOTE_EXTEND)
    {
        strcat(ret, or);
        strcat(ret, "NOTE_EXTEND");
        or = "|";
    }
    if (flags & NOTE_ATTRIB)
    {
        strcat(ret, or);
        strcat(ret, "NOTE_ATTRIB");
        or = "|";
    }
    if (flags & NOTE_LINK)
    {
        strcat(ret, or);
        strcat(ret, "NOTE_LINK");
        or = "|";
    }
    if (flags & NOTE_RENAME)
    {
        strcat(ret, or);
        strcat(ret, "NOTE_RENAME");
        or = "|";
    }
    if (flags & NOTE_REVOKE)
    {
        strcat(ret, or);
        strcat(ret, "NOTE_REVOKE");
        or = "|";
    }

    return ret;
}

// NOTE: kqueue and kevent don't watch items in subfolders folders, which means we have to walk through all the
// subdirectories and set up watch handlers ourselves.
// When we fetect new folders are created, we need to start watching them too, and when folders are
// deleted, we need to stop watching them and their subdirectories.
// When files are moved to the Trash on macOS, they may look like they're "renamed"

struct WatchFolder
{
    int   fd;
    char* path;
};

// https://man.freebsd.org/cgi/man.cgi?kqueue
struct Context
{
    struct kevent*      events;  // xarray
    struct WatchFolder* folders; // xarray
};

// TODO: add items to context array
void add_folder(struct Context* ctx, const char* path_)
{
    struct kevent event;
    size_t        pathlen = strlen(path_);

    struct WatchFolder wf;
    wf.path = xcalloc(1, pathlen + 1);

    strcpy(wf.path, path_);

    wf.fd = open(wf.path, O_EVTONLY);
    if (wf.fd <= 0)
    {
        fprintf(stderr, "The file %s could not be opened for monitoring.  Error was %s.\n", wf.path, strerror(errno));
        exit(-1);
    }

    unsigned short flags = EV_ADD | EV_CLEAR;
    unsigned int fflags  = NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK | NOTE_RENAME | NOTE_REVOKE;
    EV_SET(&event, wf.fd, EVFILT_VNODE, flags, fflags, 0, wf.path);

    xarr_push(ctx->events, event);
    xarr_push(ctx->folders, wf);

    size_t nevents  = xarr_len(ctx->events);
    size_t nfolders = xarr_len(ctx->folders);
    xassert(nevents == nfolders);
}

int find_folder(struct Context* ctx, const char* path)
{
    int    i;
    size_t nevents  = xarr_len(ctx->events);
    size_t nfolders = xarr_len(ctx->folders);
    xassert(nevents == nfolders);
    for (i = 0; i < nfolders; i++)
    {
        struct WatchFolder wf    = ctx->folders[i];
        int                match = strcmp(path, wf.path);
        if (match == 0)
            return i;
    }
    return -1;
}

void remove_folder(struct Context* ctx, const char* path)
{
    int idx = find_folder(ctx, path);
    if (idx != -1)
    {
        printf("Removing: %s\n", path);
        struct WatchFolder wf = ctx->folders[idx];
        close(wf.fd);
        xfree(wf.path);
        xarr_delete(ctx->events, idx);
        xarr_delete(ctx->folders, idx);
    }
}

void ctx_init(struct Context* ctx)
{
    xarr_setcap(ctx->events, 64);
    xarr_setlen(ctx->events, 0);
    xarr_setcap(ctx->folders, 64);
    xarr_setlen(ctx->folders, 0);
};

void ctx_deinit(struct Context* ctx)
{
    size_t nevents  = xarr_len(ctx->events);
    size_t nfolders = xarr_len(ctx->folders);
    for (int i = nevents; i-- > 0;)
    {
        const char* path = ctx->folders[i].path;
        remove_folder(ctx, path);
    }
    xarr_free(ctx->events);
    xarr_free(ctx->folders);
};

void cb_on_direntry(void* data, const xfiles_list_item_t* item)
{
    if (item->is_dir)
    {
        const char* name    = item->path + item->name_idx;
        int         match_1 = strcmp(name, ".");
        int         match_2 = strcmp(name, "..");
        if (match_1 == 0 || match_2 == 0)
            return;

        struct Context* ctx = data;
        add_folder(ctx, item->path);
        xfiles_list(item->path, ctx, cb_on_direntry);
    }
}

int main()
{
    int            kq  = 0;
    struct Context ctx = {0};
    xalloc_init();
    ctx_init(&ctx);

    add_folder(&ctx, WATCH_DIR);
    xfiles_list(WATCH_DIR, &ctx, cb_on_direntry);

    /* Set the timeout to wake us every half second. */
    struct timespec timeout;
    timeout.tv_sec    = 0;         // 0 seconds
    timeout.tv_nsec   = 500000000; // 500 milliseconds
    int continue_loop = 40;        /* Monitor for twenty seconds. */
    // int continue_loop = 120; // Monitor for one minute

    kq                           = kqueue();
    struct kevent event_data[69] = {0};

    while (--continue_loop)
    {
        size_t nevents     = xarr_len(ctx.events);
        int    event_count = kevent(kq, ctx.events, nevents, event_data, XFILES_ARRLEN(event_data), &timeout);

        if ((event_count < 0) || (event_data[0].flags == EV_ERROR))
        {
            /* An error occurred. */
            fprintf(stderr, "An error occurred (event count %d).  The error was %s.\n", event_count, strerror(errno));
            break;
        }
        if (event_count)
        {
            for (int i = 0; i < event_count; i++)
            {
                struct kevent* e = event_data + i;
                printf(
                    "Event %" PRIdPTR " occurred.  Filter %d, flags %d, filter flags %s, filter data %" PRIdPTR
                    ", path %s\n",
                    e->ident,
                    e->filter,
                    e->flags,
                    flagstring(e->fflags),
                    e->data,
                    (char*)e->udata);
                bool did_create = (e->fflags & NOTE_WRITE) && (e->fflags & NOTE_LINK);
                bool did_update = (e->fflags & NOTE_WRITE) && 0 == (e->fflags & NOTE_LINK);
            }
        }
        else
        {
            printf("No event.\n");
        }

        /* Reset the timeout.  In case of a signal interrruption, the
           values may change. */
        timeout.tv_sec  = 0;         // 0 seconds
        timeout.tv_nsec = 500000000; // 500 milliseconds
    }

    ctx_deinit(&ctx);
    xalloc_shutdown();
    return 0;
}

// int main()
// {
//     int             kq                   = 0;
//     int             event_fd             = 0;
//     struct kevent   events_to_monitor[1] = {0};
//     struct kevent   event_data[1]        = {0};
//     struct timespec timeout              = {0};
//     unsigned int    vnode_events         = 0;
//     char*           path                 = WATCH_DIR;

//     xalloc_init();

//     kq       = kqueue();
//     event_fd = open(path, O_EVTONLY);
//     if (event_fd <= 0)
//     {
//         fprintf(stderr, "The file %s could not be opened for monitoring.  Error was %s.\n", path, strerror(errno));
//         exit(-1);
//     }

//     /* Set the timeout to wake us every half second. */
//     timeout.tv_sec  = 0;         // 0 seconds
//     timeout.tv_nsec = 500000000; // 500 milliseconds

//     /* Set up a list of events to monitor. */
//     vnode_events = NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK | NOTE_RENAME | NOTE_REVOKE;
//     EV_SET(&events_to_monitor[0], event_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, vnode_events, 0, path);

//     int continue_loop = 40; /* Monitor for twenty seconds. */
//     while (--continue_loop)
//     {
//         int event_count = kevent(
//             kq,
//             events_to_monitor,
//             XFILES_ARRLEN(events_to_monitor),
//             event_data,
//             XFILES_ARRLEN(event_data),
//             &timeout);
//         if ((event_count < 0) || (event_data[0].flags == EV_ERROR))
//         {
//             /* An error occurred. */
//             fprintf(stderr, "An error occurred (event count %d).  The error was %s.\n", event_count,
//             strerror(errno)); break;
//         }
//         if (event_count)
//         {
//             printf(
//                 "Event %" PRIdPTR " occurred.  Filter %d, flags %d, filter flags %s, filter data %" PRIdPTR
//                 ", path %s\n",
//                 event_data[0].ident,
//                 event_data[0].filter,
//                 event_data[0].flags,
//                 flagstring(event_data[0].fflags),
//                 event_data[0].data,
//                 (char*)event_data[0].udata);
//         }
//         else
//         {
//             printf("No event.\n");
//         }

//         /* Reset the timeout.  In case of a signal interrruption, the
//            values may change. */
//         timeout.tv_sec  = 0;         // 0 seconds
//         timeout.tv_nsec = 500000000; // 500 milliseconds
//     }
//     printf("exit loop");
//     close(event_fd);

//     xalloc_shutdown();

//     return 0;
// }
