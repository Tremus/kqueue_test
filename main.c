#define XHL_ALLOC_IMPL
#define XHL_FILES_IMPL
#define XHL_MATHS_IMPL

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
#include <xhl/maths.h>

enum FileEventType
{
    EVENT_FILE_CREATED,
    EVENT_FILE_DELETED,
    EVENT_FILE_CONTENTS_MODIFIED,
    EVENT_FILE_ATTRIBUTES_MODIFIED,

    // NOTE: Tracking "rename" events is rarely a useful feature for apps, and an absolute PITA to try and track using
    // the kqueue API, with a great risk of failure.
    // EVENT_FILE_MOVED,
};

// Note: path 1 is nonnull
// path 2 is NULL unless type == EVENT_FILE_MOVED
void cb_file_event(enum FileEventType type, const char* path_1)
{
    xassert(path_1);
    switch (type)
    {
    case EVENT_FILE_CREATED:
        printf("EVENT_FILE_CREATED: %s\n", path_1);
        break;
    case EVENT_FILE_DELETED:
        printf("EVENT_FILE_DELETED: %s\n", path_1);
        break;
    case EVENT_FILE_CONTENTS_MODIFIED:
        printf("EVENT_FILE_CONTENTS_MODIFIED: %s\n", path_1);
        break;
    case EVENT_FILE_ATTRIBUTES_MODIFIED:
        printf("EVENT_FILE_ATTRIBUTES_MODIFIED: %s\n", path_1);
        break;
        // case EVENT_FILE_MOVED:
        //     xassert(path_2);
        //     printf("EVENT_FILE_MOVED: %s > %s\n", path_1, path_2);
        //     break;
    }
}

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
    int  fd;
    bool is_dir;
    // path is stored in stringpool
    size_t stringpool_offset;
};

// https://man.freebsd.org/cgi/man.cgi?kqueue
struct Context
{
    struct kevent*      events;     // xarray
    struct WatchFolder* folders;    // xarray
    char*               stringpool; // xarray
};

typedef struct Stringpool
{
} Stringpool;

static size_t add_string(struct Context* ctx, const char* str, size_t len)
{
    size_t offset = xarr_len(ctx->stringpool);
    xassert((offset & 15) == 0);

    size_t nextlen = offset + len + 1; // +1 for '\0' byte
    nextlen        = xm_align_up(nextlen, 16);
    xassert((nextlen & 15) == 0);
    xarr_setlen(ctx->stringpool, nextlen);

    memcpy(ctx->stringpool + offset, str, len);
    ctx->stringpool[offset + len] = '\0';

    return offset;
}

bool check_is_directory(const char* path)
{
    bool        is_dir = false;
    struct stat info   = {0};
    if (stat(path, &info) == 0)
    {
        if (info.st_mode & S_IFDIR)
        {
            is_dir = true;
        }
    }
    return is_dir;
}

// TODO: add items to context array
void watch_path(struct Context* ctx, const char* path_)
{
    struct kevent      event;
    struct WatchFolder wf;

    wf.fd                = open(path_, O_EVTONLY);
    wf.is_dir            = check_is_directory(path_);
    wf.stringpool_offset = add_string(ctx, path_, strlen(path_));
    char* path           = ctx->stringpool + wf.stringpool_offset;
    xassert(path >= ctx->stringpool);
    if (wf.fd <= 0)
    {
        fprintf(stderr, "The file %s could not be opened for monitoring.  Error was %s.\n", path_, strerror(errno));
        exit(-1);
    }

    unsigned short flags = EV_ADD | EV_CLEAR;
    unsigned int fflags  = NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK | NOTE_RENAME | NOTE_REVOKE;
    event.ident          = wf.fd;
    event.filter         = EVFILT_VNODE;
    event.flags          = flags;
    event.fflags         = fflags;
    event.data           = 0;
    // Supposedly you're able to set a ptr here to whatever you want. It appears to be occasionally overwritten by
    // something in kevent(), so we can't really trust it...
    event.udata = path;

    xarr_push(ctx->events, event);
    xarr_push(ctx->folders, wf);

    size_t nevents  = xarr_len(ctx->events);
    size_t nfolders = xarr_len(ctx->folders);
    xassert(nevents == nfolders);

    printf("Watching: %s\n", path);
}

int find_path_by_string(struct Context* ctx, const char* path)
{
    int    i;
    size_t nevents  = xarr_len(ctx->events);
    size_t nfolders = xarr_len(ctx->folders);
    xassert(nevents == nfolders);
    for (i = 0; i < nfolders; i++)
    {
        struct WatchFolder* wf          = ctx->folders + i;
        const char*         cached_path = ctx->stringpool + wf->stringpool_offset;
        int                 match       = strcmp(path, cached_path);
        if (match == 0)
            return i;
    }
    return -1;
}

int find_path_by_fd(struct Context* ctx, int fd)
{
    int    i;
    size_t nevents  = xarr_len(ctx->events);
    size_t nfolders = xarr_len(ctx->folders);
    xassert(nevents == nfolders);
    for (i = 0; i < nfolders; i++)
    {
        struct kevent* e = ctx->events + i;
        if (e->ident == fd)
            return i;
    }
    return -1;
}

// void remove_watch(struct Context* ctx, const char* path)
void remove_watch_at_index(struct Context* ctx, int idx)
{
    if (idx != -1)
    {
        struct WatchFolder wf   = ctx->folders[idx];
        const char*        path = ctx->stringpool + wf.stringpool_offset;
        printf("Removing: %s\n", path);
        close(wf.fd);
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
        const char* path = ctx->stringpool + ctx->folders[i].stringpool_offset;
        remove_watch_at_index(ctx, i);
    }
    xarr_free(ctx->events);
    xarr_free(ctx->folders);
    xarr_free(ctx->stringpool);
};

void cb_on_direntry(void* data, const xfiles_list_item_t* item)
{
    const char* name    = item->path + item->name_idx;
    int         match_1 = strcmp(name, ".");
    int         match_2 = strcmp(name, "..");
    if (match_1 == 0 || match_2 == 0)
        return;

    struct Context* ctx = data;
    watch_path(ctx, item->path);

    if (item->is_dir)
    {
        xfiles_list(item->path, ctx, cb_on_direntry);
    }
}

void cb_poll_for_new_entries(void* data, const xfiles_list_item_t* item)
{
    const char* name    = item->path + item->name_idx;
    int         match_1 = strcmp(name, ".");
    int         match_2 = strcmp(name, "..");
    if (match_1 == 0 || match_2 == 0)
        return;

    struct Context* ctx = data;
    int             idx = find_path_by_string(ctx, item->path);
    if (idx == -1)
    {
        watch_path(ctx, item->path);
        cb_file_event(EVENT_FILE_CREATED, item->path);

        if (item->is_dir)
        {
            xfiles_list(item->path, ctx, cb_poll_for_new_entries);
        }
    }
}

int main()
{
    int            kq  = 0;
    struct Context ctx = {0};
    xalloc_init();
    ctx_init(&ctx);

    static const char* WATCH_ROOT_PATH = WATCH_DIR;

    watch_path(&ctx, WATCH_ROOT_PATH);
    xfiles_list(WATCH_ROOT_PATH, &ctx, cb_on_direntry);

    /* Set the timeout to wake us every half second. */
    struct timespec timeout;
    timeout.tv_sec    = 0;         // 0 seconds
    timeout.tv_nsec   = 500000000; // 500 milliseconds
    int continue_loop = 40;        /* Monitor for twenty seconds. */

    kq = kqueue();

    while (--continue_loop)
    {
        struct kevent event_data[69] = {0};
        size_t        nevents        = xarr_len(ctx.events);
        int           event_count    = kevent(kq, ctx.events, nevents, event_data, XFILES_ARRLEN(event_data), &timeout);

        if ((event_count < 0) || (event_data[0].flags == EV_ERROR))
        {
            /* An error occurred. */
            fprintf(stderr, "An error occurred (event count %d).  The error was %s.\n", event_count, strerror(errno));
            break;
        }
        if (event_count)
        {
            printf("%d new events\n", event_count);
            for (int i = 0; i < event_count; i++)
            {
                // NOTE: The control over the event loop with kevent is nice, but the info returned absolutely sucks.
                // There is no simple "file created" or "file deleted" event to respond to
                // If you create a folder in Finder, you get a NOTE_WRITE|NOTE_LINK event
                // If you move a folder to the Trash, you get a NOTE_WRITE|NOTE_LINK event...?
                // If you `rm -R` a folder, you get a NOTE_WRITE|NOTE_LINK event, not a NOTE_DELETE event???
                // kevents are effectively triggers for doing your own polling
                struct kevent* e = event_data + i;
                xassert(e->filter == EVFILT_VNODE);

                int cached_path_idx = find_path_by_fd(&ctx, e->ident);
                xassert(cached_path_idx != -1);

                const struct WatchFolder* wf                 = ctx.folders + cached_path_idx;
                const char*               ev_path            = ctx.stringpool + wf->stringpool_offset;
                bool                      previously_existed = cached_path_idx != -1;
                bool                      currently_exists   = xfiles_exists(ev_path);

                printf(
                    "Event %" PRIdPTR " occurred.  Filter %d, flags %d, filter flags %s, filter data %" PRIdPTR
                    ", path %s\n",
                    e->ident,
                    e->filter,
                    e->flags,
                    flagstring(e->fflags),
                    e->data,
                    ev_path);

                struct WatchFolder(*view_folders)[512] = (void*)ctx.folders;

                // Helpful table pulled from here:
                // https://github.com/segmentio/fs/blob/main/notify_darwin.go
                // | Condition                               | Events                   |
                // | --------------------------------------- | ------------------------ |
                // | creating a file in a directory          | NOTE_WRITE               |
                // | creating a directory in a directory     | NOTE_WRITE NOTE_LINK     |
                // | creating a link in a directory          | NOTE_WRITE               |
                // | creating a symlink in a directory       | NOTE_WRITE               |
                // | removing a file from a directory        | NOTE_WRITE               |
                // | removing a directory from a directory   | NOTE_WRITE NOTE_LINK     |
                // | renaming a file within a directory      | NOTE_WRITE               |
                // | renaming a directory within a directory | NOTE_WRITE               |
                // | moving a file out of a directory        | NOTE_WRITE               |
                // | moving a directory out of a directory   | NOTE_WRITE NOTE_LINK     |
                // | writing to a file                       | NOTE_WRITE NOTE_EXTEND   |
                // | truncating a file                       | NOTE_ATTRIB              |
                // | overwriting a symlink                   | NOTE_DELETE, NOTE_RENAME |

                if (previously_existed && !currently_exists)
                {

                    xassert(find_path_by_fd(&ctx, e->ident) != -1);

                    if (!wf->is_dir)
                    {
                        remove_watch_at_index(&ctx, cached_path_idx);
                        cb_file_event(EVENT_FILE_DELETED, ev_path);
                    }
                    else
                    {
                        // We don't get "rename" events for deleted/renamed directories contents, so we have to remove
                        // them from our data structure ourselves
                        int N = xarr_len(ctx.folders);
                        for (int j = N; j-- > 0;)
                        {
                            // if b is substring of a, remote item
                            const char* candidate_path = ctx.stringpool + ctx.folders[j].stringpool_offset;
                            const char* a              = ev_path;
                            const char* b              = candidate_path;
                            while (*a == *b && *a != 0 && *b != 0)
                            {
                                a++;
                                b++;
                            }

                            bool is_substring = *a == 0 && *b != 0;
                            if (is_substring)
                            {
                                xassert(!xfiles_exists(candidate_path));
                                remove_watch_at_index(&ctx, j);
                                cb_file_event(EVENT_FILE_DELETED, candidate_path);
                            }
                        }
                    }
                }

                if (previously_existed && currently_exists)
                {
                    bool is_dir = wf->is_dir;
                    if (is_dir)
                    {
                        // Dir was modified. A new file may have been added
                        xfiles_list(ev_path, &ctx, cb_poll_for_new_entries);
                    }

                    if (e->fflags & NOTE_WRITE)
                        cb_file_event(EVENT_FILE_CONTENTS_MODIFIED, ev_path);
                    if (e->fflags & NOTE_ATTRIB)
                        cb_file_event(EVENT_FILE_ATTRIBUTES_MODIFIED, ev_path);
                }
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