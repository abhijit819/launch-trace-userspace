/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include "launchtrace_uapi.h"

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_DEVICE "/dev/launchtrace"
#define DEFAULT_DB     "/var/lib/launchtrace/patterns.ltdb"
#define DEFAULT_READ_BUFFER (16U * 1024U * 1024U)
#define MAX_DB_BYTES   ((uint64_t)2 * 1024 * 1024 * 1024)

struct db_entry {
    uint8_t *blob;
    size_t len;
    uint64_t pattern_id;
};

struct database {
    struct db_entry *entries;
    size_t count;
    size_t capacity;
};

static volatile sig_atomic_t stop_requested;

static void on_signal(int signo)
{
    (void)signo;
    stop_requested = 1;
}

static void usage(FILE *f)
{
    fprintf(f,
        "Usage:\n"
        "  launchtraced daemon [--device PATH] [--db PATH] [--buffer-size BYTES]\n"
        "  launchtraced set-max-apps N [--device PATH]\n"
        "  launchtraced start [--device PATH]\n"
        "  launchtraced stop [--device PATH]\n"
        "\n"
        "Run 'daemon' before starting recording. The daemon remains alive across\n"
        "STOP/START cycles and persists each completed pattern before ACKing it.\n");
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) { errno = EIO; return -1; }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) { errno = EIO; return -1; }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static uint32_t get_le32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return le32toh(v);
}

static uint64_t get_le64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return le64toh(v);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    v = htole32(v);
    memcpy(p, &v, sizeof(v));
}

static void put_le64(uint8_t *p, uint64_t v)
{
    v = htole64(v);
    memcpy(p, &v, sizeof(v));
}

/* Validate the kernel's serialized pattern and extract its pattern ID. */
static int validate_pattern(const uint8_t *b, size_t len, uint64_t *pattern_id)
{
    uint32_t path_len, device_count, total_records;
    size_t off;
    uint64_t seen_records = 0;

    if (len < LT_WIRE_HEADER_BYTES) { errno = EPROTO; return -1; }
    if (get_le32(b + 0) != LT_WIRE_MAGIC ||
        get_le32(b + 4) != LT_WIRE_VERSION ||
        get_le32(b + 8) != LT_WIRE_HEADER_BYTES) {
        errno = EPROTO;
        return -1;
    }

    *pattern_id = get_le64(b + 16);
    path_len = get_le32(b + 48);
    device_count = get_le32(b + 52);
    total_records = get_le32(b + 56);

    if ((uint64_t)LT_WIRE_HEADER_BYTES + path_len > len) {
        errno = EPROTO; return -1;
    }
    off = LT_WIRE_HEADER_BYTES + (size_t)path_len;

    for (uint32_t d = 0; d < device_count; d++) {
        uint32_t nr;
        size_t bytes;
        if (off > len || len - off < LT_WIRE_DEVICE_BYTES) {
            errno = EPROTO; return -1;
        }
        nr = get_le32(b + off + 8);
        off += LT_WIRE_DEVICE_BYTES;
        if ((uint64_t)nr * LT_WIRE_RECORD_BYTES > SIZE_MAX) {
            errno = EOVERFLOW; return -1;
        }
        bytes = (size_t)nr * LT_WIRE_RECORD_BYTES;
        if (off > len || len - off < bytes) {
            errno = EPROTO; return -1;
        }
        off += bytes;
        seen_records += nr;
    }
    if (off != len || seen_records != total_records || *pattern_id == 0) {
        errno = EPROTO; return -1;
    }
    return 0;
}

static void db_free(struct database *db)
{
    for (size_t i = 0; i < db->count; i++) free(db->entries[i].blob);
    free(db->entries);
    memset(db, 0, sizeof(*db));
}

static ssize_t db_find(const struct database *db, uint64_t id)
{
    for (size_t i = 0; i < db->count; i++)
        if (db->entries[i].pattern_id == id) return (ssize_t)i;
    return -1;
}

static int db_add(struct database *db, const uint8_t *blob, size_t len,
                  uint64_t id)
{
    struct db_entry *e;
    if (db_find(db, id) >= 0) return 0; /* at-least-once delivery: idempotent */
    if (db->count == db->capacity) {
        size_t cap = db->capacity ? db->capacity * 2 : 16;
        if (cap < db->capacity || cap > SIZE_MAX / sizeof(*e)) {
            errno = EOVERFLOW; return -1;
        }
        e = realloc(db->entries, cap * sizeof(*e));
        if (!e) return -1;
        db->entries = e;
        db->capacity = cap;
    }
    e = &db->entries[db->count];
    e->blob = malloc(len);
    if (!e->blob) return -1;
    memcpy(e->blob, blob, len);
    e->len = len;
    e->pattern_id = id;
    db->count++;
    return 1;
}

static int db_load(const char *path, struct database *db)
{
    int fd;
    struct stat st;
    uint8_t hdr[LT_DB_HEADER_BYTES];
    uint64_t count;

    memset(db, 0, sizeof(*db));
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    if (fstat(fd, &st) < 0) goto fail;
    if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(hdr) ||
        (uint64_t)st.st_size > MAX_DB_BYTES) {
        errno = EINVAL; goto fail;
    }
    if (read_all(fd, hdr, sizeof(hdr)) < 0) goto fail;
    if (memcmp(hdr, LT_DB_MAGIC, LT_DB_MAGIC_BYTES) != 0 ||
        get_le32(hdr + 8) != LT_DB_VERSION ||
        get_le32(hdr + 12) != LT_DB_HEADER_BYTES) {
        errno = EPROTO; goto fail;
    }
    count = get_le64(hdr + 16);
    if (count > (uint64_t)(st.st_size / LT_DB_ENTRY_HEADER_BYTES)) {
        errno = EPROTO; goto fail;
    }
    for (uint64_t i = 0; i < count; i++) {
        uint8_t eh[LT_DB_ENTRY_HEADER_BYTES];
        uint64_t blob_len;
        uint8_t *blob;
        uint64_t id;
        if (read_all(fd, eh, sizeof(eh)) < 0) goto fail;
        blob_len = get_le64(eh);
        if (blob_len < LT_WIRE_HEADER_BYTES || blob_len > MAX_DB_BYTES ||
            blob_len > SIZE_MAX) { errno = EPROTO; goto fail; }
        blob = malloc((size_t)blob_len);
        if (!blob) goto fail;
        if (read_all(fd, blob, (size_t)blob_len) < 0) {
            free(blob); goto fail;
        }
        if (validate_pattern(blob, (size_t)blob_len, &id) < 0) {
            free(blob); goto fail;
        }
        if (db_add(db, blob, (size_t)blob_len, id) < 0) {
            free(blob); goto fail;
        }
        free(blob);
    }
    {
        uint8_t extra;
        ssize_t n = read(fd, &extra, 1);
        if (n != 0) { errno = (n < 0 ? errno : EPROTO); goto fail; }
    }
    close(fd);
    return 0;
fail:
    {
        int saved = errno;
        close(fd);
        db_free(db);
        errno = saved;
        return -1;
    }
}

static int fsync_parent_dir(const char *path)
{
    char *copy = strdup(path);
    char *slash;
    int fd, rc, saved;
    if (!copy) return -1;
    slash = strrchr(copy, '/');
    if (!slash) {
        free(copy);
        fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } else {
        if (slash == copy) slash[1] = '\0';
        else *slash = '\0';
        fd = open(copy, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        free(copy);
    }
    if (fd < 0) return -1;
    rc = fsync(fd);
    saved = errno;
    close(fd);
    errno = saved;
    return rc;
}

static int db_save_atomic(const char *path, const struct database *db)
{
    size_t path_len = strlen(path);
    char *tmp;
    uint8_t hdr[LT_DB_HEADER_BYTES] = {0};
    int fd = -1, rc = -1, saved;

    if (path_len > PATH_MAX - 64) { errno = ENAMETOOLONG; return -1; }
    tmp = malloc(path_len + 48);
    if (!tmp) return -1;
    snprintf(tmp, path_len + 48, "%s.tmp.%ld", path, (long)getpid());
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) goto out;

    memcpy(hdr, LT_DB_MAGIC, LT_DB_MAGIC_BYTES);
    put_le32(hdr + 8, LT_DB_VERSION);
    put_le32(hdr + 12, LT_DB_HEADER_BYTES);
    put_le64(hdr + 16, db->count);
    if (write_all(fd, hdr, sizeof(hdr)) < 0) goto out;

    for (size_t i = 0; i < db->count; i++) {
        uint8_t eh[LT_DB_ENTRY_HEADER_BYTES];
        put_le64(eh, db->entries[i].len);
        if (write_all(fd, eh, sizeof(eh)) < 0 ||
            write_all(fd, db->entries[i].blob, db->entries[i].len) < 0)
            goto out;
    }
    if (fsync(fd) < 0) goto out;
    if (close(fd) < 0) { fd = -1; goto out; }
    fd = -1;
    if (rename(tmp, path) < 0) goto out;
    if (fsync_parent_dir(path) < 0) goto out;
    rc = 0;
out:
    saved = errno;
    if (fd >= 0) close(fd);
    if (rc < 0) unlink(tmp);
    free(tmp);
    errno = saved;
    return rc;
}

static int ensure_db_parent(const char *path)
{
    char *copy = strdup(path), *slash;
    struct stat st;
    if (!copy) return -1;
    slash = strrchr(copy, '/');
    if (!slash) { free(copy); return 0; }
    if (slash == copy) slash[1] = '\0';
    else *slash = '\0';
    if (stat(copy, &st) < 0) {
        int e = errno;
        free(copy);
        errno = e;
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) { free(copy); errno = ENOTDIR; return -1; }
    free(copy);
    return 0;
}

static int daemon_run(const char *device, const char *db_path, size_t buf_size)
{
    struct database db;
    struct pollfd pfd;
    uint8_t *buf = NULL;
    int fd = -1, rc = 1;

    if (ensure_db_parent(db_path) < 0) {
        fprintf(stderr, "database directory must already exist: %s: %s\n",
                db_path, strerror(errno));
        return 1;
    }
    if (db_load(db_path, &db) < 0) {
        fprintf(stderr, "cannot load database %s: %s\n", db_path, strerror(errno));
        return 1;
    }
    buf = malloc(buf_size);
    if (!buf) { perror("malloc read buffer"); goto out; }
    fd = open(device, O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { perror(device); goto out; }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    pfd.fd = fd;
    pfd.events = POLLIN;
    fprintf(stderr, "LaunchTrace daemon: device=%s database=%s patterns=%zu\n",
            device, db_path, db.count);

    while (!stop_requested) {
        int pr = poll(&pfd, 1, 1000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            perror("poll"); goto out;
        }
        if (pr == 0) continue;
        if (pfd.revents & (POLLERR | POLLNVAL)) {
            fprintf(stderr, "device poll error: revents=0x%x\n", pfd.revents);
            goto out;
        }
        if (!(pfd.revents & (POLLIN | POLLRDNORM))) continue;

        {
            ssize_t n = read(fd, buf, buf_size);
            uint64_t id;
            int added;
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                if (errno == EMSGSIZE) {
                    fprintf(stderr, "pattern exceeds read buffer (%zu bytes); "
                                    "kernel ABI needs chunked reads or larger buffer\n",
                            buf_size);
                    goto out;
                }
                perror("read pattern"); goto out;
            }
            if (n == 0) break; /* STOP with queue drained; keep daemon for next START */
            if (validate_pattern(buf, (size_t)n, &id) < 0) {
                fprintf(stderr, "invalid pattern from kernel: %s\n", strerror(errno));
                goto out; /* do not ACK malformed data */
            }
            added = db_add(&db, buf, (size_t)n, id);
            if (added < 0) { perror("add pattern to database"); goto out; }
            if (added > 0) {
                if (db_save_atomic(db_path, &db) < 0) {
                    perror("persist database");
                    /* Do not ACK: kernel will redeliver. */
                    goto out;
                }
                fprintf(stderr, "persisted pattern=%" PRIu64 " (%zd bytes)\n", id, n);
            } else {
                fprintf(stderr, "pattern=%" PRIu64 " already persisted; ACKing duplicate\n", id);
            }
            {
                uint64_t ack = htole64(id);
                if (ioctl(fd, LT_IOCTL_ACK, &ack) < 0) {
                    if (errno == ENOENT) {
                        fprintf(stderr, "pattern=%" PRIu64 " already expired/ACKed\n", id);
                    } else {
                        perror("ACK pattern"); goto out;
                    }
                }
            }
        }
    }
    rc = 0;
out:
    if (fd >= 0) close(fd);
    free(buf);
    db_free(&db);
    return rc;
}

static int open_device(const char *path)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) perror(path);
    return fd;
}

int main(int argc, char **argv)
{
    const char *device = DEFAULT_DEVICE;
    const char *db_path = DEFAULT_DB;
    const char *command;
    size_t buffer_size = DEFAULT_READ_BUFFER;
    int fd;

    if (argc < 2) { usage(stderr); return 2; }
    command = argv[1];

    if (!strcmp(command, "daemon")) {
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--device") && i + 1 < argc) device = argv[++i];
            else if (!strcmp(argv[i], "--db") && i + 1 < argc) db_path = argv[++i];
            else if (!strcmp(argv[i], "--buffer-size") && i + 1 < argc) {
                char *end = NULL;
                unsigned long long v;
                errno = 0;
                v = strtoull(argv[++i], &end, 10);
                if (errno || !end || *end || v < LT_WIRE_HEADER_BYTES || v > SIZE_MAX) {
                    fprintf(stderr, "invalid buffer size\\n"); return 2;
                }
                buffer_size = (size_t)v;
            } else { usage(stderr); return 2; }
        }
        return daemon_run(device, db_path, buffer_size);
    }

    if (!strcmp(command, "set-max-apps")) {
        char *end = NULL;
        unsigned long v;
        uint32_t value;
        if (argc < 3) { usage(stderr); return 2; }
        errno = 0;
        v = strtoul(argv[2], &end, 10);
        if (errno || !end || *end || v < 1 || v > 4096) {
            fprintf(stderr, "max applications must be between 1 and 4096\\n"); return 2;
        }
        value = (uint32_t)v;
        for (int i = 3; i < argc; i++) {
            if (!strcmp(argv[i], "--device") && i + 1 < argc) device = argv[++i];
            else { usage(stderr); return 2; }
        }
        fd = open_device(device);
        if (fd < 0) return 1;
        if (ioctl(fd, LT_IOCTL_SET_MAX_APPS, &value) < 0) {
            perror("LT_IOCTL_SET_MAX_APPS"); close(fd); return 1;
        }
        close(fd);
        printf("maximum retained application sessions set to %u\\n", value);
        return 0;
    }

    if (!strcmp(command, "start") || !strcmp(command, "stop")) {
        int cmd;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--device") && i + 1 < argc) device = argv[++i];
            else { usage(stderr); return 2; }
        }
        fd = open_device(device);
        if (fd < 0) return 1;
        cmd = !strcmp(command, "start") ? LT_IOCTL_START : LT_IOCTL_STOP;
        if (ioctl(fd, cmd) < 0) {
            perror(command); close(fd); return 1;
        }
        close(fd);
        printf("recording %s\\n", !strcmp(command, "start") ? "started" : "stopped");
        return 0;
    }

    usage(stderr);
    return 2;
}
