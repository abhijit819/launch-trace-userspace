# LaunchTrace userspace controller and persistence daemon

This userspace program targets the IOCTL/read ABI declared by the current
LaunchTrace Linux 4.4 kernel package.

## Build

```sh
make
```

Requires a Linux userspace toolchain with GCC and glibc (or compatible libc)
providing `endian.h` and `sys/ioctl.h`.

## Run

Start the persistence daemon first:

```sh
sudo mkdir -p /var/lib/launchtrace
sudo chmod 0700 /var/lib/launchtrace
sudo ./launchtraced daemon
```

In another terminal, configure the retained-session limit before the first
START, then start recording:

```sh
sudo ./launchtraced set-max-apps 50
sudo ./launchtraced start
```

Run the application(s) whose startup I/O should be captured. Stop recording
when the experiment is complete:

```sh
sudo ./launchtraced stop
```

The daemon remains alive across STOP/START cycles. It polls the device, reads
completed patterns, validates their wire stream, atomically persists the
updated database, and only then sends `LT_IOCTL_ACK`. SIGINT/SIGTERM stops the
daemon cleanly; unacknowledged patterns remain eligible for kernel retry.

Options:

```sh
./launchtraced daemon --device /dev/launchtrace \
    --db /var/lib/launchtrace/patterns.ltdb --buffer-size 16777216
./launchtraced start --device /dev/launchtrace
./launchtraced stop --device /dev/launchtrace
./launchtraced set-max-apps 32 --device /dev/launchtrace
```

## Persistent database format: LTDB v1

All integers are little-endian. The database is rewritten atomically through a
temporary file, `fsync()`, `rename()`, and parent-directory `fsync()`.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `LTDBv1` followed by two NUL bytes |
| 8 | 4 | Version (`1`) |
| 12 | 4 | Header size (`24`) |
| 16 | 8 | Pattern count |

Each entry is:

| Size | Field |
|---:|---|
| 8 | Serialized pattern blob length (`u64`) |
| variable | Exact little-endian pattern blob returned by the kernel |

The embedded pattern stream is wire format v1 from `launchtrace.h`: pattern
header, raw executable path, device headers, and sector-sorted page records.
The daemon preserves the kernel blob byte-for-byte. `pattern_id` is the
idempotency key; a duplicate delivery is not inserted twice and is ACKed only
after the existing database is known to contain it.

## Important ABI limitations

- The current kernel wire header does **not** contain argv/argc. The daemon
  cannot persist arguments that the kernel never supplies. Add argv fields to
  the kernel wire ABI in a versioned change if they become required.
- The kernel currently uses a 16 MiB default maximum userspace read buffer here.
  A pattern larger than the configured buffer returns `EMSGSIZE`; chunked reads
  are not supported by this kernel ABI yet. Increase `--buffer-size` if needed.
- The daemon requires the database parent directory to exist. It does not
  create missing directories automatically.
- The database is a single rewritten file. This is intentionally simple for
  the experiment; very large databases will make each new pattern save slower.
- The kernel queue is not crash-persistent across module unload/reboot. The
  userspace database is persistent once the atomic save has completed.
- Run the daemon before issuing START. The daemon can remain running during
  STOP and later START operations.
- This program is experimental. Test on a disposable system and validate the
  kernel module ABI before relying on collected data.
