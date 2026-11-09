# Performance notes

Measured with `cargo run --release -p tpt-vault-core --example throughput` on the Windows dev
machine, NTFS, one run each. Results vary from run to run, mostly because of disk flushes, so
treat them as rough figures. Re-run the example on the target hardware before making claims.

## Results (after the fixes below)

| Operation                              | Result                         |
|----------------------------------------|--------------------------------|
| Sequential write, 256 MiB, 1 MiB chunks | about 20 MiB/s (12.5 s)        |
| Sequential read, 256 MiB               | about 530 MiB/s                |
| Small overwrite, 512 B, random offset  | about 10–22 ms each            |

Small-write cost is now flat in the file size. Before the fix it grew with the file: about 2.4 s
per write on a 64 MiB file.

## Baseline before the fixes

The first background run, before any fix, is recorded here for comparison. Its output file
(captured stdout and cargo messages) shows:

| Operation                    | Result                                             |
|------------------------------|----------------------------------------------------|
| Sequential write, 256 MiB    | 2.7 MiB/s (93.6 s), 64 KiB chunks, whole-tail rewrite |
| Sequential read, 256 MiB     | 511 MiB/s                                          |
| Small overwrites, 2000 x 512 B | did not complete: the process exited with code 1 |

The exit code 1 has no message in the captured output. Panics normally print to stderr and exit
with code 101, so this exit is not a standard panic. The cause is unknown. The run had also
used the whole-tail rewrite, which is now fixed. The same run did not reproduce after the fixes.

## What the numbers show

- **Small writes are dominated by flushes.** Each `write_at` fsyncs the journal and then the data.
  A raw 4 KiB write plus `sync_data` measured about 3 ms on the same machine, so the rest of the
  10–22 ms is journal file creation, rename and copying.
- **Sequential writes are dominated by flushes too.** Each `write_at` call costs two fsyncs, so
  the chunk size sets the throughput. The streaming chunk went from 64 KiB to 1 MiB, which made
  sequential writes about 16 times faster on a 32 MiB test (4.4 to 69.5 MiB/s). The 256 MiB
  run measured 20–28 MiB/s, so the gain is smaller at larger sizes.

## Fixes made while profiling

1. **Writes rewrote the rest of the file.** `write_at` re-encrypted every record from the
   touched block to the end of the file. A 512-byte write in a 64 MiB file rewrote about 54 MB,
   and the journal saved all of it. Now only the records the write touches are rewritten,
   and only the file's final block is sealed as last. The regression test is
   `journal::tests::small_write_rewrites_only_the_records_it_touches`.
2. **Streaming chunks were small.** `STREAM_CHUNK` is now 1 MiB (256 blocks), up from 64 KiB.
   Memory use stays bounded, and each chunk costs one journal and two flushes.

## Decision: keep one journal per `write_at`

Re-measured on the dev machine: 30.5 MiB/s for a 256 MiB sequential write, and 2000 small
overwrites at 11.5 ms each (87 per second).

The cost is not visible in real note editing. The editor saves the whole note in one
`write_at` call (`save_note`), and only after a 1.5 s pause or 10 s of continuous typing. So a
save costs one journal and two flushes, not one per keystroke. Batching or dropping the second
fsync would weaken the crash guarantee for a cost users would not notice. The design stays.

Revisit this if bulk copies into the vault become slow in practice, for example through the
mount backends, which issue many small writes.

## Open items

- Bulk copies, and the mount backends' small writes, still pay two flushes per `write_at`. Only
  revisit if that is slow on real use.
- The baseline run exited with code 1 during the small-write phase, with no message in its
  output. It did not reproduce after the fixes. The cause is unknown. If it returns, run
  the example with stderr redirected to a file, so any panic text is kept.
