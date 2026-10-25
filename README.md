# linen-box

Small workers for authenticated batch jobs.

An owner supplies an encrypted, inventoried bundle. Workers validate it, execute
one assigned part with a fixed time limit, and return encrypted output.
Workload diagnostics are captured inside the encrypted result. Public receipts
contain opaque identities and generic completion status.

Execution requires an explicit dispatch on the main branch. At most four parts
run concurrently. Outputs expire after three days. There are no scheduled runs.

The payload environment excludes provider credentials. This worker is designed
for trusted owner-authored software, not hostile programs. Execution timing,
counts, and encrypted file sizes are public. The host processes plaintext during
execution; encryption protects published content rather than the host itself.

Run the contract checks with `python -B -m unittest -q test_worker`.
