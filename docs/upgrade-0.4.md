# Preparing an upgrade to 0.4

Publishing or installing the shared-core package is not permission to modify a
running installation. Release qualification does not touch live memory,
Hermes/Codex configuration, workers, or a model. Keep the current runtime until
the exact package has passed its [public release gates](v04-readiness.md) and
the separately authorized host/memory acceptance checks for your installation.
Those operator-environment checks are not certified by the public release.

## Rehearse before promotion

1. Identify the current runtime artifact and explicit memory root; record their
   versions and existing host settings. Never rely on an implicit default root.
2. For a real upgrade, obtain a quiet/stopped writer boundary with the operator's
   approval. Preserve the original runtime, configuration and a verified full
   backup. A hash inventory alone is not a restorable backup.
3. Restore or copy that backup to a new disposable directory. Verify the old
   runtime can read it, and record original Scroll/Card/Library identities,
   artifact hashes, scope behavior and queued jobs before candidate use.
4. Install the exact reviewed wheel into a separate virtual environment. Confirm
   imports and version come from that environment, not an adjacent source tree.
   Use explicit disposable roots for status, strict verification and new-feature
   checks. Do not run old and new writers concurrently on one memory root.
5. Confirm original memory/evidence remains available, private/session/project
   selection is unchanged, credential rejection still works, and new derived
   indexes can be rebuilt without deleting original evidence. Optional embedding
   checks require a separately authorized provider; they are not needed for the
   model-free checks and must not silently start a model.
6. Rehearse rollback by restoring the preserved pre-upgrade backup into another
   empty disposable directory and selecting the old runtime. Verify that exact
   historical state. Reopening a modified candidate root with old code is not a
   substitute for a tested backup restore.

Synthetic rehearsal roots cover deterministic behavior but do not establish
compatibility with every existing user's historical memory. Representative real
memory needs a separately authorized, private, disposable rehearsal; never copy
it into public source archives or test fixtures.

## Promote only with explicit authority

After exact-package and operator-environment checks pass, separately approve
the live writer boundary, backup verification, runtime pointer change and host
reconnect. Preserve the
old runtime and config preimages until real conversation/recall, image follow-up,
structured call/result preservation and worker recovery checks pass. A failure
requires the recorded rollback, not ad-hoc schema edits or deleting memories.

Installing a package is not permission to restart or reconfigure a model. Keep
model lifecycle/settings ownership with the operator. Ordinary memory operations
and model-free retrieval remain available without an embedding provider.
