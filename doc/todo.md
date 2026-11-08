# To Do

Planned work, in order. Each item names what to build, how it fits the seams
in place, and how to verify it. Finished items leave this list for the design
document.

1. **The budget's readings.** §9 of vif's design asks for the service's RSS
   with 10,000 verifiers loaded and under the launch-day rate of 170
   introspections a second, against the 256 MiB the unit allows and the pool
   of ten. Load a test database with `identity account add` in a loop or with
   `store.CreateAccount` from a small program, run the binary, read its RSS
   from `/proc`, and drive `POST /introspect` with a closed-loop client at
   that rate; report the readings in the PR body, and the `-db-pool` and
   `MemoryMax` they justify.
2. **The jail's address filter.** Once the deployment names the jail's
   address, a drop-in for `identity.service` with `IPAddressDeny=any` and
   `IPAddressAllow=` for localhost and that address, kept outside this
   repository as the unit's comment says; verify that the service connects
   and that a dial elsewhere is refused.
3. **An operator's change without a restart.** `identity account add` and
   `reset` reach the running service at its next start, which loads every
   verifier then. A reload on a signal, or a periodic check of `updated_at`
   against the loaded set, would take them live; the SCRAM server replaces a
   credential with `AddCredential` and drops one with `RemoveCredential`.
   Verify with a handler test that signs in after a reset without a new
   handler.
