# Private promotion rehearsal — CP-10.02

Refs #49. This is bounded **offline synthetic engineering evidence**, not issue
completion, accepted prerequisites, signing, release approval or publication.
D-011 signer identity, custody, rotation and recovery, and D-012 public current
pointer compatibility remain unaccepted. No key is generated or used. Frozen
bearer-authenticated v1 and the canonical website service remain unchanged.

## Exact local protocol

`src.publication.promote` consumes the pinned `BuildResult` from CP-10.01 and
only the public `FixtureStore` APIs from CP-14.01. Both are locally prepared
prerequisites, not accepted outcomes. Supply private temporary roots and only
synthetic bytes. The single channel name is `synthetic`; it is a local SQLite
row, never a public endpoint, mirror or operating channel.

1. `fixture_packet(build, operation_id, approvers)` constructs a plain packet
   with `schema_version=synthetic-promotion-packet-0.1`, synthetic operation ID,
   channel, exact manifest SHA256, release ID/revision, parent release pin,
   `records_sha256` and two to four distinct synthetic approver IDs. The records
   digest binds every manifest candidate, record, evidence, packet, review,
   rights, projection and notice pin. The manifest binds source provenance
   indirectly through exact catalog bytes. Identities cannot cross these roles.
2. `fixture_proof(packet)` returns `protocol=NONAUTHORITATIVE-fixture-checksum-0.1`
   and `packet_sha256`, SHA256 of UTF-8 JSON with sorted keys, no whitespace,
   non-ASCII preserved, and NaN forbidden. Anyone can reproduce it. This is a
   **test checksum, not a signature**. Missing, altered or unsupported proofs
   refuse before staging. Synthetic approvers are unauthenticated assertions.
3. `FixturePromoter(root, store).set_fixture_decision(packet, state='active',
   expected_version=0)` appends an unauthenticated aggregate fixture decision.
   It represents all source/review/rights pins together, not a source-rights
   service or permission grant. Each update expects the exact previous version;
   `state='revoked'` is terminal. Callers must represent changed or revoked
   upstream fixture decisions here; there is no real source retrieval or automatic
   source-policy synchronization. A new bundle needs its own exact decision.
4. `promote(build, packet, proof, expected_revision=0, expected_sha256=None)`
   verifies strict versions/schema, synthetic flags, all three named artifacts,
   exact sizes/hashes, immutable byte types, metadata roles and packet/proof.
   Existing current retries revalidate without restaging missing objects.
   It stages and references all four exact blobs (including manifest) through
   public store methods, then rereads them before the separate pointer commit.
   Object reference IDs are `urn:pya:synthetic:promotion-object:<sha256>`, revision
   one, and source revision is their own digest; shared bytes deduplicate safely.
5. Under pointer SQLite `BEGIN IMMEDIATE`, the aggregate decision is revalidated,
   expected pointer revision **and** manifest digest must match, and the manifest
   parent must equal the prior release ID/revision/digest. First parent is null.
   The operation receipt and pointer change commit together. Exact current
   retries return the committed receipt. Historical retries refuse; operation
   identities and release ID/revision pairs cannot be reused for different bytes.

Receipts include `revision` (pointer revision), `release_id`, `release_revision`,
`manifest_sha256`, `operation_id`, `decision_version`, `packet`, `fixture_proof`,
`objects` (the exact four FixtureStore metadata dictionaries), `channel` and
`evidence_level=synthetic_local_promotion_rehearsal`. Every receipt and decision
result permanently reports `synthetic=true`, `actual_signature_verified=false`,
`actual_rights_cleared=false`, `authenticated=false`, `publication_eligible=false`.
A checksum or schema pass never authenticates an approval or clears rights.

`current()` returns null before promotion, otherwise a detached receipt only
after the current aggregate decision and all stored bytes revalidate. Corruption,
missing bytes or revocation refuses the read. `history()` returns detached
historical receipts; it **does not verify current eligibility or stored bytes**.
Revocation preserves history and refuses current reads/retries; it does not
choose a rollback target or erase the pointer. An existing active manifest can
be revoked even when ordinary decision admission is exhausted. The exact packet
and expected version remain mandatory; stale or changed packets refuse, and a
terminal decision cannot be appended again or reactivated. `close()` closes the
local connection. One promoter and store connection are required per worker thread.

## Failure and resource boundary

There is no transaction across FixtureStore and pointer SQLite. Interrupted
staging or a failed pointer transaction can retain complete orphan objects or
references; these are visible through the store inventory. The prior pointer
stays unchanged. A committed receipt survives process exit/reopen, and an exact
retry cannot move history backwards. Cooperating code treats stored objects as
immutable. An external filesystem owner can still corrupt/remove them after a
read; this is trusted temporary test infrastructure, not an adversarial host or
proof of power-loss durability. No storage private method/database is accessed.

The common bound is **64 KiB per object**, even though the builder can emit
2 MiB artifacts. Larger outputs fail explicitly. Additional limits are 64
retained promotion operations, 64 ordinary aggregate decision admissions, the
store's 64 objects/references, revisions at most 1,000,000, bounded plain metadata
traversal, and one-second SQLite lock waits. Every active append and every new
initially revoked manifest consumes one ordinary admission. Each previously
active manifest also reserves one terminal revocation, allowing at most 128
decision rows in total. Revocations do not reclaim admission capacity. Existing
64-row fixture histories require no migration to retain terminal withdrawal.
There is no deletion, compaction, eviction, network transport or public
distribution. Ordinary admission and operation capacities remain independent.
Full admission permits terminal withdrawal; full operation history still permits
validated exact current promotion retries.
Caller packet/proof data is detached before lock waits; exact bytes are already
immutable. JSON/Unicode parser failures return a fixed diagnostic without
retaining the internal decoding exception as a cause or context. This does not
sanitize exception frames, local variables or caller telemetry.

## Verification and remaining gates

Focused tests exercise real local byte corruption and missing files, malformed
and unsigned fixture proof, stale CAS/parent, competing SQLite connections,
revocation during staging, mutation during an actual lock wait, SQLite abort,
process exit before/after pointer commit, reopen, retries, terminal withdrawal
after full admission and bounded revocation of all admitted manifests. Parser
tests check fixed diagnostics and absent decoding exception cause/context. Injected
interruptions are synthetic fault tests, not deployed durability evidence.

The full original acceptance criterion requiring actual signature verification
is **not met**. Accepted CP-10.01, CP-08.02 and CP-13.03 outcomes, D-011/D-012,
authorized independent review, authentic source rights, operating acceptance and
exact receiving-consumer receipts remain required. Author checks do not replace
independent correctness and security review of the exact candidate. This partial
work neither updates GitHub acceptance state nor authorizes remote publication.
