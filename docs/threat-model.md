# Threat model

The library targets two backends through the `Calculator<TNumber>` strategy pattern: the .NET-native `BigInteger` and a custom `SecureBigInteger`.
The latter is positioned as the security-conscious option, but its protection is scoped — it is not a drop-in replacement for hardened native crypto stacks.

> [!IMPORTANT]
> Constant-time big-integer arithmetic in pure managed .NET is non-trivial; canonical implementations (libsodium, BoringSSL) rely on fixed-width representation, branchless conditional moves, and hand-tuned cache-pattern audits.
> The constant-time primitives exposed here approximate that approach within the constraints of managed .NET — they are best-effort against passive timing analysis and have *not* been audited against active co-located attackers (cross-VM cache attacks, browser high-resolution timers, network-RTT measurements).
> Consumers whose threat model includes such attackers should layer the operation through a constant-time crypto stack (e.g. libsodium-net, hardware-backed enclaves) rather than rely on the `SecureBigInteger` naming alone.

## At a glance

| Topic | Classification |
|---|---|
| [Passive memory disclosure](#passive-memory-disclosure) | Protected |
| [No string materialization in Base64 encoding](#no-string-materialization-in-base64-encoding) | Protected |
| [Length-vs-content equality leaks](#length-vs-content-equality-leaks) | Protected |
| [Insecure RNG](#insecure-rng) | Protected |
| [Digit-value timing leaks in the per-limb arithmetic](#digit-value-timing-leaks-in-the-per-limb-arithmetic) | Protected |
| [No variable-time number-theoretic surface](#no-variable-time-number-theoretic-surface) | Protected |
| [Timing leaks in modular inversion](#timing-leaks-in-modular-inversion-when-the-consumer-opts-in) | Protected, when the consumer opts in |
| [`Pow(int exponent)`](#powint-exponent) | Public input |
| [The sign of `Add` / `Subtract` operands, and the magnitude ordering of `Subtract`](#the-sign-of-add--subtract-operands-and-the-magnitude-ordering-of-subtract) | Public input |
| [`ByteCount` leaking the value's byte length](#bytecount-leaking-the-values-byte-length) | Not protected |
| [Ordering and serialization of `SecureBigInteger`](#ordering-and-serialization-of-securebiginteger) | Not protected |
| [Post-arithmetic zero branches](#post-arithmetic-zero-branches) | Not protected |
| [Result normalization leaking the result's magnitude](#result-normalization-leaking-the-results-magnitude) | Not protected |
| [Variable-time modular inverse when a variable-time GCD is chosen](#variable-time-modular-inverse-when-a-variable-time-gcd-is-chosen) | Not protected |
| [Hex- and Base64-decoder input-character timing](#hex--and-base64-decoder-input-character-timing) | Not protected |
| [Ordering of `Secret<TNumber>`](#ordering-of-secrettnumber) | Not protected |
| [Mathematically-small Mersenne security levels](#mathematically-small-mersenne-security-levels) | Not protected |
| [Resource use of a supported security level](#resource-use-of-a-supported-security-level) | Not protected |
| [Silent reconstruction on tampered shares](#silent-reconstruction-on-tampered-shares) | Not protected |
| [Not classified](#not-classified) | Not examined |

## Protected when using `SecureBigInteger`

### Passive memory disclosure

The internal limb buffer, a `PinnedPoolArray<ulong>`, is GC-pinned and overwritten on dispose with a 3-pass scramble and a final zeroing pass: `CryptographicOperations.ZeroMemory` on net8/9/10 and netstandard2.1, per-byte volatile writes on the legacy TFMs.
Heap snapshots, swap files, and reuse-after-free of the same physical pages cannot recover plaintext.

### No string materialization in Base64 encoding

`Secret<TNumber>.ToBase64CharArray()` encodes directly into the pinned destination buffer on every supported TFM —

- net8/9/10 and netstandard2.1 via `Convert.TryToBase64Chars`,
- legacy TFMs (netstandard2.0 / net4.7.2 / net4.8 / net4.8.1) via an inline 24-bit-window encoder mirroring the existing pinned Base64 decoder.

No intermediate, GC-relocatable, possibly-interned managed `string` is created on any TFM.

### Length-vs-content equality leaks

`SecureBigInteger.Equals` pre-pads to `max(left, right)` and uses fixed-time comparison; equality timing does not leak which prefix bytes match.
The comparison runs uniformly across all targeted TFMs via a private XOR-OR-fold helper, with no `#if`-conditional code path.

### Insecure RNG

Every random draw goes through `System.Security.Cryptography.RandomNumberGenerator` via the internal `Cryptography.SecureRandom` helper.
No `System.Random`, no PRNG seeds.

### Digit-value timing leaks in the per-limb arithmetic

`Add`, `Subtract`, `Multiply`, `Square`, `Divide`, and `Remainder` iterate a number of limbs fixed by the operand limb counts and use branchless carry/borrow propagation, so the arithmetic proper does not branch on the digit values.
The bound differs per operation and is not the same one for all six:

- `Subtract` iterates `max(left.LimbCount, right.LimbCount)`,
- `Add` that plus one for the carry limb,
- `Multiply` and `Square` run nested loops of `left.LimbCount × right.LimbCount`, and
- `Divide` and `Remainder` run `dividend.LimbCount × 64` outer iterations whose inner work spans the remainder and divisor limbs.

Each bound is derived from the limb counts alone, not from the digit values.

`MersenneModulo` folds branchlessly and finishes with a mask-driven conditional subtract; its iteration count is derived from the public Mersenne exponent and the operand limb count — which, per the [normalization note](#result-normalization-leaking-the-results-magnitude) below, is itself secret-derived for intermediate values.
This is a guarantee about the **per-limb loop only** — see [*result normalization*](#result-normalization-leaking-the-results-magnitude) and [the sign of `Add` / `Subtract` operands](#the-sign-of-add--subtract-operands-and-the-magnitude-ordering-of-subtract) below, both of which remain value-dependent.

### No variable-time number-theoretic surface

The legacy `Gcd`, `ModPow`, `Log`, `Log10`, and `Log2` static methods — whose implementations branched on operand values or invoked `Math.Log` on operand-derived doubles — were removed from `SecureBigInteger`.
The surface is narrowed to operations whose timing is bounded by the public bit-length, so there is no longer a way to call a variable-time-on-secret-operand method by accident.

### Timing leaks in modular inversion (when the consumer opts in)

`MersenneSafeGcdAlgorithm<TNumber>` implements the Bernstein–Yang "safegcd" / divstep recurrence and provides a **fixed-iteration** modular inverse for use inside `SecretReconstructor.DivMod`.
The **outer iteration count** is fixed at the public Mersenne exponent, independent of operand values; that is the only timing guarantee the algorithm gives out of the box.

**Per-iteration wall-clock time is not uniform** on the SecureBigInteger backend — the three divstep branches dispatch a different number of fresh `Calculator` allocations — seven for each of the two odd-`g` branches (six arithmetic results plus one `Clone`) against six for the even-`g` branch (three arithmetic results plus three `Clone`s) — and funnel `g` (or `g − f`) through `SecureBigInteger.Divide`, whose bit-loop count tracks the limb count of the shrinking intermediate working values.
The branch selector reads the parity of `g` and the sign of `delta`, both derived from the denominator handed to `Compute`; in reconstruction that denominator is built from the public share indices, so at a fixed field the branch sequence is public.
It is secret-dependent only for a caller passing a secret operand to `Compute` directly.
See the class XDoc for the full breakdown.
Strict branchless mask-select (all three branches run; result chosen via constant-time mask) is future work to lift this from "outer-iteration-count constant-time" to "per-iteration uniform".

The exponent is derived from the modulus passed to `Compute` at call time — the algorithm holds no `ISecurityLevelManager` reference, so it cannot drift from the `SecretReconstructor` consuming it.

The simplest way to opt in is `FixedIterationSecretReconstructor<TNumber>` — it accepts only fixed-iteration GCD strategies and defaults to `MersenneSafeGcdAlgorithm<TNumber>`, so the strategy cannot be mispaired:

```csharp
using var combiner = new FixedIterationSecretReconstructor<SecureBigInteger>();
using var recovered = combiner.Reconstruction(shares);
```

To pin a specific fixed-iteration strategy, pass it to the same type:

```csharp
new FixedIterationSecretReconstructor<SecureBigInteger>(new MersenneSafeGcdAlgorithm<SecureBigInteger>())
```

**Scope:** the fixed iteration count is relative to the security level.
`Reconstruction` runs at the level the shares record or the caller names, and derives one from the shares' maximum value only for shares recording neither, so the iteration count reflects that level — which is public either way, recorded in the share or revealed by its size.
What this removes versus `ExtendedEuclideanAlgorithm` is the operand-value dependence *within* a level, not the level-selection dependence (observable only to a pure-timing attacker with no share access).

## Public-input dependence (treated as public, not secret)

### `Pow(int exponent)`

`Pow(int exponent)` is variable-time *on the exponent value* (iteration count is `O(log₂(exponent))`, with additional early-return shortcuts for `exponent ∈ {0, 1}` that distinguish those two values from all others).
The exponent is *not* treated as secret; the per-iteration arithmetic on the secret base goes through the constant-time-on-bit-length `Multiply`.
Callers must not pass secret-derived exponents through this method.

### The sign of `Add` / `Subtract` operands, and the magnitude ordering of `Subtract`

Both branch on whether the operand signs match, and the routing differs between them: `Add` runs `AddUnsigned` on equal signs and `CompareUnsigned` followed by `SubtractUnsigned` on mixed ones, `Subtract` the other way round.
For `Add` the two paths cost one operation against two, so wall-clock time distinguishes a same-sign addition from a mixed-sign one.

For `Subtract` with equal signs — the ordinary case for Shamir values, which the mark byte keeps positive — the compare path is the one taken, and `comparison >= 0` selects which operand becomes the minuend.
Both selections call the same `SubtractUnsigned` over the same limb count, so magnitude ordering steers the branch without changing the amount of work; treat the ordering of two secret operands as observable rather than assuming the positive-value invariant removes the branch.

Within this library the *mixed-sign* path is not reached on the Shamir values themselves — the mark byte keeps secrets, coefficients and share values positive and `MersenneModulo` reduces into `[0, M_p)` — so `Subtract` on them always takes the equal-sign compare path above, ordering branch included.
The mixed-sign path *is* taken inside the modular inverse.
`MersenneSafeGcdAlgorithm.ApplyExtendedDivstep` operates on the signed Bézout coefficients: `newUG = uG - uF` turns negative at the first branch-1 iteration, which is the first divstep when the normalized denominator is odd and a later one when it is even, since the even-`g` branch carries `uG` through unchanged.

`MersenneModulo` carries its own sign branch, whose negative path runs three additional limb loops, a `SubtractInPlace` and one more pinned allocation that the positive path skips entirely.
`MersenneSafeGcdAlgorithm.Compute` reduces two signed intermediates per call — `beta * inv2n` and `alpha * inv2n`, both sign-corrected Bézout coefficients — and the negative path runs for whichever of them is negative.
It is *not* reached from `SecretReconstructor.DivMod`: `Compute` returns the coefficient already reduced into `[0, M_p)`, so the reduction that follows there sees a non-negative value.
`IsOne` likewise returns early on a negative sign, ahead of its fold.

#### What this does and does not say about reconstruction

These branches are real, but inside this library they do not run on the secret.
`Compute` has exactly one call site, `SecretReconstructor.DivMod`, which passes the normalized *denominator* and the field prime.
Both `DivMod` call sites in `LagrangeInterpolate` build that denominator purely from differences of share indices, `x_i - x_j`; the secret share values enter the *numerator*, which never reaches `Compute`.
At a fixed security level the divstep history, and therefore every sign it produces, is a function of the public share indices.
What remains share-dependent is the level selection itself, already [documented above](#timing-leaks-in-modular-inversion-when-the-consumer-opts-in) as public, recorded in the share or revealed by its size.
The warning binds callers who use `SecureBigInteger` or `MersenneSafeGcdAlgorithm` directly on signed secret operands: they must treat the sign as public, or normalize to magnitudes before the operation.

## Not protected, even with `SecureBigInteger`

### `ByteCount` leaking the value's byte length

The property returns early when the high limb is zero and otherwise calls `BytesInLimb`, which counts significant bytes by shifting until the limb reaches zero — one to eight iterations depending on the value.
This is finer than the limb granularity of the [normalization note](#result-normalization-leaking-the-results-magnitude) below, and it sits on the secret path: `SecurityLevelManager.AdjustSecurityLevel` evaluates `maximumY.ByteCount` on a share value, and `Secret<TNumber>` uses it on the secret and on polynomial coefficients.

### Ordering and serialization of `SecureBigInteger`

`CompareTo` returns early when the operand signs differ, before the fixed-count `CompareUnsigned` runs.
`ToByteArray` and its `IsExactByteBoundaryPowerOfTwo` helper take several value-dependent early returns.
Both are treated as boundary operations, like the [hex and Base64 decoders](#hex--and-base64-decoder-input-character-timing) below; only equality is constant-time.

### Post-arithmetic zero branches

`Add`, `Subtract`, `Multiply`, `Divide`, and `Remainder` branch on `IsZeroInternal()` after the limb work, before assigning the result sign.
The guarded work is a single field write, so the timing difference is minimal, but the predicate is the secret-derived zero status of the result.

In `Add` and `Subtract` that branch also undoes a leak the code closes deliberately a few lines earlier: `Subtract` folds the `comparison == 0` case into the `>= 0` branch so timing cannot separate `|minuend| == |subtrahend|` from `|minuend| ≠ |subtrahend|`, and the zero normalization then branches on exactly that case.
None of the five takes a zero short-circuit *before* the arithmetic — `Multiply` carries a source comment explaining that branching there would leak — and the remaining zero check is the divide-by-zero contract, evaluated on the divisor.

### Result normalization leaking the result's magnitude

Every unsigned helper returns through `new SecureBigInteger(limbs, count, isNegative)`, whose constructor calls `TrimLeadingZerosInPlace`.
That trim scans the limbs downward and stops at the first non-zero one, so its iteration count depends on how many leading zero limbs the result has — a value-dependent quantity, even when both operands had the same limb count.
The trimmed length is then stored and sizes the next operation, so the limb count of an intermediate value is itself secret-derived rather than public.

The absolute cost is small — at most one `ulong` comparison per limb of the *result*, which is wider than the operands: with two-limb operands at security level 127 a sum is three limbs, a product four, and a division remainder three — but it is a data-dependent branch present in every core operation, so the arithmetic as a whole is not constant-time on the result magnitude.
Removing this would require a fixed-width representation that never trims.

### Variable-time modular inverse when a variable-time GCD is chosen

The base `SecretReconstructor<TNumber>` requires an explicit GCD strategy; pairing it with `ExtendedEuclideanAlgorithm<TNumber>` yields an iteration count that is variable on the operand values.
This is a deliberate opt-out, not a default — use `FixedIterationSecretReconstructor<TNumber>` (which accepts only fixed-iteration strategies and defaults to `MersenneSafeGcdAlgorithm<TNumber>`) for reconstruction whose timing does not depend on secret operands.
The variable-time pairing remains available for the `BigInteger` backend and other cases where constant time is not a goal.

### Hex- and Base64-decoder input-character timing

`Share<TNumber>`'s hex-deserialization pipeline (`DecodeHexToCalculator` → `GetHexValue`) and `Secret<TNumber>`'s Base64 decode (`DecodeBase64Char`) are not constant-time on input characters — both compile to branchy range-pattern switches whose wall-clock time varies by which character class the input belongs to.
Both decoders are treated as boundary parsers: only the resulting `Calculator<TNumber>` value / decoded secret bytes flow through the CT primitives.

### Ordering of `Secret<TNumber>`

`Secret<TNumber>.CompareTo` and the relational operators (`<`, `>`, `<=`, `>=`) ultimately use `PinnedPoolArray<byte>.IStructuralComparable.CompareTo`, which short-circuits on the first differing byte.
Wall-clock time leaks the length of the common prefix between two secrets.
Sorting or comparing secret material where ordering timing matters is out of scope — only equality (`Secret<TNumber>.Equals` over the fixed-time path) is CT.

### Mathematically-small Mersenne security levels

`ISecurityLevelManager.SecurityLevel` accepts every Mersenne prime exponent from the library's table, starting at `MinMersennePrimeExponent = 13` (prime `2^13 − 1 = 8191`).
A 13-bit modulus is mathematically tiny and is included for round-trip / parameter-exploration scenarios, *not* as a recommended cipher-strength floor.

The auto-upgrade in `SecretSplitter<TNumber>.MakeShares` raises the level whenever the secret's bit-length exceeds the current prime; reconstruction runs at the level the shares record or the caller names, and only for shares recording neither fits the level to the maximum share value via `SecurityLevelManager.AdjustSecurityLevel`, which may raise or lower the level.
Either way, consumers who explicitly construct shares at low exponents on a small secret receive what they ask for.

Treat `MinMersennePrimeExponent` as a representational floor, not a security floor; **production secrets should use a security level of `127` or higher.**

### Resource use of a supported security level

Validating an exponent keeps *unsupported* values out; it does not bound what a *supported* one costs.
The built-in table reaches `43,112,609`, and reconstruction computes the Mersenne prime for the level it runs under — at least twice, once to check the coordinates against the field and once when the security level manager takes the level.
That computation grows roughly quadratically with the exponent: seconds in the low millions, extrapolating to minutes at the top of the table, and longer on `SecureBigInteger`.
Because shares can record their level, the cost no longer scales with the size of the input — a three-segment share string of a dozen characters can name the largest exponent.

Applications that reconstruct shares from untrusted sources should build their `SecurityLevelManager` on an `IMersennePrimeProvider` that supports only the exponents they use; reconstruction then refuses any other before computing a prime.
Pass the same provider to `ReissueWithSecurityLevel` when migrating.
The library sets no ceiling of its own, and such a provider is an allowlist, not a general denial-of-service defense.

### Silent reconstruction on tampered shares

Shamir's scheme carries no integrity check on individual shares: if a single share's `Index` or `Value` is mutated in transit, in storage, or by a malicious participant, `SecretReconstructor.Reconstruction` produces a wrong secret with no exception, no warning, and no signal that anything is off.
The library implements plain Shamir; it does not implement verifiable secret sharing (VSS — e.g. Feldman or Pedersen) or per-share MACs.
Consumers whose threat model includes share manipulation must layer an integrity scheme (signed shares, HMAC-keyed envelopes, VSS) on top.

**The recorded security level is not authenticated either.**
Reconstruction refuses shares whose levels disagree, but that detects inconsistency, not manipulation: a level changed alike on every share passes the check and can lead to a wrong secret just as silently.
An integrity scheme has to cover the level together with the coordinates — for the three-segment form, the whole string.

## Not classified

The three groups above list what was examined.
Absence from all of them is not a guarantee — it means the surface was not walked against the code.
That currently covers, among others,

- `ToPinnedCharArray` and the decimal conversion behind it,
- `ToHexadecimal` and `FromHexadecimal`,
- `Abs` and `Negate`,
- the conversion operators, and
- the limb/byte marshalling helpers.

Several are reveal paths by design, where constant time is not a goal; the point of saying so is that you can tell an unexamined surface from an examined one.
