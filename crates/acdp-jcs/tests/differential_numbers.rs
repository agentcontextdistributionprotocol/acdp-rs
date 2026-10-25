//! Differential tests for RFC 8785 (JCS) number serialization.
//!
//! RFC 8785 §3.2.2.3 defers JSON number formatting to the ECMAScript
//! `Number::toString(10)` algorithm. The production implementation
//! (`write_number` / `ecma_number_string` in `src/lib.rs`) takes Rust's
//! shortest-round-trip `{:e}` digits and hand-reformats them into the
//! ECMAScript notation bands. The *digit generation* is trusted (stdlib
//! Grisu/Ryū); the BAND / NOTATION logic is what these tests attack:
//!
//! 1. An independent reference oracle transcribed verbatim from the
//!    ECMA-262 spec text (`es_number_to_string` below).
//! 2. Property tests over arbitrary finite `f64` bit patterns plus
//!    bit-level neighborhoods of every notation boundary.
//! 3. A curated boundary corpus (band edges, 2^53 ladder, IEEE 754
//!    extremes, negative zero, the can-011 fixture values).
//! 4. The published RFC 8785 Appendix B vectors (every entry verified
//!    against an actual ECMAScript engine before being pinned here).
//! 5. The can-011 conformance vectors — embedded, and cross-checked
//!    against the spec fixture file when it is locatable.

use acdp_jcs::{canonicalize_value, try_canonicalize_value};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────────
// Reference oracle: ECMAScript Number::toString(x, 10)
//
// Transcribed directly from ECMA-262 §6.1.6.1.20 "Number::toString ( x,
// radix )" (the radix-10 positional rules; identically numbered as steps
// 5–10 of the classic ES5.1 §9.8.1 "ToString Applied to the Number Type",
// which RFC 8785 §3.2.2.3 references). Written independently of the
// production code: each branch below is the literal spec step, cited
// inline. Only the digit triple (s, k, n) is sourced from Rust's
// shortest-round-trip formatter, which the task charter declares trusted.
// ─────────────────────────────────────────────────────────────────────────────

/// ECMAScript `Number::toString(x, 10)` for finite `x`.
/// ECMA-262 §6.1.6.1.20 step 5 even-tie rule for the oracle. `x` is an
/// exact decimal midpoint iff `x == t × 10^e / 2` with `t = 2s ∓ 1`; the
/// comparison `m·2^(q+1−e) == t·5^e` is done in checked `u128` integer
/// arithmetic (a genuine tie forces `5^|e|` to divide a ≤53-bit mantissa
/// product, so both sides fit; overflow soundly means "not a tie").
fn apply_even_tie_rule(x: f64, s: String, n: i64) -> String {
    if s.len() > 17 {
        return s;
    }
    let k = s.len() as i64;
    let e = (n - k) as i32; // value = s_int × 10^e
    let v: u128 = s.parse().expect("digit string parses as an integer");
    if v.is_multiple_of(2) {
        return s; // even already wins any tie
    }
    for cand in [v - 1, v + 1] {
        let t = v + cand; // 2v−1 (below) or 2v+1 (above), both odd
        if oracle_exact_midpoint(x, t, e) {
            let out = cand.to_string();
            assert_eq!(out.len(), s.len(), "tie flip must preserve k");
            assert!(
                !out.ends_with('0'),
                "tie flip must not create trailing zero"
            );
            return out;
        }
    }
    s
}

fn oracle_exact_midpoint(x: f64, t: u128, e: i32) -> bool {
    let bits = x.to_bits();
    let frac = bits & ((1u64 << 52) - 1);
    let biased = ((bits >> 52) & 0x7ff) as i32;
    let (m, q) = if biased == 0 {
        (frac as u128, -1074i32)
    } else {
        ((frac | (1u64 << 52)) as u128, biased - 1075)
    };
    fn scale(v: u128, p2: u32, p5: u32) -> Option<u128> {
        if p2 >= 128 || v.leading_zeros() < p2 {
            return None;
        }
        (0..p5).try_fold(v << p2, |acc, _| acc.checked_mul(5))
    }
    let p2 = q + 1 - e;
    let lhs = scale(m, p2.max(0) as u32, (-e).max(0) as u32);
    let rhs = scale(t, (-p2).max(0) as u32, e.max(0) as u32);
    lhs.is_some() && lhs == rhs
}

fn es_number_to_string(x: f64) -> String {
    assert!(x.is_finite(), "oracle is defined for finite numbers only");

    // Step 2 (ES5.1 §9.8.1 step 2): "If m is +0 or −0, return the String
    // \"0\"." Both zero signs collapse to "0".
    if x == 0.0 {
        return "0".to_string();
    }

    // Step 3: "If m is less than zero, return the String concatenation of
    // the String \"-\" and ToString(−m)."
    if x < 0.0 {
        return format!("-{}", es_number_to_string(-x));
    }

    // Step 5: "Otherwise, let n, k, and s be integers such that k ≥ 1,
    // 10^(k−1) ≤ s < 10^k, the Number value for s × 10^(n−k) is m, and k
    // is as small as possible." (s is the significant-digit string with
    // no trailing zeros — "s is not divisible by 10"; k = number of
    // digits of s; n places the decimal point: m = 0.s × 10^n.)
    //
    // Digit source: Rust's `{:e}` emits the shortest round-tripping
    // decimal as "d[.ddd…]e<exp>", i.e. m = d.ddd… × 10^exp. Therefore
    // the first significant digit has place value 10^exp, giving
    // n = exp + 1 — independent of any trailing-zero trimming, which
    // only shortens k.
    let sci = format!("{:e}", x);
    let (mantissa, exp) = sci
        .split_once('e')
        .expect("Rust {:e} output always contains 'e'");
    let n: i64 = exp
        .parse::<i64>()
        .expect("Rust {:e} exponent is a decimal integer")
        + 1;
    let mut s: Vec<u8> = mantissa.bytes().filter(|b| *b != b'.').collect();
    while s.len() > 1 && s.last() == Some(&b'0') {
        s.pop(); // enforce "s is not divisible by 10" (minimal k)
    }
    let s = String::from_utf8(s).expect("digits are ASCII");
    debug_assert!(s.as_bytes()[0] != b'0', "x != 0 ⇒ leading digit nonzero");
    // Step 5 tie clause: "If there are two such possible values of s,
    // choose the one that is even." The digit source above inherits
    // Rust's tie-break, which may pick the odd candidate; detect an
    // exact decimal midpoint with integer arithmetic and flip to the
    // even neighbor. (Independently implements the same clause the
    // production code applies; both sides stay anchored to engine
    // ground truth by the V8-verified Appendix B pins below.)
    let s = apply_even_tie_rule(x, s, n);
    let k = s.len() as i64;

    if k <= n && n <= 21 {
        // Step 6: "If k ≤ n ≤ 21, return the String consisting of the
        // code units of the k digits of the decimal representation of s
        // (in order, with no leading zeroes), followed by n−k occurrences
        // of the code unit 0x0030 (DIGIT ZERO)."
        let mut out = s;
        for _ in 0..(n - k) {
            out.push('0');
        }
        out
    } else if 0 < n && n <= 21 {
        // Step 7: "If 0 < n ≤ 21, return the String consisting of the
        // code units of the most significant n digits of the decimal
        // representation of s, followed by the code unit 0x002E (FULL
        // STOP), followed by the code units of the remaining k−n digits."
        // (Reached only when n < k, so both slices are non-empty.)
        let (int_part, frac_part) = s.split_at(n as usize);
        format!("{int_part}.{frac_part}")
    } else if -6 < n && n <= 0 {
        // Step 8: "If −6 < n ≤ 0, return the String consisting of the
        // code unit 0x0030 (DIGIT ZERO), followed by the code unit 0x002E
        // (FULL STOP), followed by −n occurrences of the code unit 0x0030
        // (DIGIT ZERO), followed by the code units of the k digits of the
        // decimal representation of s."
        let mut out = String::from("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&s);
        out
    } else if k == 1 {
        // Step 9: "Otherwise, if k = 1, return the String consisting of
        // the code unit of the single digit of s, followed by code unit
        // 0x0065 (LATIN SMALL LETTER E), followed by the code unit 0x002B
        // (PLUS SIGN) or the code unit 0x002D (HYPHEN-MINUS) according to
        // whether n−1 is positive or negative, followed by the code units
        // of the decimal representation of the integer abs(n−1) (with no
        // leading zeroes)."
        let e = n - 1;
        format!("{s}e{}{}", if e < 0 { '-' } else { '+' }, e.abs())
    } else {
        // Step 10: "Return the String consisting of the code units of the
        // most significant digit of the decimal representation of s,
        // followed by code unit 0x002E (FULL STOP), followed by the code
        // units of the remaining k−1 digits of the decimal representation
        // of s, followed by code unit 0x0065 (LATIN SMALL LETTER E),
        // followed by [the signed exponent n−1 as in step 9]."
        let e = n - 1;
        let (first, rest) = s.split_at(1);
        format!(
            "{first}.{rest}e{}{}",
            if e < 0 { '-' } else { '+' },
            e.abs()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Harness helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Serialize a single `f64` through the crate's public API and return the
/// emitted number token. A bare number is a complete JSON text, so the
/// whole canonicalization output *is* the token.
fn jcs_number_token(f: f64) -> String {
    let v = serde_json::Value::from(f);
    assert!(
        v.is_number(),
        "Value::from must yield a Number for finite input, got {v:?}"
    );
    String::from_utf8(canonicalize_value(&v)).expect("JCS output is UTF-8")
}

/// Core differential assertion: production token == oracle token, and the
/// oracle output round-trips back to the exact same double (bit-for-bit,
/// except the sign of zero, which RFC 8785 §3.2.2.3 deliberately erases).
fn assert_number_differential(f: f64) {
    let oracle = es_number_to_string(f);
    let produced = jcs_number_token(f);
    assert_eq!(
        produced,
        oracle,
        "JCS/oracle divergence for f64 bits=0x{:016x} (value {f:?}): \
         production={produced:?} oracle={oracle:?}",
        f.to_bits()
    );

    // Oracle self-check (guards the oracle itself, not the crate): the
    // shortest-round-trip guarantee means the token must reparse to the
    // identical double.
    let reparsed: f64 = oracle
        .parse()
        .unwrap_or_else(|e| panic!("oracle emitted unparseable token {oracle:?}: {e}"));
    if f == 0.0 {
        assert_eq!(reparsed, 0.0, "zero must reparse to zero");
    } else {
        assert_eq!(
            reparsed.to_bits(),
            f.to_bits(),
            "oracle token {oracle:?} does not round-trip: bits 0x{:016x} → 0x{:016x}",
            f.to_bits(),
            reparsed.to_bits()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Curated boundary corpus
// ─────────────────────────────────────────────────────────────────────────────

/// Boundary values around every notation band edge, plus IEEE 754
/// extremes, the 2^53 integer-exactness ladder, and the can-011 fixture
/// values. Each is tested with both signs.
// The over-precise 123456789.123456789 literal is deliberate: the corpus
// wants "the double nearest that decimal", however it rounds.
#[allow(clippy::excessive_precision)]
fn curated_corpus() -> Vec<f64> {
    // Largest double strictly below 1e21 (the high band edge). 1e21 is
    // exactly representable (5^21 < 2^53) with ulp 2^17 = 131072, so
    // subtracting 65537 (> half an ulp) rounds down to the predecessor.
    let below_1e21 = 1e21_f64 - 65537.0;
    assert_eq!(
        below_1e21.to_bits(),
        1e21_f64.to_bits() - 1,
        "corpus construction: 1e21 - 65537 must be the predecessor of 1e21"
    );

    vec![
        // Notation band edges (RFC 8785 §3.2.2.3 / ES steps 6–10).
        1e20,
        1e21,
        below_1e21,
        1e-6,
        1e-7,
        // IEEE 754 extremes.
        5e-324, // minimum positive subnormal
        f64::MAX,
        f64::MIN_POSITIVE, // minimum positive normal
        // 2^53 integer-exactness ladder. 2^53 + 1 is not representable;
        // the literal rounds to 2^53 — the corpus entry is the rounded
        // double, per the task charter ("as f64").
        9007199254740991.0, // 2^53 − 1
        9007199254740992.0, // 2^53
        9007199254740993.0, // 2^53 + 1 → rounds to 2^53
        // Everyday decimals.
        0.1,
        1.0 / 3.0,
        123456789.123456789,
        // Zeros (sign must be erased).
        -0.0,
        0.0,
        // can-011 vector values (see also the fixture tests below).
        1e22,
        1.23e25,
        1e100,
        1e-10,
        5e-9,
        1e-20,
        100.0,
        1000000.5,
        12345.6789,
        1.1,
        1.5,
        1.7976931348623157e308,
    ]
}

#[test]
fn curated_boundary_corpus_matches_oracle() {
    for &f in &curated_corpus() {
        assert_number_differential(f);
        assert_number_differential(-f);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RFC 8785 Appendix B published vectors
//
// (IEEE 754 bit pattern, expected ES6 string) pairs from the RFC 8785
// Appendix B table. Every entry below was re-verified against a real
// ECMAScript engine (Node.js/V8 `String(buf.readDoubleBE(0))`) before
// being pinned, so it anchors BOTH the production code and the oracle to
// ground truth. The Appendix's NaN/Infinity rows are error cases in JSON
// and are asserted separately.
// ─────────────────────────────────────────────────────────────────────────────

const RFC8785_APPENDIX_B: &[(u64, &str)] = &[
    (0x0000000000000000, "0"),      // zero
    (0x8000000000000000, "0"),      // minus zero → "0"
    (0x0000000000000001, "5e-324"), // min positive subnormal
    (0x8000000000000001, "-5e-324"),
    (0x7fefffffffffffff, "1.7976931348623157e+308"), // max positive
    (0xffefffffffffffff, "-1.7976931348623157e+308"),
    (0x4340000000000000, "9007199254740992"), // 2^53
    (0xc340000000000000, "-9007199254740992"),
    (0x4430000000000000, "295147905179352830000"), // 2^68, decimal band
    (0x44b52d02c7e14af5, "9.999999999999997e+22"),
    (0x44b52d02c7e14af6, "1e+23"),
    (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
    (0x444b1ae4d6e2ef4e, "999999999999999700000"),
    (0x444b1ae4d6e2ef4f, "999999999999999900000"),
    (0x444b1ae4d6e2ef50, "1e+21"), // decimal→exponential boundary
    (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
    (0x3eb0c6f7a0b5ed8d, "0.000001"), // exponential→decimal boundary
    (0x41b3de4355555553, "333333333.3333332"),
    (0x41b3de4355555554, "333333333.33333325"),
    (0x41b3de4355555555, "333333333.3333333"),
    (0x41b3de4355555556, "333333333.3333334"),
    (0x41b3de4355555557, "333333333.33333343"),
    (0xbecbf647612f3696, "-0.0000033333333333333333"),
    // "Round to even": an exact shortest-digits tie; ECMA-262 step 5
    // requires the even candidate. See the regression test below for the
    // history of this vector.
    (0x43143ff3c1cb0959, "1424953923781206.2"),
];

#[test]
fn rfc8785_appendix_b_vectors() {
    for &(bits, expected) in RFC8785_APPENDIX_B {
        let f = f64::from_bits(bits);
        assert_eq!(
            jcs_number_token(f),
            expected,
            "production mismatch for Appendix B bits=0x{bits:016x}"
        );
        assert_eq!(
            es_number_to_string(f),
            expected,
            "oracle mismatch for Appendix B bits=0x{bits:016x}"
        );
    }
}

/// REGRESSION (divergence found by this suite 2026-07, fixed same round):
/// the RFC 8785 Appendix B "Round to even" vector.
///
/// - Input bits:       0x43143ff3c1cb0959
/// - Exact value:      1424953923781206.25 (a perfect shortest-digits tie:
///   both "…206.2" and "…206.3" round-trip to these bits, each 0.05 away)
/// - ECMAScript / RFC: "1424953923781206.2" (ECMA-262 §6.1.6.1.20 step 5:
///   "If there are two such possible values of s, choose the one that is
///   even" — verified against Node.js/V8)
/// - Rust `{:e}` alone: "1424953923781206.3" (breaks the tie upward)
///
/// `write_number` now applies `round_half_even_correction` (exact-integer
/// midpoint detection on the bit pattern) before band formatting, and the
/// oracle applies its own independent `apply_even_tie_rule` — both anchored
/// to engine ground truth here. If either regresses, this test fails.
#[test]
fn rfc8785_appendix_b_round_to_even_regression() {
    let f = f64::from_bits(0x43143ff3c1cb0959);
    assert_eq!(jcs_number_token(f), "1424953923781206.2", "production");
    assert_eq!(es_number_to_string(f), "1424953923781206.2", "oracle");
    // The negative twin exercises the sign-independent path.
    assert_eq!(jcs_number_token(-f), "-1424953923781206.2", "negative");
    // A neighboring non-tie value must be untouched by the correction.
    let non_tie = f64::from_bits(0x43143ff3c1cb095a);
    assert_eq!(jcs_number_token(non_tie), es_number_to_string(non_tie));
}

#[test]
fn rfc8785_appendix_b_non_finite_are_unrepresentable() {
    // Appendix B rows 0x7fffffffffffffff (NaN) and 0x7ff0000000000000
    // (Infinity) must be rejected before canonicalization; serde_json's
    // safe API cannot even build them as Numbers.
    for bits in [
        0x7fffffffffffffff_u64,
        0x7ff0000000000000,
        0xfff0000000000000,
    ] {
        let f = f64::from_bits(bits);
        assert!(serde_json::Number::from_f64(f).is_none());
        assert!(serde_json::Value::from(f).is_null());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// can-011 conformance vectors (embedded copies + optional live fixture)
// ─────────────────────────────────────────────────────────────────────────────

/// (input JSON text, expected canonical form, expected SHA-256 hex) —
/// embedded verbatim from
/// `schemas/conformance/can-011-jcs-numeric-vectors.json` in the spec
/// repo, so the vectors hold even when the fixture is not co-located.
/// `can011_fixture_file_matches_embedded_vectors` cross-checks these
/// against the live fixture when it is present.
const CAN011_VECTORS: &[(&str, &str, &str)] = &[
    (
        r#"{"values":[1e21,1e22,1.23e25,1e100]}"#,
        r#"{"values":[1e+21,1e+22,1.23e+25,1e+100]}"#,
        "881882253d72cbf9717fe390b583e608c67cef87ea42741c4607f69734ab7437",
    ),
    (
        r#"{"values":[1e-7,1e-10,5e-9,1e-20]}"#,
        r#"{"values":[1e-7,1e-10,5e-9,1e-20]}"#,
        "f0e09d362698146665218833beb09f3713b0d07263a1200a4c4ef2505c657aa9",
    ),
    (
        r#"{"values":[1e-6,0.1,100,1000000.5,12345.6789]}"#,
        r#"{"values":[0.000001,0.1,100,1000000.5,12345.6789]}"#,
        "0eeda601dd06670a598ef66014dabf2495f917e962413ca9526b59b136457469",
    ),
    (
        r#"{"values":[9007199254740992,1000000000000000,0,42,-7]}"#,
        r#"{"values":[9007199254740992,1000000000000000,0,42,-7]}"#,
        "0b0cb037d8a08b7c2a99e5e57237fc2ea72431cf8006542102a71c30d9fb0e85",
    ),
    (
        r#"{"values":[-0.0,1.1,1.5,0.0]}"#,
        r#"{"values":[0,1.1,1.5,0]}"#,
        "bf5a988fe80cd62911c9609646535415e9cd392fa724d74eb587510e90bf8865",
    ),
    (
        r#"{"values":[1.7976931348623157e308,5e-324]}"#,
        r#"{"values":[1.7976931348623157e+308,5e-324]}"#,
        "41e99ffc170922788df5c6f64528212004aa0024936895933c21d9c5487e2a41",
    ),
];

fn canonicalize_json_text(input: &str) -> (String, String) {
    let v: serde_json::Value = serde_json::from_str(input).expect("vector input parses");
    let bytes = try_canonicalize_value(&v).expect("shallow vector canonicalizes");
    let canonical = String::from_utf8(bytes.clone()).expect("JCS output is UTF-8");
    let sha = hex::encode(Sha256::digest(&bytes));
    (canonical, sha)
}

#[test]
fn can011_embedded_vectors() {
    for (input, expected_canonical, expected_sha) in CAN011_VECTORS {
        let (canonical, sha) = canonicalize_json_text(input);
        assert_eq!(&canonical, expected_canonical, "input={input}");
        assert_eq!(&sha, expected_sha, "input={input}");
    }
}

/// Locate the spec checkout the same way `tests/conformance.rs` in the
/// workspace root does: `ACDP_SPEC_DIR`, else the monorepo sibling
/// directory. Returns `None` (test skips gracefully) when unavailable.
fn spec_dir() -> Option<std::path::PathBuf> {
    if let Ok(env) = std::env::var("ACDP_SPEC_DIR") {
        let p = std::path::PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
    }
    // CARGO_MANIFEST_DIR = <repo>/crates/acdp-jcs → sibling of <repo>.
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sibling = manifest_dir
        .ancestors()
        .nth(3)?
        .join("agentcontextdistributionprotocol");
    sibling.exists().then_some(sibling)
}

#[test]
fn can011_fixture_file_matches_embedded_vectors() {
    let Some(dir) = spec_dir() else {
        eprintln!("can-011 fixture: spec checkout not found (set ACDP_SPEC_DIR); skipping");
        return;
    };
    let path = dir.join("schemas/conformance/can-011-jcs-numeric-vectors.json");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        eprintln!("can-011 fixture missing at {}; skipping", path.display());
        return;
    };
    let fixture: serde_json::Value = serde_json::from_str(&raw).expect("fixture parses");
    let vectors = fixture["vectors"].as_array().expect("fixture has vectors");
    assert_eq!(
        vectors.len(),
        CAN011_VECTORS.len(),
        "embedded can-011 copies are stale: vector count changed in {}",
        path.display()
    );
    for vector in vectors {
        let name = vector["name"].as_str().unwrap_or("<unnamed>");
        let expected_canonical = vector["expected"]["canonical_form"]
            .as_str()
            .expect("canonical_form");
        let expected_sha = vector["expected"]["sha256_hex"]
            .as_str()
            .expect("sha256_hex");

        let bytes = try_canonicalize_value(&vector["input"]).expect("fixture input canonicalizes");
        let canonical = String::from_utf8(bytes.clone()).unwrap();
        let sha = hex::encode(Sha256::digest(&bytes));
        assert_eq!(canonical, expected_canonical, "vector: {name}");
        assert_eq!(sha, expected_sha, "vector: {name}");

        // Guard against the embedded copies drifting from the fixture.
        assert!(
            CAN011_VECTORS
                .iter()
                .any(|(_, c, s)| *c == expected_canonical && *s == expected_sha),
            "fixture vector {name:?} has no matching embedded copy — update CAN011_VECTORS"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property-based differential
// ─────────────────────────────────────────────────────────────────────────────

/// Bit-pattern neighborhoods of every notation-band boundary: uniform bit
/// fuzzing almost never lands within an ulp of 1e21 / 1e-6 / 2^53, so we
/// jitter the exact boundary bit patterns by a few thousand ulps.
fn boundary_neighborhood() -> impl Strategy<Value = f64> {
    let bases: Vec<u64> = [
        1e21_f64,
        1e20,
        1e22,
        1e-6,
        1e-7,
        1e-5,
        9007199254740992.0, // 2^53
        1.0,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::from_bits(1), // 5e-324
    ]
    .iter()
    .map(|f| f.to_bits())
    .collect();

    (prop::sample::select(bases), -4096_i64..=4096, any::<bool>()).prop_map(
        |(base, offset, negate)| {
            // Offsetting the bit pattern moves an exact number of ulps.
            // Clamp into the positive-finite range (bit patterns 1 ..=
            // f64::MAX bits), then apply the sign.
            let bits = (base as i64)
                .saturating_add(offset)
                .clamp(1, f64::MAX.to_bits() as i64) as u64;
            let f = f64::from_bits(bits);
            if negate {
                -f
            } else {
                f
            }
        },
    )
}

/// Mantissa × 10^exp values biased toward the plain-decimal band, which
/// uniform 64-bit patterns (dominated by huge/tiny binary exponents)
/// rarely produce.
fn decimal_band_biased() -> impl Strategy<Value = f64> {
    (any::<i64>(), -30_i32..=30).prop_map(|(m, e)| (m as f64) * 10f64.powi(e))
}

proptest! {
    /// Arbitrary finite doubles via raw bit patterns — every f64 is fair
    /// game, including subnormals.
    #[test]
    fn differential_arbitrary_bit_patterns(bits in any::<u64>()) {
        let f = f64::from_bits(bits);
        prop_assume!(f.is_finite());
        // Skip values whose serde_json Number round-trip changes them
        // (none are expected with `float_roundtrip`; this guards the
        // harness, not the crate).
        let n = serde_json::Number::from_f64(f).expect("finite");
        prop_assume!(n.as_f64() == Some(f));
        assert_number_differential(f);
    }

    /// Dense coverage within a few thousand ulps of every band boundary.
    #[test]
    fn differential_band_boundaries(f in boundary_neighborhood()) {
        assert_number_differential(f);
    }

    /// Human-scale decimals across the plain-decimal band and both
    /// crossovers into exponential notation.
    #[test]
    fn differential_decimal_band(f in decimal_band_biased()) {
        prop_assume!(f.is_finite()); // m × 10^e is always finite here, but stay total
        assert_number_differential(f);
    }
}
