//! RFC 6962-style Merkle tree machinery for the ACDP registry
//! transparency log (RFC-ACDP-0012 §5, §9).
//!
//! Pure functions over raw 32-byte SHA-256 digests — no I/O, no wire
//! shapes (those live in `acdp-types::log`), usable under
//! `--no-default-features`. The RFC-ACDP-0012 hash-valued wire strings
//! (`"sha256:<hex>"`) are decoded/encoded by the callers; everything
//! here operates on the digests those strings encode (RFC-ACDP-0012 §2).
//!
//! The `0x00`/`0x01` domain-separation prefixes of RFC 6962 §2.1 are
//! REQUIRED (RFC-ACDP-0012 §5.1): they provide second-preimage
//! separation between leaves and interior nodes — without them, an
//! attacker who can choose leaf bytes could present an interior node's
//! 64-byte child concatenation as a "leaf" and forge proofs for entries
//! that were never appended.

use sha2::{Digest, Sha256};

/// The single prefix byte hashed before leaf bytes (RFC 6962 §2.1;
/// RFC-ACDP-0012 §5.1): `leaf_hash = SHA-256(0x00 ‖ leaf_bytes)`.
pub const LEAF_HASH_PREFIX: u8 = 0x00;

/// The single prefix byte hashed before interior-node children
/// (RFC 6962 §2.1; RFC-ACDP-0012 §5.1):
/// `node_hash = SHA-256(0x01 ‖ left ‖ right)`.
pub const NODE_HASH_PREFIX: u8 = 0x01;

/// `leaf_hash(leaf) = SHA-256(0x00 ‖ leaf_bytes)` (RFC-ACDP-0012 §5.1).
///
/// For transparency-log leaves, `leaf_bytes` is the JCS canonicalization
/// (RFC 8785) of the closed leaf object — there is no exclusion set.
pub fn leaf_hash(leaf_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_HASH_PREFIX]);
    h.update(leaf_bytes);
    h.finalize().into()
}

/// `node_hash(left, right) = SHA-256(0x01 ‖ left ‖ right)` over raw
/// 32-byte child digests (RFC-ACDP-0012 §5.1).
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_HASH_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The largest power of two **strictly less than** `n` (RFC 6962 §2.1's
/// split point `k`). Caller guarantees `n >= 2`.
fn largest_pow2_lt(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// RFC 6962 §2.1 Merkle Tree Hash `MTH(D[n])` over an ordered list of
/// leaf hashes (RFC-ACDP-0012 §5.2):
///
/// ```text
/// MTH({})   = SHA-256("")                       // empty tree
/// MTH({d})  = d                                 // d is already 0x00-prefixed
/// MTH(D[n]) = node_hash(MTH(D[0:k]), MTH(D[k:n]))
///             where k is the largest power of two strictly less than n
/// ```
pub fn merkle_tree_hash(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    match leaf_hashes.len() {
        0 => Sha256::digest(b"").into(),
        1 => leaf_hashes[0],
        n => {
            let k = largest_pow2_lt(n);
            node_hash(
                &merkle_tree_hash(&leaf_hashes[..k]),
                &merkle_tree_hash(&leaf_hashes[k..]),
            )
        }
    }
}

/// RFC 6962 §2.1.1 audit path `PATH(m, D[n])` for the leaf at index
/// `leaf_index` in the tree over `leaf_hashes` (`n = leaf_hashes.len()`),
/// ordered from the lowest tree level upward (RFC-ACDP-0012 §8.2):
///
/// ```text
/// PATH(m, {d})  = {}
/// PATH(m, D[n]) = PATH(m, D[0:k])     : MTH(D[k:n])   for m <  k
///               = PATH(m − k, D[k:n]) : MTH(D[0:k])   for m >= k
/// ```
///
/// Returns `None` when `leaf_index >= leaf_hashes.len()` or the tree is
/// empty (no proof exists).
pub fn inclusion_path(leaf_index: usize, leaf_hashes: &[[u8; 32]]) -> Option<Vec<[u8; 32]>> {
    let n = leaf_hashes.len();
    if leaf_index >= n {
        return None;
    }
    if n == 1 {
        return Some(Vec::new());
    }
    let k = largest_pow2_lt(n);
    let mut path = if leaf_index < k {
        let mut p = inclusion_path(leaf_index, &leaf_hashes[..k])?;
        p.push(merkle_tree_hash(&leaf_hashes[k..]));
        p
    } else {
        let mut p = inclusion_path(leaf_index - k, &leaf_hashes[k..])?;
        p.push(merkle_tree_hash(&leaf_hashes[..k]));
        p
    };
    path.shrink_to_fit();
    Some(path)
}

/// RFC 6962 §2.1.2 consistency proof `PROOF(m, D[n])` between the tree
/// of size `first` and the tree over `leaf_hashes`
/// (`n = leaf_hashes.len()`), demonstrating that `D[0:first]` is a
/// prefix of `D[n]` (RFC-ACDP-0012 §8.2, §9.2):
///
/// ```text
/// PROOF(m, D[n])       = SUBPROOF(m, D[n], true)
/// SUBPROOF(m, D[m], true)  = {}                      // shared MTH is known
/// SUBPROOF(m, D[m], false) = {MTH(D[m])}
/// SUBPROOF(m, D[n], b) for m < n, k = largest pow2 < n:
///   m <= k: SUBPROOF(m, D[0:k], b)         : MTH(D[k:n])
///   m >  k: SUBPROOF(m − k, D[k:n], false) : MTH(D[0:k])
/// ```
///
/// Returns `None` unless `0 < first <= leaf_hashes.len()`. The proof is
/// empty exactly when `first == leaf_hashes.len()`.
pub fn consistency_proof(first: usize, leaf_hashes: &[[u8; 32]]) -> Option<Vec<[u8; 32]>> {
    if first == 0 || first > leaf_hashes.len() {
        return None;
    }

    fn subproof(m: usize, d: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
        let n = d.len();
        if m == n {
            return if b {
                Vec::new()
            } else {
                vec![merkle_tree_hash(d)]
            };
        }
        let k = largest_pow2_lt(n);
        let mut p = if m <= k {
            let mut p = subproof(m, &d[..k], b);
            p.push(merkle_tree_hash(&d[k..]));
            p
        } else {
            let mut p = subproof(m - k, &d[k..], false);
            p.push(merkle_tree_hash(&d[..k]));
            p
        };
        p.shrink_to_fit();
        p
    }

    Some(subproof(first, leaf_hashes, true))
}

/// Verify an inclusion proof: fold `path` over `leaf_hash` and compare
/// against `root` — the RFC 9162 §2.1.3.2 algorithm transcribed in
/// RFC-ACDP-0012 §9.1 steps 5–6.
///
/// Steps (RFC-ACDP-0012 §9.1):
/// 5. Let `fn = leaf_index`, `sn = tree_size − 1`, `r = leaf_hash`.
///    For each element `p` of the path in order:
///    1. If `sn == 0`, fail (path too long).
///    2. If `fn` is odd, or `fn == sn`: `r = node_hash(p, r)`; then, if
///       `fn` is even, right-shift both `fn` and `sn` until `fn` is odd
///       or `fn == 0`.
///    3. Otherwise: `r = node_hash(r, p)`.
///    4. Right-shift both `fn` and `sn` by one.
/// 6. After consuming the whole path, `sn` MUST equal 0 and `r` MUST
///    equal `root`. Any leftover path, premature exhaustion, or
///    mismatch fails.
#[must_use]
pub fn verify_inclusion(
    leaf_hash: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    // §9.1 step 5: fn = leaf_index, sn = tree_size − 1, r = leaf_hash.
    let mut fnode = leaf_index;
    let mut snode = tree_size - 1;
    let mut r = *leaf_hash;
    for p in path {
        // §9.1 step 5.1: path longer than the tree height.
        if snode == 0 {
            return false;
        }
        if fnode % 2 == 1 || fnode == snode {
            // §9.1 step 5.2: the sibling is on the left.
            r = node_hash(p, &r);
            if fnode.is_multiple_of(2) {
                while fnode.is_multiple_of(2) && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            // §9.1 step 5.3: the sibling is on the right.
            r = node_hash(&r, p);
        }
        // §9.1 step 5.4.
        fnode >>= 1;
        snode >>= 1;
    }
    // §9.1 step 6: full consumption and root equality.
    snode == 0 && r == *root
}

/// Verify a consistency proof between the tree of size `first` (root
/// `first_root`) and the tree of size `second` (root `second_root`) —
/// the RFC 9162 §2.1.4.2 algorithm transcribed in RFC-ACDP-0012 §9.2.
///
/// Steps (RFC-ACDP-0012 §9.2):
/// 1. If `first == second`: the path MUST be empty and the roots equal.
/// 2. If `first == 0`, `first > second`, or the path is empty, fail (an
///    empty tree is trivially consistent with anything; registries
///    never prove it, verifiers never demand it).
/// 3. If `first` is an exact power of two, prepend `first_root` to the
///    path.
/// 4. Let `fn = first − 1`, `sn = second − 1`. While `fn` is odd,
///    right-shift both by one.
/// 5. Let `fr = sr = path[0]`. For each subsequent element `c`:
///    1. If `sn == 0`, fail.
///    2. If `fn` is odd, or `fn == sn`: `fr = node_hash(c, fr)` and
///       `sr = node_hash(c, sr)`; then, if `fn` is even, right-shift
///       both `fn` and `sn` until `fn` is odd or `fn == 0`.
///    3. Otherwise: `sr = node_hash(sr, c)`.
///    4. Right-shift both `fn` and `sn` by one.
/// 6. `fr` MUST equal `first_root`, `sr` MUST equal `second_root`, and
///    `sn` MUST equal 0.
#[must_use]
pub fn verify_consistency(
    first: u64,
    second: u64,
    path: &[[u8; 32]],
    first_root: &[u8; 32],
    second_root: &[u8; 32],
) -> bool {
    // §9.2 step 1: equal sizes — empty path, identical roots.
    if first == second {
        return path.is_empty() && first_root == second_root;
    }
    // §9.2 step 2.
    if first == 0 || first > second || path.is_empty() {
        return false;
    }
    // §9.2 step 3: when `first` is an exact power of two, the verifier
    // already knows the left subtree's hash — it IS first_root.
    let mut elements: Vec<&[u8; 32]> = Vec::with_capacity(path.len() + 1);
    if first & (first - 1) == 0 {
        elements.push(first_root);
    }
    elements.extend(path.iter());
    let mut elements = elements.into_iter();
    // §9.2 step 4.
    let mut fnode = first - 1;
    let mut snode = second - 1;
    while fnode % 2 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    // §9.2 step 5: seed both running roots from the first element.
    let Some(first_el) = elements.next() else {
        return false;
    };
    let mut fr = *first_el;
    let mut sr = *first_el;
    for c in elements {
        // §9.2 step 5.1.
        if snode == 0 {
            return false;
        }
        if fnode % 2 == 1 || fnode == snode {
            // §9.2 step 5.2: node on the left of both subtrees.
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnode.is_multiple_of(2) {
                while fnode.is_multiple_of(2) && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            // §9.2 step 5.3: node on the right, second tree only.
            sr = node_hash(&sr, c);
        }
        // §9.2 step 5.4.
        fnode >>= 1;
        snode >>= 1;
    }
    // §9.2 step 6.
    fr == *first_root && sr == *second_root && snode == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
            .collect()
    }

    /// RFC-ACDP-0012 §5.2: the empty tree's root is SHA-256("").
    #[test]
    fn empty_tree_root_is_sha256_of_empty_string() {
        assert_eq!(
            hex::encode(merkle_tree_hash(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Domain separation: a leaf hashed as a node (or vice versa) never
    /// collides (RFC-ACDP-0012 §5.1).
    #[test]
    fn prefixes_domain_separate() {
        let l = [7u8; 32];
        let r = [9u8; 32];
        let mut concat = Vec::new();
        concat.extend_from_slice(&l);
        concat.extend_from_slice(&r);
        assert_ne!(node_hash(&l, &r), leaf_hash(&concat));
    }

    /// The generator's own self-check, transcribed (RFC-ACDP-0012 §14):
    /// for all tree sizes ≤ 8, every inclusion proof and every
    /// consistency proof verifies against brute-force recomputation,
    /// and single-bit tampering of any element fails.
    #[test]
    fn inclusion_and_consistency_exhaustive_to_8() {
        for n in 1..=8usize {
            let d = leaves(n);
            let root = merkle_tree_hash(&d);
            for m in 0..n {
                let path = inclusion_path(m, &d).expect("path exists");
                assert!(
                    verify_inclusion(&d[m], m as u64, n as u64, &path, &root),
                    "PATH({m}, D[{n}]) must verify"
                );
                // Tampered leaf hash fails.
                let mut bad_leaf = d[m];
                bad_leaf[0] ^= 1;
                assert!(!verify_inclusion(
                    &bad_leaf, m as u64, n as u64, &path, &root
                ));
                // Tampered path element fails; truncated/extended fail.
                for i in 0..path.len() {
                    let mut bad = path.clone();
                    bad[i][0] ^= 1;
                    assert!(!verify_inclusion(&d[m], m as u64, n as u64, &bad, &root));
                }
                if !path.is_empty() {
                    assert!(!verify_inclusion(
                        &d[m],
                        m as u64,
                        n as u64,
                        &path[..path.len() - 1],
                        &root
                    ));
                }
                let mut long = path.clone();
                long.push([0u8; 32]);
                assert!(!verify_inclusion(&d[m], m as u64, n as u64, &long, &root));
            }
            for m in 1..=n {
                let first_root = merkle_tree_hash(&d[..m]);
                let proof = consistency_proof(m, &d).expect("proof exists");
                assert!(
                    verify_consistency(m as u64, n as u64, &proof, &first_root, &root),
                    "PROOF({m}, D[{n}]) must verify"
                );
                if m == n {
                    assert!(proof.is_empty());
                }
                for i in 0..proof.len() {
                    let mut bad = proof.clone();
                    bad[i][0] ^= 1;
                    assert!(!verify_consistency(
                        m as u64,
                        n as u64,
                        &bad,
                        &first_root,
                        &root
                    ));
                }
                if m < n {
                    // Swapped roots fail.
                    assert!(!verify_consistency(
                        m as u64,
                        n as u64,
                        &proof,
                        &root,
                        &first_root
                    ));
                }
            }
        }
    }

    /// §9.2 step 2: first == 0 and first > second always fail; an empty
    /// path fails unless first == second.
    #[test]
    fn consistency_degenerate_cases() {
        let d = leaves(4);
        let root = merkle_tree_hash(&d);
        let empty_root = merkle_tree_hash(&[]);
        assert!(!verify_consistency(0, 4, &[], &empty_root, &root));
        assert!(!verify_consistency(0, 4, &[[0u8; 32]], &empty_root, &root));
        assert!(!verify_consistency(5, 4, &[[0u8; 32]], &root, &root));
        assert!(!verify_consistency(
            2,
            4,
            &[],
            &merkle_tree_hash(&d[..2]),
            &root
        ));
        // first == second: empty path + equal roots verify.
        assert!(verify_consistency(4, 4, &[], &root, &root));
        assert!(!verify_consistency(4, 4, &[[0u8; 32]], &root, &root));
        assert!(!verify_consistency(
            4,
            4,
            &[],
            &merkle_tree_hash(&d[..2]),
            &root
        ));
        // Out-of-range generation requests refuse.
        assert!(inclusion_path(4, &d).is_none());
        assert!(inclusion_path(0, &[]).is_none());
        assert!(consistency_proof(0, &d).is_none());
        assert!(consistency_proof(5, &d).is_none());
    }
}
