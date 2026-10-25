//! The deterministic breadth-first walk (RFC-ACDP-0017 §6.1), cycle
//! detection, and shortest tainted paths (§8.3).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::evidence::Parsed;
use crate::options::Limits;
use crate::verdict::Control;

/// What the walk admitted.
pub(crate) struct Walk {
    /// Admitted `ctx_id` → depth.
    pub depth: BTreeMap<String, u32>,
    /// The edges the walk considered (from expanded nodes, within fanout).
    pub edges: BTreeMap<String, Vec<String>>,
    /// Referenced but not admitted, sorted.
    pub frontier: Vec<String>,
    /// The first control that fired, in walk order.
    pub control: Option<Control>,
    /// The roots, sorted and deduplicated.
    pub roots: Vec<String>,
}

pub(crate) fn walk(
    roots: &[String],
    parsed: &Parsed<'_>,
    limits: Limits,
    should_stop: &mut dyn FnMut() -> bool,
) -> Walk {
    let mut roots = roots.to_vec();
    roots.sort();
    roots.dedup();

    let mut depth: BTreeMap<String, u32> = BTreeMap::new();
    let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    // (ctx_id, control) in walk order; the first whose ctx_id ends up
    // unadmitted names the control (§6.1(4)).
    let mut fired: Vec<(String, Control)> = Vec::new();
    let mut timeout = false;

    let max_nodes = limits.max_nodes as usize;
    for r in &roots {
        referenced.insert(r.clone());
        if depth.len() < max_nodes {
            depth.insert(r.clone(), 0);
        } else {
            fired.push((r.clone(), Control::MaxNodes));
        }
    }

    let mut level: Vec<String> = depth.keys().cloned().collect();
    let mut d = 0u32;
    'walk: while !level.is_empty() {
        let mut next = Vec::new();
        for node in &level {
            if should_stop() {
                timeout = true;
                break 'walk;
            }
            let Some(pc) = parsed.contexts.get(node.as_str()) else {
                continue;
            };
            let mut distinct: Vec<String> = Vec::new();
            for e in &pc.body.derived_from {
                let e = e.as_str().to_string();
                if !distinct.contains(&e) {
                    distinct.push(e);
                }
            }
            if d >= limits.max_depth {
                for e in distinct {
                    referenced.insert(e.clone());
                    fired.push((e, Control::MaxDepth));
                }
                continue;
            }
            let fanout = limits.max_fanout as usize;
            for (i, e) in distinct.into_iter().enumerate() {
                referenced.insert(e.clone());
                if i >= fanout {
                    fired.push((e, Control::MaxFanout));
                    continue;
                }
                edges.entry(node.clone()).or_default().push(e.clone());
                if depth.contains_key(&e) {
                    continue; // DAG join
                }
                if depth.len() >= max_nodes {
                    fired.push((e, Control::MaxNodes));
                    continue;
                }
                depth.insert(e.clone(), d + 1);
                next.push(e);
            }
        }
        next.sort();
        level = next;
        d += 1;
    }

    let frontier: Vec<String> = referenced
        .into_iter()
        .filter(|c| !depth.contains_key(c))
        .collect();
    let control = if timeout {
        Some(Control::Timeout)
    } else {
        fired
            .iter()
            .find(|(c, _)| !depth.contains_key(c))
            .map(|(_, k)| *k)
    };
    Walk {
        depth,
        edges,
        frontier,
        control,
        roots,
    }
}

/// Every node that lies on a cycle of the considered edges: members of
/// a strongly connected component of size > 1, or with a self-edge.
pub(crate) fn cycle_nodes(walk: &Walk) -> BTreeSet<String> {
    // Iterative Tarjan over the admitted nodes, in byte order.
    struct State {
        index: BTreeMap<String, usize>,
        low: BTreeMap<String, usize>,
        on_stack: BTreeSet<String>,
        stack: Vec<String>,
        next: usize,
        out: BTreeSet<String>,
    }
    let mut st = State {
        index: BTreeMap::new(),
        low: BTreeMap::new(),
        on_stack: BTreeSet::new(),
        stack: Vec::new(),
        next: 0,
        out: BTreeSet::new(),
    };
    let empty = Vec::new();
    let succ = |n: &str| -> &Vec<String> { walk.edges.get(n).unwrap_or(&empty) };

    for start in walk.depth.keys() {
        if st.index.contains_key(start) {
            continue;
        }
        // (node, next successor position)
        let mut call: Vec<(String, usize)> = vec![(start.clone(), 0)];
        st.index.insert(start.clone(), st.next);
        st.low.insert(start.clone(), st.next);
        st.next += 1;
        st.stack.push(start.clone());
        st.on_stack.insert(start.clone());
        while let Some((v, pos)) = call.last().cloned() {
            let succs = succ(&v);
            if pos < succs.len() {
                call.last_mut().expect("non-empty").1 += 1;
                let w = &succs[pos];
                if !walk.depth.contains_key(w) {
                    continue;
                }
                if !st.index.contains_key(w) {
                    st.index.insert(w.clone(), st.next);
                    st.low.insert(w.clone(), st.next);
                    st.next += 1;
                    st.stack.push(w.clone());
                    st.on_stack.insert(w.clone());
                    call.push((w.clone(), 0));
                } else if st.on_stack.contains(w) {
                    let lw = st.index[w];
                    let lv = st.low.get_mut(&v).expect("indexed");
                    *lv = (*lv).min(lw);
                }
                continue;
            }
            call.pop();
            if let Some((parent, _)) = call.last() {
                let lv = st.low[&v];
                let lp = st.low.get_mut(parent).expect("indexed");
                *lp = (*lp).min(lv);
            }
            if st.low[&v] == st.index[&v] {
                let mut component = Vec::new();
                loop {
                    let w = st.stack.pop().expect("on stack");
                    st.on_stack.remove(&w);
                    let done = w == v;
                    component.push(w);
                    if done {
                        break;
                    }
                }
                let self_loop = succ(&v).contains(&v);
                if component.len() > 1 || self_loop {
                    st.out.extend(component);
                }
            }
        }
    }
    st.out
}

/// For every admitted node, its shortest path from a root over the
/// considered edges, ties broken lexicographically (§8.3).
pub(crate) fn shortest_paths(walk: &Walk) -> BTreeMap<String, Vec<String>> {
    let mut best: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for r in &walk.roots {
        if walk.depth.contains_key(r) {
            best.insert(r.clone(), vec![r.clone()]);
            queue.push_back(r.clone());
        }
    }
    // Level-synchronous BFS: a node's best path is final once its level
    // is done, and only same-length candidates compete.
    while !queue.is_empty() {
        let level: Vec<String> = queue.drain(..).collect();
        let mut candidates: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for v in &level {
            let path = best[v].clone();
            for w in walk.edges.get(v).into_iter().flatten() {
                if best.contains_key(w) || !walk.depth.contains_key(w) {
                    continue;
                }
                let mut p = path.clone();
                p.push(w.clone());
                match candidates.get(w) {
                    Some(existing) if *existing <= p => {}
                    _ => {
                        candidates.insert(w.clone(), p);
                    }
                }
            }
        }
        for (w, p) in candidates {
            best.insert(w.clone(), p);
            queue.push_back(w);
        }
    }
    best
}
