'use client';

// Graph - the tenant's knowledge graph. Files and folders are nodes; the
// folder tree plus the citations and wikilinks between files are edges.
// Everything is drawn as hand-rolled SVG driven by a small force
// simulation (no D3 or graph library). Colours come by class and pass the
// dataviz six-checks validator in both light and dark; node labels are
// always on, which is the sanctioned contrast relief for the lightest hue.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import {
    DriveError,
    getGraph,
    getLint,
    type DriveGraph,
    type GraphLint,
    type NodeClass,
    type Tenant
} from '~/lib/drive-api';
import { CloseIcon, GraphIcon, LockIcon } from './icons';

// ---- Class colours + labels ------------------------------------------

const CLASSES: { key: NodeClass; label: string; cssVar: string }[] = [
    { key: 'document', label: 'Documents', cssVar: '--drv-graph-document' },
    { key: 'conversation', label: 'Conversations', cssVar: '--drv-graph-conversation' },
    { key: 'memory', label: 'Memories', cssVar: '--drv-graph-memory' }
];

/** The CSS colour for a node class; unknown classes read as muted. */
function classColour(cls: NodeClass): string {
    const c = CLASSES.find((x) => x.key === cls);
    return c ? `var(${c.cssVar})` : 'var(--drv-text-muted)';
}

function classLabel(cls: NodeClass): string {
    const c = CLASSES.find((x) => x.key === cls);
    return c ? c.label.replace(/s$/, '') : cls || 'Other';
}

// ---- Simulation model ------------------------------------------------

interface SimNode {
    id: string;
    name: string;
    cls: NodeClass;
    ghost: boolean; // a placeholder for a dangling wikilink target
    x: number;
    y: number;
    vx: number;
    vy: number;
    r: number;
}

interface SimEdge {
    from: string;
    to: string;
    kind: string;
}

interface SimData {
    nodes: SimNode[];
    edges: SimEdge[];
    /** Adjacency: node id -> set of neighbour ids. */
    neighbours: Map<string, Set<string>>;
    index: Map<string, SimNode>;
}

/** Build the simulation graph, minting ghost nodes for dangling links. */
function buildSim(graph: DriveGraph): SimData {
    const nodes: SimNode[] = [];
    const index = new Map<string, SimNode>();
    const n = graph.nodes.length || 1;

    // Seed on a ring so the layout unfolds cleanly rather than from a point.
    graph.nodes.forEach((g, i) => {
        const a = (i / n) * Math.PI * 2;
        const node: SimNode = {
            id: g.node_id,
            name: g.name,
            cls: g.class,
            ghost: false,
            x: Math.cos(a) * 180 + (Math.random() - 0.5) * 20,
            y: Math.sin(a) * 180 + (Math.random() - 0.5) * 20,
            vx: 0,
            vy: 0,
            r: g.kind === 'folder' ? 9 : 7
        };
        nodes.push(node);
        index.set(node.id, node);
    });

    const edges: SimEdge[] = [];
    graph.edges.forEach((e) => {
        let toId = e.to_node;
        if (!toId) {
            // Dangling wikilink: attach a ghost placeholder keyed to its
            // (source, target-name) so identical dead links coalesce.
            const key = e.to_name || 'unknown';
            toId = `ghost:${e.from_node}:${key}`;
            if (!index.has(toId)) {
                const ghost: SimNode = {
                    id: toId,
                    name: e.to_name || 'unknown',
                    cls: 'ghost',
                    ghost: true,
                    x: (Math.random() - 0.5) * 300,
                    y: (Math.random() - 0.5) * 300,
                    vx: 0,
                    vy: 0,
                    r: 5
                };
                nodes.push(ghost);
                index.set(toId, ghost);
            }
        }
        if (!index.has(e.from_node) || !index.has(toId)) return;
        edges.push({ from: e.from_node, to: toId, kind: e.kind });
    });

    const neighbours = new Map<string, Set<string>>();
    const link = (a: string, b: string) => {
        if (!neighbours.has(a)) neighbours.set(a, new Set());
        neighbours.get(a)!.add(b);
    };
    edges.forEach((e) => {
        link(e.from, e.to);
        link(e.to, e.from);
    });

    return { nodes, edges, neighbours, index };
}

// ---- Force constants -------------------------------------------------

const REPULSION = 5200;
const SPRING_K = 0.02;
const SPRING_LEN: Record<string, number> = { containment: 62, citation: 110, wikilink: 100 };
const CENTER_K = 0.012;
const DAMPING = 0.85;

interface View {
    tx: number;
    ty: number;
    scale: number;
}

export function GraphView({ session, tenant }: { session: SealedSession; tenant: Tenant }) {
    const [graph, setGraph] = useState<DriveGraph | null>(null);
    const [lint, setLint] = useState<GraphLint | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [forbidden, setForbidden] = useState(false);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const g = await getGraph(session, tenant.id);
            setGraph(g);
            setForbidden(false);
            // Lint is a nicety; never let it fail the view.
            getLint(session, tenant.id)
                .then(setLint)
                .catch(() => setLint(null));
        } catch (e) {
            if (e instanceof DriveError && e.status === 403) {
                setForbidden(true);
            } else {
                setError(e instanceof Error ? e.message : 'Could not load the graph.');
            }
        } finally {
            setLoading(false);
        }
    }, [session, tenant.id]);

    useEffect(() => {
        void load();
    }, [load]);

    const empty = !!graph && graph.nodes.length === 0;

    return (
        <div className="flex min-h-0 flex-1 flex-col p-4 sm:p-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                <div>
                    <h1 className="text-lg font-semibold">Graph</h1>
                    <p className="mt-0.5 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        How {tenant.kind === 'user' ? 'your files' : `${tenant.name}'s files`} link to
                        one another. Citations and wikilinks are the knowledge edges; the folder tree
                        sits faintly behind them.
                    </p>
                </div>
                {lint && (lint.dangling_links.length > 0 || lint.orphan_nodes.length > 0) && (
                    <span
                        className="rounded-full border px-3 py-1 text-xs font-medium"
                        style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}
                        title="Links that point nowhere, and nodes nothing links to"
                    >
                        {lint.dangling_links.length} dangling{' '}
                        {lint.dangling_links.length === 1 ? 'link' : 'links'}, {lint.orphan_nodes.length}{' '}
                        {lint.orphan_nodes.length === 1 ? 'orphan' : 'orphans'}
                    </span>
                )}
            </div>

            {error && (
                <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                    {error}
                </div>
            )}

            {loading ? (
                <div className="py-16 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                    Loading…
                </div>
            ) : forbidden ? (
                <div className="flex flex-col items-center justify-center py-20 text-center">
                    <LockIcon width={48} height={48} style={{ color: 'var(--drv-border)' }} />
                    <p className="mt-4 text-sm font-medium">Members only</p>
                    <p className="mt-1 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Ask a workspace owner to add you to see its graph.
                    </p>
                </div>
            ) : empty ? (
                <div className="flex flex-col items-center justify-center py-20 text-center">
                    <GraphIcon width={48} height={48} style={{ color: 'var(--drv-border)' }} />
                    <p className="mt-4 text-sm font-medium">Nothing to graph yet</p>
                    <p className="mt-1 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Once your files cite or link to one another, the connections will appear here.
                    </p>
                </div>
            ) : graph ? (
                <GraphCanvas graph={graph} />
            ) : null}
        </div>
    );
}

// ---- The interactive canvas ------------------------------------------

function GraphCanvas({ graph }: { graph: DriveGraph }) {
    const sim = useMemo(() => buildSim(graph), [graph]);

    const wrapRef = useRef<HTMLDivElement | null>(null);
    const [size, setSize] = useState({ w: 0, h: 0 });
    useEffect(() => {
        const el = wrapRef.current;
        if (!el) return;
        const ro = new ResizeObserver((entries) => {
            const r = entries[0]?.contentRect;
            if (r) setSize({ w: Math.round(r.width), h: Math.round(r.height) });
        });
        ro.observe(el);
        return () => ro.disconnect();
    }, []);

    // Positions live on the sim nodes (mutated in place by the loop). A
    // frame counter forces the re-render each animation frame without
    // churning React state, and - crucially - a positions snapshot keyed
    // on it (below) is what the marks read, so React Compiler cannot
    // memoise the layout on the stable `sim` reference and freeze it.
    const [frame, setFrame] = useState(0);
    const alphaRef = useRef(1);
    const draggingRef = useRef<string | null>(null);

    const [view, setView] = useState<View>({ tx: 0, ty: 0, scale: 1 });
    const viewRef = useRef(view);
    viewRef.current = view;

    // Centre the world origin on first measure.
    const centred = useRef(false);
    useEffect(() => {
        if (!centred.current && size.w > 0 && size.h > 0) {
            setView({ tx: size.w / 2, ty: size.h / 2, scale: 1 });
            centred.current = true;
        }
    }, [size]);

    const [selected, setSelected] = useState<string | null>(null);
    const [hover, setHover] = useState<string | null>(null);

    // Reheat the simulation whenever the graph changes.
    useEffect(() => {
        alphaRef.current = 1;
        setSelected(null);
    }, [sim]);

    // The force loop is restartable: it sleeps once the layout cools, and a
    // reheat (drag start, graph change) kicks it awake again.
    const rafRef = useRef(0);
    const runningRef = useRef(false);

    const startLoop = useCallback(() => {
        if (runningRef.current) return;
        runningRef.current = true;
        const nodes = sim.nodes;
        const tick = () => {
            const dragging = draggingRef.current;
            const alpha = alphaRef.current;

            // Pairwise repulsion (O(n^2); the graph is bounded in practice).
            for (let i = 0; i < nodes.length; i++) {
                const a = nodes[i];
                for (let j = i + 1; j < nodes.length; j++) {
                    const b = nodes[j];
                    let dx = a.x - b.x;
                    let dy = a.y - b.y;
                    let d2 = dx * dx + dy * dy;
                    if (d2 < 0.01) {
                        dx = Math.random() - 0.5;
                        dy = Math.random() - 0.5;
                        d2 = 0.01;
                    }
                    const f = REPULSION / d2;
                    const d = Math.sqrt(d2);
                    const fx = (dx / d) * f;
                    const fy = (dy / d) * f;
                    a.vx += fx;
                    a.vy += fy;
                    b.vx -= fx;
                    b.vy -= fy;
                }
            }

            // Springs along the edges.
            for (const e of sim.edges) {
                const a = sim.index.get(e.from);
                const b = sim.index.get(e.to);
                if (!a || !b) continue;
                const dx = b.x - a.x;
                const dy = b.y - a.y;
                const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
                const target = SPRING_LEN[e.kind] ?? 100;
                const f = SPRING_K * (d - target);
                const fx = (dx / d) * f;
                const fy = (dy / d) * f;
                a.vx += fx;
                a.vy += fy;
                b.vx -= fx;
                b.vy -= fy;
            }

            // Weak pull toward the world origin, then integrate.
            let motion = 0;
            for (const nd of nodes) {
                if (nd.id === dragging) {
                    nd.vx = 0;
                    nd.vy = 0;
                    continue;
                }
                nd.vx -= nd.x * CENTER_K;
                nd.vy -= nd.y * CENTER_K;
                nd.vx *= DAMPING;
                nd.vy *= DAMPING;
                nd.x += nd.vx * alpha;
                nd.y += nd.vy * alpha;
                motion += Math.abs(nd.vx) + Math.abs(nd.vy);
            }

            if (!dragging) alphaRef.current = Math.max(0, alpha * 0.985);
            setFrame((f) => (f + 1) & 0xffff);

            if (dragging || (alphaRef.current > 0.02 && motion > 0.5)) {
                rafRef.current = requestAnimationFrame(tick);
            } else {
                runningRef.current = false;
                rafRef.current = 0;
            }
        };
        rafRef.current = requestAnimationFrame(tick);
    }, [sim]);

    useEffect(() => {
        startLoop();
        return () => {
            if (rafRef.current) cancelAnimationFrame(rafRef.current);
            runningRef.current = false;
            rafRef.current = 0;
        };
    }, [startLoop]);

    const reheat = useCallback(() => {
        if (alphaRef.current < 0.35) alphaRef.current = 0.5;
        startLoop();
    }, [startLoop]);

    // Screen <-> world helpers.
    const toWorld = useCallback((clientX: number, clientY: number) => {
        const rect = wrapRef.current?.getBoundingClientRect();
        const v = viewRef.current;
        const sx = clientX - (rect?.left ?? 0);
        const sy = clientY - (rect?.top ?? 0);
        return { x: (sx - v.tx) / v.scale, y: (sy - v.ty) / v.scale };
    }, []);

    // Pointer interactions: drag a node, pan the background.
    const dragMovedRef = useRef(false);
    const panRef = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null);

    const onNodePointerDown = useCallback(
        (e: React.PointerEvent, id: string) => {
            e.stopPropagation();
            (e.target as Element).setPointerCapture?.(e.pointerId);
            draggingRef.current = id;
            dragMovedRef.current = false;
            reheat();
        },
        [reheat]
    );

    const onPointerMove = useCallback(
        (e: React.PointerEvent) => {
            const id = draggingRef.current;
            if (id) {
                const p = toWorld(e.clientX, e.clientY);
                const nd = sim.index.get(id);
                if (nd) {
                    nd.x = p.x;
                    nd.y = p.y;
                    nd.vx = 0;
                    nd.vy = 0;
                }
                dragMovedRef.current = true;
                setFrame((f) => (f + 1) & 0xffff);
                return;
            }
            const pan = panRef.current;
            if (pan) {
                const dx = e.clientX - pan.x;
                const dy = e.clientY - pan.y;
                setView((v) => ({ ...v, tx: pan.tx + dx, ty: pan.ty + dy }));
            }
        },
        [sim.index, toWorld]
    );

    const onNodePointerUp = useCallback((e: React.PointerEvent, id: string) => {
        e.stopPropagation();
        draggingRef.current = null;
        if (!dragMovedRef.current) setSelected((s) => (s === id ? null : id));
    }, []);

    const onBgPointerDown = useCallback((e: React.PointerEvent) => {
        const v = viewRef.current;
        panRef.current = { x: e.clientX, y: e.clientY, tx: v.tx, ty: v.ty };
        (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
    }, []);

    const onBgPointerUp = useCallback((e: React.PointerEvent) => {
        const moved = panRef.current;
        panRef.current = null;
        draggingRef.current = null;
        // A background click that did not pan clears the selection.
        if (moved && Math.abs(e.clientX - moved.x) < 3 && Math.abs(e.clientY - moved.y) < 3) {
            setSelected(null);
        }
    }, []);

    const onWheel = useCallback((e: React.WheelEvent) => {
        const rect = wrapRef.current?.getBoundingClientRect();
        const sx = e.clientX - (rect?.left ?? 0);
        const sy = e.clientY - (rect?.top ?? 0);
        setView((v) => {
            const factor = Math.exp(-e.deltaY * 0.0015);
            const scale = Math.min(4, Math.max(0.25, v.scale * factor));
            const k = scale / v.scale;
            // Keep the point under the cursor fixed while zooming.
            return { scale, tx: sx - (sx - v.tx) * k, ty: sy - (sy - v.ty) * k };
        });
    }, []);

    const active = selected ?? hover;
    const activeSet = useMemo(() => {
        if (!active) return null;
        const s = new Set<string>([active]);
        sim.neighbours.get(active)?.forEach((n) => s.add(n));
        return s;
    }, [active, sim.neighbours]);

    const isLit = (id: string) => !activeSet || activeSet.has(id);
    const showLabel = (id: string) => view.scale > 0.7 || !!activeSet?.has(id);

    const selectedNode = selected ? sim.index.get(selected) ?? null : null;

    // Per-frame position snapshot. Recomputed on every `frame` tick, so the
    // marks below flow from a value that actually changes (defeating any
    // memoisation on the stable `sim` reference).
    const pos = useMemo(() => {
        void frame;
        const m = new Map<string, { x: number; y: number }>();
        for (const n of sim.nodes) m.set(n.id, { x: n.x, y: n.y });
        return m;
    }, [sim, frame]);

    return (
        <div className="relative flex min-h-0 flex-1 gap-4">
            <div
                ref={wrapRef}
                className="relative min-h-[420px] flex-1 overflow-hidden rounded-xl border"
                style={{
                    borderColor: 'var(--drv-border)',
                    background: 'var(--drv-surface)',
                    cursor: panRef.current ? 'grabbing' : 'grab',
                    touchAction: 'none'
                }}
            >
                <svg
                    width={size.w}
                    height={size.h}
                    onPointerDown={onBgPointerDown}
                    onPointerMove={onPointerMove}
                    onPointerUp={onBgPointerUp}
                    onWheel={onWheel}
                    role="img"
                    aria-label="Force-directed knowledge graph. Drag a node to move it, drag the background to pan, scroll to zoom."
                >
                    <g transform={`translate(${view.tx} ${view.ty}) scale(${view.scale})`}>
                        {/* Edges. Containment recedes; citation is solid and
                            prominent; wikilink is dashed. */}
                        {sim.edges.map((e, i) => {
                            const a = pos.get(e.from);
                            const b = pos.get(e.to);
                            if (!a || !b) return null;
                            const lit = !activeSet || (activeSet.has(e.from) && activeSet.has(e.to));
                            const containment = e.kind === 'containment';
                            const stroke = containment
                                ? 'var(--drv-border)'
                                : lit && active
                                    ? 'var(--drv-accent)'
                                    : 'var(--drv-text-muted)';
                            return (
                                <line
                                    key={i}
                                    x1={a.x}
                                    y1={a.y}
                                    x2={b.x}
                                    y2={b.y}
                                    stroke={stroke}
                                    strokeWidth={containment ? 1 : e.kind === 'citation' ? 1.75 : 1.5}
                                    strokeDasharray={e.kind === 'wikilink' ? '4 3' : undefined}
                                    strokeOpacity={lit ? (containment ? 0.6 : 0.9) : 0.12}
                                />
                            );
                        })}

                        {/* Nodes. A 2px surface ring separates overlapping
                            marks; ghost placeholders are dashed and hollow. */}
                        {sim.nodes.map((nd) => {
                            const lit = isLit(nd.id);
                            const isActive = nd.id === active;
                            const p = pos.get(nd.id) ?? { x: nd.x, y: nd.y };
                            return (
                                <g
                                    key={nd.id}
                                    transform={`translate(${p.x} ${p.y})`}
                                    style={{ cursor: 'pointer' }}
                                    opacity={lit ? 1 : 0.25}
                                    onPointerDown={(e) => onNodePointerDown(e, nd.id)}
                                    onPointerUp={(e) => onNodePointerUp(e, nd.id)}
                                    onPointerEnter={() => setHover(nd.id)}
                                    onPointerLeave={() => setHover((h) => (h === nd.id ? null : h))}
                                >
                                    <circle
                                        r={nd.r + (isActive ? 2 : 0)}
                                        fill={nd.ghost ? 'var(--drv-surface)' : classColour(nd.cls)}
                                        stroke={
                                            nd.ghost
                                                ? 'var(--drv-text-muted)'
                                                : isActive
                                                    ? 'var(--drv-accent)'
                                                    : 'var(--drv-surface)'
                                        }
                                        strokeWidth={2}
                                        strokeDasharray={nd.ghost ? '3 2' : undefined}
                                    />
                                    {showLabel(nd.id) && (
                                        <text
                                            y={nd.r + 12}
                                            textAnchor="middle"
                                            fontSize={10}
                                            fill="var(--drv-text)"
                                            stroke="var(--drv-surface)"
                                            strokeWidth={3}
                                            paintOrder="stroke"
                                            style={{
                                                pointerEvents: 'none',
                                                fontStyle: nd.ghost ? 'italic' : 'normal',
                                                opacity: nd.ghost ? 0.75 : 1
                                            }}
                                        >
                                            {nd.name.length > 22 ? `${nd.name.slice(0, 21)}…` : nd.name}
                                        </text>
                                    )}
                                </g>
                            );
                        })}
                    </g>
                </svg>

                <Legend hasGhost={sim.nodes.some((n) => n.ghost)} />
            </div>

            {selectedNode && (
                <NodePanel
                    node={selectedNode}
                    sim={sim}
                    onClose={() => setSelected(null)}
                    onPick={(id) => setSelected(id)}
                />
            )}
        </div>
    );
}

// ---- Legend ----------------------------------------------------------

function Legend({ hasGhost }: { hasGhost: boolean }) {
    return (
        <div
            className="absolute bottom-3 left-3 rounded-lg border px-3 py-2 text-xs shadow-sm"
            style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
        >
            <div className="flex flex-col gap-1.5">
                {CLASSES.map((c) => (
                    <span key={c.key} className="flex items-center gap-2">
                        <span
                            className="inline-block h-2.5 w-2.5 rounded-full"
                            style={{ background: `var(${c.cssVar})` }}
                        />
                        <span style={{ color: 'var(--drv-text-muted)' }}>{c.label}</span>
                    </span>
                ))}
                {hasGhost && (
                    <span className="flex items-center gap-2">
                        <span
                            className="inline-block h-2.5 w-2.5 rounded-full border border-dashed"
                            style={{ borderColor: 'var(--drv-text-muted)' }}
                        />
                        <span style={{ color: 'var(--drv-text-muted)' }}>Dangling link</span>
                    </span>
                )}
            </div>
            <div
                className="mt-2 flex flex-col gap-1 border-t pt-2"
                style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}
            >
                <EdgeKey label="Citation" dash={false} width={1.75} />
                <EdgeKey label="Wikilink" dash width={1.5} />
                <EdgeKey label="Folder" dash={false} width={1} faint />
            </div>
        </div>
    );
}

function EdgeKey({
    label,
    dash,
    width,
    faint
}: {
    label: string;
    dash: boolean;
    width: number;
    faint?: boolean;
}) {
    return (
        <span className="flex items-center gap-2">
            <svg width={18} height={6} aria-hidden="true">
                <line
                    x1={0}
                    y1={3}
                    x2={18}
                    y2={3}
                    stroke={faint ? 'var(--drv-border)' : 'var(--drv-text-muted)'}
                    strokeWidth={width}
                    strokeDasharray={dash ? '4 3' : undefined}
                />
            </svg>
            {label}
        </span>
    );
}

// ---- Side panel ------------------------------------------------------

interface LinkRow {
    id: string;
    name: string;
    kind: string;
    ghost: boolean;
}

function NodePanel({
    node,
    sim,
    onClose,
    onPick
}: {
    node: SimNode;
    sim: SimData;
    onClose: () => void;
    onPick: (id: string) => void;
}) {
    const outgoing: LinkRow[] = [];
    const backlinks: LinkRow[] = [];
    for (const e of sim.edges) {
        if (e.from === node.id) {
            const t = sim.index.get(e.to);
            if (t) outgoing.push({ id: t.id, name: t.name, kind: e.kind, ghost: t.ghost });
        } else if (e.to === node.id) {
            const s = sim.index.get(e.from);
            if (s) backlinks.push({ id: s.id, name: s.name, kind: e.kind, ghost: s.ghost });
        }
    }

    return (
        <aside
            className="drv-scroll hidden w-72 shrink-0 overflow-auto rounded-xl border p-4 lg:block"
            style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
        >
            <div className="mb-3 flex items-start justify-between gap-2">
                <div className="min-w-0">
                    <div className="flex items-center gap-2">
                        <span
                            className="inline-block h-3 w-3 shrink-0 rounded-full"
                            style={{
                                background: node.ghost ? 'transparent' : classColour(node.cls),
                                border: node.ghost ? '1px dashed var(--drv-text-muted)' : undefined
                            }}
                        />
                        <span
                            className="rounded-full px-2 py-0.5 text-xs font-medium"
                            style={{ background: 'var(--drv-accent-weak)', color: 'var(--drv-accent)' }}
                        >
                            {node.ghost ? 'Dangling link' : classLabel(node.cls)}
                        </span>
                    </div>
                    <h2 className="mt-2 text-sm font-semibold break-words" title={node.name}>
                        {node.name}
                    </h2>
                </div>
                <button
                    onClick={onClose}
                    className="shrink-0 rounded-lg p-1 hover:bg-[var(--drv-hover)]"
                    aria-label="Close"
                    style={{ color: 'var(--drv-text-muted)' }}
                >
                    <CloseIcon width={16} height={16} />
                </button>
            </div>

            {node.ghost ? (
                <p className="text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                    A wikilink points here, but no file of this name exists. Create it, or fix the link
                    in the source file.
                </p>
            ) : (
                <>
                    <LinkList title="Links out" rows={outgoing} onPick={onPick} />
                    <LinkList title="Backlinks" rows={backlinks} onPick={onPick} />
                    {outgoing.length === 0 && backlinks.length === 0 && (
                        <p className="text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                            Nothing links to or from this file yet.
                        </p>
                    )}
                </>
            )}
        </aside>
    );
}

function LinkList({
    title,
    rows,
    onPick
}: {
    title: string;
    rows: LinkRow[];
    onPick: (id: string) => void;
}) {
    if (rows.length === 0) return null;
    return (
        <div className="mb-4">
            <div className="mb-1.5 text-xs font-medium" style={{ color: 'var(--drv-text-muted)' }}>
                {title} ({rows.length})
            </div>
            <ul className="flex flex-col gap-0.5">
                {rows.map((r, i) => (
                    <li key={`${r.id}-${i}`}>
                        <button
                            onClick={() => !r.ghost && onPick(r.id)}
                            disabled={r.ghost}
                            className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-sm hover:bg-[var(--drv-hover)] disabled:cursor-default disabled:opacity-70 disabled:hover:bg-transparent"
                        >
                            <span
                                className="inline-block h-1.5 w-4 shrink-0 rounded"
                                style={{
                                    background:
                                        r.kind === 'containment'
                                            ? 'var(--drv-border)'
                                            : 'var(--drv-text-muted)'
                                }}
                                title={r.kind}
                            />
                            <span
                                className="truncate"
                                title={r.name}
                                style={{ fontStyle: r.ghost ? 'italic' : 'normal' }}
                            >
                                {r.name}
                            </span>
                        </button>
                    </li>
                ))}
            </ul>
        </div>
    );
}
