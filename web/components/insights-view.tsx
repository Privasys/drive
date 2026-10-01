'use client';

// Insights - access metrics for the active tenant (owner/admin only).
// Shows who connected (opaque pairwise subs, never names), what they
// viewed, how often and for how long. The enclave aggregates; nothing
// here identifies a person - name resolution arrives with the wallet
// decoration channel later.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import {
    DriveError,
    getTenantMetrics,
    type MetricsPoint,
    type Tenant,
    type TenantMetrics
} from '~/lib/drive-api';
import { formatBytes, formatDate, formatDuration, relativeTime } from '~/lib/format';
import { ChartIcon, FileIcon, LockIcon } from './icons';

const RANGES = [7, 30, 90] as const;

interface DayPoint {
    date: string; // YYYY-MM-DD
    views: number;
    downloads: number;
    unique: number;
}

/** Expand the sparse ascending server series to one point per day. */
function denseSeries(series: MetricsPoint[], days: number): DayPoint[] {
    const byDate = new Map(series.map((p) => [p.date, p]));
    const now = new Date();
    const out: DayPoint[] = [];
    for (let i = days - 1; i >= 0; i--) {
        const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
        const key = d.toISOString().slice(0, 10);
        const p = byDate.get(key);
        out.push({
            date: key,
            views: p?.views ?? 0,
            downloads: p?.downloads ?? 0,
            unique: p?.unique_subs ?? 0
        });
    }
    return out;
}

/** Round a rough step up to a clean 1/2/5 x 10^k value. */
function niceStep(rough: number): number {
    const pow = Math.pow(10, Math.floor(Math.log10(Math.max(rough, 1e-6))));
    const r = rough / pow;
    return (r <= 1 ? 1 : r <= 2 ? 2 : r <= 5 ? 5 : 10) * pow;
}

/** Track the rendered width of a block element (responsive SVG chart). */
function useMeasuredWidth(): [React.RefObject<HTMLDivElement | null>, number] {
    const ref = useRef<HTMLDivElement | null>(null);
    const [width, setWidth] = useState(0);
    useEffect(() => {
        const el = ref.current;
        if (!el) return;
        const ro = new ResizeObserver((entries) => {
            const w = entries[0]?.contentRect.width ?? 0;
            setWidth(Math.round(w));
        });
        ro.observe(el);
        return () => ro.disconnect();
    }, []);
    return [ref, width];
}

export function InsightsView({ session, tenant }: { session: SealedSession; tenant: Tenant }) {
    const [days, setDays] = useState<number>(30);
    const [metrics, setMetrics] = useState<TenantMetrics | null>(null);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [forbidden, setForbidden] = useState(false);

    const load = useCallback(
        async (d: number, initial: boolean) => {
            if (initial) setLoading(true);
            else setRefreshing(true);
            setError(null);
            try {
                setMetrics(await getTenantMetrics(session, tenant.id, d));
                setForbidden(false);
            } catch (e) {
                if (e instanceof DriveError && e.status === 403) {
                    setForbidden(true);
                } else {
                    setError(e instanceof Error ? e.message : 'Could not load insights.');
                }
            } finally {
                setLoading(false);
                setRefreshing(false);
            }
        },
        [session, tenant.id]
    );

    const loadedOnce = useRef(false);
    useEffect(() => {
        void load(days, !loadedOnce.current);
        loadedOnce.current = true;
    }, [load, days]);

    const series = useMemo(
        () => (metrics ? denseSeries(metrics.series, days) : []),
        [metrics, days]
    );
    const totalViews = useMemo(() => series.reduce((n, p) => n + p.views, 0), [series]);
    const totalDownloads = useMemo(() => series.reduce((n, p) => n + p.downloads, 0), [series]);
    const topNode = metrics?.top_nodes[0];
    const uniqueVisitors = metrics?.unique_subs ?? 0;

    const empty =
        !!metrics &&
        totalViews === 0 &&
        totalDownloads === 0 &&
        metrics.top_nodes.length === 0 &&
        metrics.subs.length === 0;

    return (
        <div className="p-4 sm:p-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                <div>
                    <h1 className="text-lg font-semibold">Insights</h1>
                    <p className="mt-0.5 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Who accessed {tenant.kind === 'user' ? 'your drive' : tenant.name}, what
                        they viewed and for how long. Visitors are opaque IDs; no names are stored.
                    </p>
                </div>
                <RangePicker value={days} onChange={setDays} disabled={loading || refreshing} />
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
                    <p className="mt-4 text-sm font-medium">Owners and admins only</p>
                    <p className="mt-1 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Ask a workspace owner or admin to see access metrics.
                    </p>
                </div>
            ) : empty ? (
                <div className="flex flex-col items-center justify-center py-20 text-center">
                    <ChartIcon width={48} height={48} style={{ color: 'var(--drv-border)' }} />
                    <p className="mt-4 text-sm font-medium">No activity yet</p>
                    <p className="mt-1 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Once people open or download files, their activity will appear here.
                    </p>
                </div>
            ) : metrics ? (
                <div
                    className="space-y-4 transition-opacity"
                    style={{ opacity: refreshing ? 0.6 : 1 }}
                >
                    {/* Stat tiles */}
                    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                        <StatTile label="Views" value={totalViews.toLocaleString('en-GB')} />
                        <StatTile label="Downloads" value={totalDownloads.toLocaleString('en-GB')} />
                        <StatTile
                            label="Unique visitors"
                            value={uniqueVisitors.toLocaleString('en-GB')}
                        />
                        <StatTile label="Most viewed" value={topNode?.name ?? 'Nothing yet'} text />
                    </div>

                    <ActivityCard series={series} />

                    <TopFilesCard metrics={metrics} />

                    <VisitorsCard metrics={metrics} />
                </div>
            ) : null}
        </div>
    );
}

function RangePicker({
    value,
    onChange,
    disabled
}: {
    value: number;
    onChange: (d: number) => void;
    disabled: boolean;
}) {
    return (
        <div
            className="flex items-center gap-1 rounded-full border p-1"
            style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
            role="group"
            aria-label="Time range"
        >
            {RANGES.map((d) => (
                <button
                    key={d}
                    onClick={() => onChange(d)}
                    disabled={disabled}
                    aria-pressed={value === d}
                    className="rounded-full px-3 py-1 text-xs font-medium transition-colors disabled:opacity-60"
                    style={{
                        background: value === d ? 'var(--drv-accent-weak)' : 'transparent',
                        color: value === d ? 'var(--drv-accent)' : 'var(--drv-text-muted)'
                    }}
                >
                    {d} days
                </button>
            ))}
        </div>
    );
}

function StatTile({ label, value, text }: { label: string; value: string; text?: boolean }) {
    return (
        <div
            className="rounded-xl border p-4"
            style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
        >
            <div className="text-xs font-medium" style={{ color: 'var(--drv-text-muted)' }}>
                {label}
            </div>
            <div
                className={text ? 'mt-1 truncate text-base font-semibold' : 'mt-1 text-2xl font-semibold'}
                title={text ? value : undefined}
            >
                {value}
            </div>
        </div>
    );
}

// ---- Daily activity chart --------------------------------------------

const CHART_H = 240;
const M = { top: 8, right: 8, bottom: 24, left: 40 };

function ActivityCard({ series }: { series: DayPoint[] }) {
    const [asTable, setAsTable] = useState(false);
    return (
        <div
            className="rounded-xl border p-4"
            style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
        >
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-sm font-semibold">Daily activity</h2>
                <div className="flex items-center gap-4">
                    <Legend />
                    <button
                        onClick={() => setAsTable((v) => !v)}
                        className="rounded-full border px-3 py-1 text-xs font-medium hover:bg-[var(--drv-hover)]"
                        style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}
                    >
                        {asTable ? 'View as chart' : 'View as table'}
                    </button>
                </div>
            </div>
            {asTable ? <ActivityTable series={series} /> : <ActivityChart series={series} />}
        </div>
    );
}

function Legend() {
    return (
        <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
            <span className="flex items-center gap-1.5">
                <span
                    className="inline-block h-2.5 w-2.5 rounded-sm"
                    style={{ background: 'var(--drv-chart-views)' }}
                />
                Views
            </span>
            <span className="flex items-center gap-1.5">
                <span
                    className="inline-block h-2.5 w-2.5 rounded-sm"
                    style={{ background: 'var(--drv-chart-downloads)' }}
                />
                Downloads
            </span>
        </div>
    );
}

/** A column path with a rounded top and a square baseline end. */
function topRoundedRect(x: number, y: number, w: number, h: number, r: number): string {
    const rr = Math.min(r, h, w / 2);
    return [
        `M ${x} ${y + h}`,
        `L ${x} ${y + rr}`,
        `Q ${x} ${y} ${x + rr} ${y}`,
        `L ${x + w - rr} ${y}`,
        `Q ${x + w} ${y} ${x + w} ${y + rr}`,
        `L ${x + w} ${y + h}`,
        'Z'
    ].join(' ');
}

function ActivityChart({ series }: { series: DayPoint[] }) {
    const [wrapRef, width] = useMeasuredWidth();
    const [hover, setHover] = useState<number | null>(null);

    const innerW = Math.max(0, width - M.left - M.right);
    const innerH = CHART_H - M.top - M.bottom;
    const n = series.length;

    const maxStack = Math.max(1, ...series.map((p) => p.views + p.downloads));
    const step = niceStep(maxStack / 3);
    const top = Math.max(step, Math.ceil(maxStack / step) * step);
    const ticks: number[] = [];
    for (let v = 0; v <= top; v += step) ticks.push(v);

    const band = n > 0 ? innerW / n : 0;
    const barW = Math.max(2, Math.min(24, band - 2));
    const y = (v: number) => M.top + innerH - (v / top) * innerH;

    // A handful of x labels: first, last and a few evenly spaced.
    const labelEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(innerW / 90))));
    const showLabel = (i: number) => i === 0 || i === n - 1 || (i % labelEvery === 0 && i < n - labelEvery / 2);

    const h = hover !== null ? series[hover] : null;
    const tooltipLeft =
        hover !== null && width > 0
            ? Math.min(Math.max(M.left + hover * band + band / 2 - 70, 0), width - 150)
            : 0;

    return (
        <div ref={wrapRef} className="relative">
            {width > 0 && (
                <svg
                    width={width}
                    height={CHART_H}
                    role="img"
                    aria-label="Daily views and downloads. Use the table view for exact values."
                    onPointerLeave={() => setHover(null)}
                >
                    {/* Gridlines + y ticks (hairline, recessive) */}
                    {ticks.map((t) => (
                        <g key={t}>
                            <line
                                x1={M.left}
                                x2={width - M.right}
                                y1={y(t)}
                                y2={y(t)}
                                stroke="var(--drv-border)"
                                strokeWidth={1}
                            />
                            <text
                                x={M.left - 8}
                                y={y(t) + 3.5}
                                textAnchor="end"
                                fontSize={10}
                                fill="var(--drv-text-muted)"
                                style={{ fontVariantNumeric: 'tabular-nums' }}
                            >
                                {t.toLocaleString('en-GB')}
                            </text>
                        </g>
                    ))}

                    {/* Hover band highlight (behind the marks) */}
                    {hover !== null && (
                        <rect
                            x={M.left + hover * band}
                            y={M.top}
                            width={band}
                            height={innerH}
                            fill="var(--drv-hover)"
                        />
                    )}

                    {/* Stacked columns: views at the baseline, downloads on
                        top, a 2px surface gap between the segments and a
                        rounded top on the topmost segment only. */}
                    {series.map((p, i) => {
                        const x = M.left + i * band + (band - barW) / 2;
                        const base = M.top + innerH;
                        const hv = (p.views / top) * innerH;
                        const hd = (p.downloads / top) * innerH;
                        const gap = hv > 0 && hd > 0 ? 2 : 0;
                        return (
                            <g key={p.date}>
                                {hv > 0 &&
                                    (hd > 0 ? (
                                        <rect
                                            x={x}
                                            y={base - hv}
                                            width={barW}
                                            height={hv}
                                            fill="var(--drv-chart-views)"
                                        />
                                    ) : (
                                        <path
                                            d={topRoundedRect(x, base - hv, barW, hv, 4)}
                                            fill="var(--drv-chart-views)"
                                        />
                                    ))}
                                {hd > 0 && (
                                    <path
                                        d={topRoundedRect(x, base - hv - gap - hd, barW, hd, 4)}
                                        fill="var(--drv-chart-downloads)"
                                    />
                                )}
                            </g>
                        );
                    })}

                    {/* X labels */}
                    {series.map(
                        (p, i) =>
                            showLabel(i) && (
                                <text
                                    key={p.date}
                                    x={M.left + i * band + band / 2}
                                    y={CHART_H - 8}
                                    textAnchor="middle"
                                    fontSize={10}
                                    fill="var(--drv-text-muted)"
                                >
                                    {formatDate(p.date)}
                                </text>
                            )
                    )}

                    {/* Full-height hit bands (bigger than the marks) */}
                    {series.map((p, i) => (
                        <rect
                            key={p.date}
                            x={M.left + i * band}
                            y={M.top}
                            width={band}
                            height={innerH}
                            fill="transparent"
                            onPointerEnter={() => setHover(i)}
                            onPointerMove={() => setHover(i)}
                        />
                    ))}
                </svg>
            )}

            {/* Tooltip: values lead, labels follow; line keys per series. */}
            {h && (
                <div
                    className="pointer-events-none absolute z-10 w-[150px] rounded-lg border px-3 py-2 text-xs shadow-lg"
                    style={{
                        left: tooltipLeft,
                        top: M.top,
                        background: 'var(--drv-surface)',
                        borderColor: 'var(--drv-border)'
                    }}
                >
                    <div className="font-medium">{formatDate(h.date)}</div>
                    <div className="mt-1 space-y-0.5">
                        <TooltipRow color="var(--drv-chart-views)" value={h.views} label="views" />
                        <TooltipRow
                            color="var(--drv-chart-downloads)"
                            value={h.downloads}
                            label="downloads"
                        />
                        <div style={{ color: 'var(--drv-text-muted)' }}>
                            <span className="font-semibold" style={{ color: 'var(--drv-text)' }}>
                                {h.unique.toLocaleString('en-GB')}
                            </span>{' '}
                            unique visitors
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

function TooltipRow({ color, value, label }: { color: string; value: number; label: string }) {
    return (
        <div className="flex items-center gap-1.5">
            <span className="inline-block h-0.5 w-3 rounded" style={{ background: color }} />
            <span className="font-semibold">{value.toLocaleString('en-GB')}</span>
            <span style={{ color: 'var(--drv-text-muted)' }}>{label}</span>
        </div>
    );
}

/** The chart's table twin: every plotted value, reachable without hover. */
function ActivityTable({ series }: { series: DayPoint[] }) {
    return (
        <div className="drv-scroll max-h-60 overflow-auto rounded-lg border" style={{ borderColor: 'var(--drv-border)' }}>
            <table className="w-full text-sm">
                <thead>
                    <tr className="text-left text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                        <th className="px-3 py-2 font-medium">Date</th>
                        <th className="px-3 py-2 text-right font-medium">Views</th>
                        <th className="px-3 py-2 text-right font-medium">Downloads</th>
                        <th className="px-3 py-2 text-right font-medium">Unique visitors</th>
                    </tr>
                </thead>
                <tbody style={{ fontVariantNumeric: 'tabular-nums' }}>
                    {series.map((p) => (
                        <tr key={p.date} style={{ borderTop: '1px solid var(--drv-border)' }}>
                            <td className="px-3 py-1.5">{formatDate(p.date)}</td>
                            <td className="px-3 py-1.5 text-right">{p.views.toLocaleString('en-GB')}</td>
                            <td className="px-3 py-1.5 text-right">{p.downloads.toLocaleString('en-GB')}</td>
                            <td className="px-3 py-1.5 text-right">{p.unique.toLocaleString('en-GB')}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

// ---- Top files -------------------------------------------------------

function TopFilesCard({ metrics }: { metrics: TenantMetrics }) {
    return (
        <div
            className="rounded-xl border p-4"
            style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
        >
            <h2 className="mb-3 text-sm font-semibold">Top files</h2>
            {metrics.top_nodes.length === 0 ? (
                <p className="py-4 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                    No files were viewed in this period.
                </p>
            ) : (
                <table className="w-full text-sm">
                    <thead>
                        <tr className="text-left text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                            <th className="px-2 py-1.5 font-medium">Name</th>
                            <th className="px-2 py-1.5 text-right font-medium">Views</th>
                            <th className="px-2 py-1.5 text-right font-medium">Last accessed</th>
                        </tr>
                    </thead>
                    <tbody>
                        {metrics.top_nodes.map((f) => (
                            <tr key={f.node_id} style={{ borderTop: '1px solid var(--drv-border)' }}>
                                <td className="max-w-0 px-2 py-2">
                                    <div className="flex items-center gap-2">
                                        <FileIcon
                                            width={16}
                                            height={16}
                                            style={{ color: 'var(--drv-text-muted)', flexShrink: 0 }}
                                        />
                                        <span className="truncate" title={f.name}>
                                            {f.name}
                                        </span>
                                    </div>
                                </td>
                                <td
                                    className="px-2 py-2 text-right"
                                    style={{ fontVariantNumeric: 'tabular-nums' }}
                                >
                                    {f.views.toLocaleString('en-GB')}
                                </td>
                                <td
                                    className="whitespace-nowrap px-2 py-2 text-right"
                                    style={{ color: 'var(--drv-text-muted)' }}
                                >
                                    {relativeTime(f.last_at)}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    );
}

// ---- Visitors --------------------------------------------------------

function shortSub(sub: string): string {
    return sub.length > 10 ? `${sub.slice(0, 10)}…` : sub;
}

function VisitorsCard({ metrics }: { metrics: TenantMetrics }) {
    return (
        <div
            className="rounded-xl border p-4"
            style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
        >
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-sm font-semibold">Visitors</h2>
                <div className="flex items-center gap-3">
                    <p className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                        Names live in your wallet. Connect your wallet to reveal who these are.
                    </p>
                    <button
                        disabled
                        title="Coming soon"
                        className="cursor-not-allowed rounded-full border px-3 py-1 text-xs font-medium opacity-50"
                        style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}
                    >
                        Reveal with wallet
                    </button>
                </div>
            </div>
            {metrics.subs.length === 0 ? (
                <p className="py-4 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                    Nobody connected in this period.
                </p>
            ) : (
                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="text-left text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                <th className="px-2 py-1.5 font-medium">Visitor</th>
                                <th className="px-2 py-1.5 text-right font-medium">Views</th>
                                <th className="px-2 py-1.5 text-right font-medium">Downloads</th>
                                <th className="px-2 py-1.5 text-right font-medium">Data</th>
                                <th className="px-2 py-1.5 text-right font-medium">Read time</th>
                                <th className="px-2 py-1.5 text-right font-medium">First seen</th>
                                <th className="px-2 py-1.5 text-right font-medium">Last seen</th>
                            </tr>
                        </thead>
                        <tbody>
                            {metrics.subs.map((v) => (
                                <tr key={v.sub} style={{ borderTop: '1px solid var(--drv-border)' }}>
                                    <td className="px-2 py-2">
                                        <span className="font-mono text-xs" title={v.sub}>
                                            {shortSub(v.sub)}
                                        </span>
                                    </td>
                                    <td
                                        className="px-2 py-2 text-right"
                                        style={{ fontVariantNumeric: 'tabular-nums' }}
                                    >
                                        {v.views.toLocaleString('en-GB')}
                                    </td>
                                    <td
                                        className="px-2 py-2 text-right"
                                        style={{ fontVariantNumeric: 'tabular-nums' }}
                                    >
                                        {v.downloads.toLocaleString('en-GB')}
                                    </td>
                                    <td
                                        className="whitespace-nowrap px-2 py-2 text-right"
                                        style={{ fontVariantNumeric: 'tabular-nums' }}
                                    >
                                        {formatBytes(v.bytes)}
                                    </td>
                                    <td
                                        className="whitespace-nowrap px-2 py-2 text-right"
                                        style={{ fontVariantNumeric: 'tabular-nums' }}
                                    >
                                        {formatDuration(v.total_ms)}
                                    </td>
                                    <td
                                        className="whitespace-nowrap px-2 py-2 text-right"
                                        style={{ color: 'var(--drv-text-muted)' }}
                                    >
                                        {relativeTime(v.first_at)}
                                    </td>
                                    <td
                                        className="whitespace-nowrap px-2 py-2 text-right"
                                        style={{ color: 'var(--drv-text-muted)' }}
                                    >
                                        {relativeTime(v.last_at)}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
