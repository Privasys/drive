'use client';

// Workspace member management. Members are identified by Privasys ID
// (their sub) — the platform holds no names or emails; friendly-name
// resolution arrives with the wallet Contacts work. Admins add people,
// change roles and remove; anyone can leave (never the last owner).

import { useCallback, useEffect, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import {
    addMember,
    listMembers,
    removeMember,
    setMemberRole,
    type Member,
    type MemberRole,
    type Tenant
} from '~/lib/drive-api';
import { avatarColor, initials } from '~/lib/format';
import { PeopleIcon, TrashIcon } from './icons';

const ROLES: MemberRole[] = ['owner', 'admin', 'contributor', 'reader'];

export function MembersView({
    session,
    tenant,
    mySub
}: {
    session: SealedSession;
    tenant: Tenant;
    mySub: string;
}) {
    const [members, setMembers] = useState<Member[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [newSub, setNewSub] = useState('');
    const [newRole, setNewRole] = useState<MemberRole>('contributor');

    const myRole = members.find((m) => m.sub === mySub)?.role ?? tenant.role ?? 'reader';
    const isAdmin = myRole === 'owner' || myRole === 'admin';

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            setMembers(await listMembers(session, tenant.id));
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not load members.');
        } finally {
            setLoading(false);
        }
    }, [session, tenant.id]);

    useEffect(() => {
        void load();
    }, [load]);

    const run = async (fn: () => Promise<void>, failure: string) => {
        setBusy(true);
        setError(null);
        try {
            await fn();
            await load();
        } catch (e) {
            setError(e instanceof Error ? e.message : failure);
        } finally {
            setBusy(false);
        }
    };

    const add = () => {
        const sub = newSub.trim();
        if (!sub) return;
        void run(async () => {
            await addMember(session, tenant.id, sub, newRole);
            setNewSub('');
        }, 'Could not add the member.');
    };

    return (
        <div className="p-4 sm:p-6">
            <div className="mb-4">
                <h1 className="text-lg font-semibold">Members of {tenant.name}</h1>
                <p className="mt-0.5 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                    People are identified by their Privasys ID. No names or email
                    addresses are stored.
                </p>
            </div>

            {error && (
                <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                    {error}
                </div>
            )}

            {isAdmin && (
                <div className="mb-5 flex flex-wrap gap-2">
                    <input
                        value={newSub}
                        onChange={(e) => setNewSub(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && add()}
                        placeholder="Member's Privasys ID"
                        className="min-w-0 flex-1 rounded-lg border px-3 py-2 text-sm outline-none focus:border-[var(--drv-accent)]"
                        style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                    />
                    <select
                        value={newRole}
                        onChange={(e) => setNewRole(e.target.value as MemberRole)}
                        className="rounded-lg border px-2 py-2 text-sm outline-none"
                        style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                    >
                        {ROLES.map((r) => (
                            <option key={r} value={r}>
                                {r}
                            </option>
                        ))}
                    </select>
                    <button
                        onClick={add}
                        disabled={busy || !newSub.trim()}
                        className="drv-btn-primary rounded-lg px-4 py-2 text-sm disabled:opacity-50"
                    >
                        Add
                    </button>
                </div>
            )}

            {loading ? (
                <div className="py-16 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                    Loading…
                </div>
            ) : members.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-20 text-center">
                    <PeopleIcon width={48} height={48} style={{ color: 'var(--drv-border)' }} />
                    <p className="mt-4 text-sm font-medium">No members</p>
                </div>
            ) : (
                <div
                    className="overflow-hidden rounded-xl border"
                    style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                >
                    {members.map((m) => (
                        <div
                            key={m.sub}
                            className="flex items-center gap-3 px-4 py-3"
                            style={{ borderBottom: '1px solid var(--drv-border)' }}
                        >
                            <div
                                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-sm font-semibold text-white"
                                style={{ background: avatarColor(m.sub) }}
                            >
                                {initials(m.sub)}
                            </div>
                            <div className="min-w-0 flex-1">
                                <div className="truncate text-sm font-medium">
                                    {m.sub}
                                    {m.sub === mySub && (
                                        <span className="ml-1.5 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                            (you)
                                        </span>
                                    )}
                                </div>
                            </div>
                            {isAdmin ? (
                                <select
                                    value={m.role}
                                    disabled={busy}
                                    onChange={(e) =>
                                        void run(
                                            () => setMemberRole(session, tenant.id, m.sub, e.target.value as MemberRole),
                                            'Could not change the role.'
                                        )
                                    }
                                    className="rounded-lg border px-2 py-1.5 text-sm outline-none"
                                    style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                                >
                                    {ROLES.map((r) => (
                                        <option key={r} value={r}>
                                            {r}
                                        </option>
                                    ))}
                                </select>
                            ) : (
                                <span
                                    className="rounded-full px-2.5 py-1 text-xs"
                                    style={{ background: 'var(--drv-accent-weak)', color: 'var(--drv-accent)' }}
                                >
                                    {m.role}
                                </span>
                            )}
                            {(isAdmin || m.sub === mySub) && (
                                <button
                                    title={m.sub === mySub ? 'Leave workspace' : 'Remove member'}
                                    disabled={busy}
                                    onClick={() =>
                                        void run(
                                            () => removeMember(session, tenant.id, m.sub),
                                            'Could not remove the member.'
                                        )
                                    }
                                    className="rounded-lg p-1.5 hover:bg-[var(--drv-hover)]"
                                    style={{ color: 'var(--drv-text-muted)' }}
                                >
                                    <TrashIcon width={16} height={16} />
                                </button>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
