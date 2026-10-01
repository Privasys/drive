'use client';

import { useState } from 'react';
import { Navbar, Footer } from '@privasys/ui';
import { useDrive } from '~/lib/use-drive';
import { avatarColor, initials } from '~/lib/format';
import { FileBrowser } from './file-browser';
import { SharedView } from './shared-view';
import { RequestsView } from './requests-view';
import { MembersView } from './members-view';
import { InsightsView } from './insights-view';
import { GraphView } from './graph-view';
import { SecurityView } from './security-view';
import { TrustFooter } from './trust-footer';
import { StorageGauge } from './storage-gauge';
import { AppsView } from './apps-view';
import { AppFoldersView } from './app-folders-view';
import { AppsIcon, ChartIcon, FolderIcon, GraphIcon, HomeIcon, InboxIcon, PeopleIcon, PlusIcon, ShieldCheck } from './icons';

type View = 'files' | 'shared' | 'requests' | 'members' | 'insights' | 'graph' | 'security' | 'apps' | 'app-folders';

const FOOTER_LINKS = [{ label: 'Legal', href: 'https://privasys.org/legal/', external: true }];

export function DriveApp() {
    const { me, name, tenant, tenants, switchTenant, newWorkspace, session, signOut, holderToken } = useDrive();
    const [view, setView] = useState<View>('files');
    // Where the Security view returns to (the view it was opened from).
    const [prevView, setPrevView] = useState<View>('files');
    const [creating, setCreating] = useState(false);
    const [wsName, setWsName] = useState('');
    const [wsError, setWsError] = useState<string | null>(null);
    const [wsBusy, setWsBusy] = useState(false);

    if (!session || !tenant) return null;

    const personal = tenants.find((t) => t.kind === 'user');
    const workspaces = tenants.filter((t) => t.kind === 'enterprise');
    const isEnterprise = tenant.kind === 'enterprise';
    // Insights is owner/admin only (a personal drive is always yours).
    const canSeeInsights =
        tenant.kind === 'user' || tenant.role === 'owner' || tenant.role === 'admin';

    const pick = (t: typeof tenant) => {
        switchTenant(t);
        setView('files');
    };

    const createWs = async () => {
        const n = wsName.trim();
        if (!n) return;
        setWsBusy(true);
        setWsError(null);
        try {
            await newWorkspace(n);
            setCreating(false);
            setWsName('');
            setView('files');
        } catch (e) {
            setWsError(e instanceof Error ? e.message : 'Could not create the workspace.');
        } finally {
            setWsBusy(false);
        }
    };

    return (
        <div className="flex min-h-screen flex-col" style={{ background: 'var(--drv-surface)' }}>
            <Navbar
                brandSuffix="Drive"
                fullWidth
                trailing={
                    <div className="flex items-center gap-3">
                        <span
                            className="hidden items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium sm:flex"
                            style={{ background: 'var(--drv-accent-weak)', color: 'var(--drv-accent)' }}
                            title="Files are sealed end-to-end to an attested enclave"
                        >
                            <ShieldCheck /> Sealed and attested
                        </span>
                        <UserMenu name={name} email={me?.email} onSignOut={signOut} />
                    </div>
                }
            />

            <div className="flex flex-1 pt-14">
                {/* Sidebar: stretches with the row; the nav sticks under the
                    header. */}
                <aside
                    className="hidden w-56 shrink-0 flex-col border-r sm:flex"
                    style={{ borderColor: 'var(--drv-border)' }}
                >
                    <nav className="flex flex-1 flex-col gap-1 overflow-auto p-3">
                        {personal && (
                            <SidebarItem
                                active={view === 'files' && tenant.id === personal.id}
                                onClick={() => pick(personal)}
                                icon={<HomeIcon width={18} height={18} />}
                                label="My Drive"
                            />
                        )}
                        <SidebarItem
                            active={view === 'shared'}
                            onClick={() => setView('shared')}
                            icon={<PeopleIcon width={18} height={18} />}
                            label="Shared with me"
                        />
                        <SidebarItem
                            active={view === 'requests'}
                            onClick={() => setView('requests')}
                            icon={<InboxIcon width={18} height={18} />}
                            label="Requests"
                        />
                        <SidebarItem
                            active={view === 'graph'}
                            onClick={() => setView('graph')}
                            icon={<GraphIcon width={18} height={18} />}
                            label="Graph"
                        />
                        <SidebarItem
                            active={view === 'apps'}
                            onClick={() => setView('apps')}
                            icon={<AppsIcon width={18} height={18} />}
                            label="Apps with access"
                        />
                        <SidebarItem
                            active={view === 'app-folders'}
                            onClick={() => setView('app-folders')}
                            icon={<FolderIcon width={18} height={18} />}
                            label="App folders"
                        />
                        {canSeeInsights && (
                            <SidebarItem
                                active={view === 'insights'}
                                onClick={() => setView('insights')}
                                icon={<ChartIcon width={18} height={18} />}
                                label="Insights"
                            />
                        )}

                        {/* Workspaces (enterprise tenants) */}
                        <div
                            className="mt-4 mb-1 flex items-center justify-between px-4 text-xs font-medium"
                            style={{ color: 'var(--drv-text-muted)' }}
                        >
                            Workspaces
                            <button
                                title="New workspace"
                                onClick={() => setCreating((v) => !v)}
                                className="rounded p-0.5 hover:bg-[var(--drv-hover)]"
                            >
                                <PlusIcon width={14} height={14} />
                            </button>
                        </div>
                        {creating && (
                            <div className="mb-1 px-2">
                                <input
                                    autoFocus
                                    value={wsName}
                                    onChange={(e) => setWsName(e.target.value)}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter') void createWs();
                                        if (e.key === 'Escape') setCreating(false);
                                    }}
                                    placeholder="Workspace name"
                                    disabled={wsBusy}
                                    className="w-full rounded-lg border px-2.5 py-1.5 text-sm outline-none focus:border-[var(--drv-accent)]"
                                    style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                                />
                                {wsError && <p className="mt-1 text-xs text-red-500">{wsError}</p>}
                            </div>
                        )}
                        {workspaces.length === 0 && !creating && (
                            <p className="px-4 py-1 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                Shared drives for a team.
                            </p>
                        )}
                        {workspaces.map((w) => (
                            <SidebarItem
                                key={w.id}
                                active={view === 'files' && tenant.id === w.id}
                                onClick={() => pick(w)}
                                icon={<FolderIcon width={18} height={18} />}
                                label={w.name}
                            />
                        ))}

                        {isEnterprise && (
                            <>
                                <div
                                    className="mt-4 mb-1 px-4 text-xs font-medium"
                                    style={{ color: 'var(--drv-text-muted)' }}
                                >
                                    {tenant.name}
                                </div>
                                <SidebarItem
                                    active={view === 'members'}
                                    onClick={() => setView('members')}
                                    icon={<PeopleIcon width={18} height={18} />}
                                    label="Members"
                                />
                            </>
                        )}
                    </nav>
                    <StorageGauge key={tenant.id} session={session} tenant={tenant} />
                    <TrustFooter
                        session={session}
                        onOpenSecurity={() => {
                            setPrevView(view === 'security' ? 'files' : view);
                            setView('security');
                        }}
                    />
                </aside>

                {/* Main */}
                <main className="flex min-w-0 flex-1 flex-col" style={{ background: 'var(--drv-surface-2)' }}>
                    {view === 'files' ? (
                        <FileBrowser key={tenant.id} session={session} tenant={tenant} me={me} />
                    ) : view === 'shared' ? (
                        <SharedView session={session} />
                    ) : view === 'requests' ? (
                        <RequestsView session={session} tenant={tenant} />
                    ) : view === 'insights' ? (
                        <InsightsView key={tenant.id} session={session} tenant={tenant} />
                    ) : view === 'graph' ? (
                        <GraphView key={tenant.id} session={session} tenant={tenant} />
                    ) : view === 'apps' ? (
                        <AppsView key={tenant.id} session={session} tenant={tenant} />
                    ) : view === 'app-folders' ? (
                        <AppFoldersView key={tenant.id} session={session} token={holderToken} />
                    ) : view === 'security' ? (
                        <SecurityView onBack={() => setView(prevView)} />
                    ) : (
                        <MembersView session={session} tenant={tenant} mySub={me?.sub ?? ''} />
                    )}
                </main>
            </div>

            {/* !mt-0 overrides the shared footer's 7.5rem marketing-page
                top margin, which does not belong in an app shell. */}
            <Footer
                className="!mt-0"
                companyLine="Every file is sealed inside a hardware-protected enclave. Verify its attestation yourself; you don't have to trust us."
                links={FOOTER_LINKS}
            />
        </div>
    );
}

function UserMenu({
    name,
    email,
    onSignOut
}: {
    name: string;
    email?: string;
    onSignOut: () => void;
}) {
    const [open, setOpen] = useState(false);
    const label = name || email || 'You';
    return (
        <div className="relative">
            <button
                onClick={() => setOpen((v) => !v)}
                className="flex h-9 w-9 items-center justify-center rounded-full text-sm font-semibold text-white"
                style={{ background: avatarColor(label) }}
                title={label}
            >
                {initials(label)}
            </button>
            {open && (
                <>
                    <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
                    <div
                        className="absolute right-0 z-20 mt-2 w-64 rounded-xl border p-2 shadow-lg"
                        style={{ background: 'var(--drv-surface)', borderColor: 'var(--drv-border)' }}
                    >
                        <div className="px-3 py-2">
                            <div className="truncate text-sm font-medium">{name || 'Your account'}</div>
                            {email && (
                                <div className="mt-0.5 truncate text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                    {email}
                                </div>
                            )}
                            <div className="mt-0.5 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                Your personal drive
                            </div>
                        </div>
                        <button
                            onClick={onSignOut}
                            className="mt-1 w-full rounded-lg px-3 py-2 text-left text-sm hover:bg-[var(--drv-hover)]"
                        >
                            Sign out
                        </button>
                    </div>
                </>
            )}
        </div>
    );
}

function SidebarItem({
    active,
    onClick,
    icon,
    label
}: {
    active: boolean;
    onClick: () => void;
    icon: React.ReactNode;
    label: string;
}) {
    return (
        <button
            onClick={onClick}
            className="flex items-center gap-3 rounded-full px-4 py-2.5 text-left text-sm font-medium transition-colors"
            style={{
                background: active ? 'var(--drv-accent-weak)' : 'transparent',
                color: active ? 'var(--drv-accent)' : 'var(--drv-text)'
            }}
        >
            {icon}
            <span className="truncate">{label}</span>
        </button>
    );
}
