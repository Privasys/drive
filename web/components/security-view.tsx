'use client';

import { AttestationResultView, useAttestation } from '@privasys/attestation-view';
import { useAuth } from '~/lib/privasys-auth';
import { RUNTIME } from '~/lib/runtime-config';

// Full-pane Security view for the Drive enclave, reached from the sidebar
// trust footer. Runs the same live attestation the footer pill summarises,
// then renders the full report (quote, certificate, platform extensions)
// via the shared @privasys/attestation-view component — identical wording
// and layout to the chat and developer-portal security surfaces.

const API_BASE = RUNTIME.apiBase;
const APP_ID = RUNTIME.appId;
const AS_VERIFY = 'https://as.privasys.org/verify-quote';

export function SecurityView({ onBack }: { onBack?: () => void }) {
    const { getTokenForAudience } = useAuth();
    const attestUrl = APP_ID ? `${API_BASE}/api/v1/apps/${APP_ID}/attest` : '';
    const [state, actions] = useAttestation({
        attestUrl,
        verifyQuoteUrl: AS_VERIFY,
        token: () => getTokenForAudience('attestation-server'),
        verifyQuoteToken: () => getTokenForAudience('attestation-server'),
        autoInspect: Boolean(attestUrl),
        autoVerifyQuote: Boolean(attestUrl)
    });

    return (
        <div className="flex flex-1 flex-col overflow-y-auto">
            <div className="mx-auto w-full max-w-3xl px-6 py-8">
                <header className="mb-6">
                    {onBack && (
                        <button
                            type="button"
                            onClick={onBack}
                            className="mb-3 inline-flex items-center gap-1 rounded-md text-sm transition-colors hover:opacity-80"
                            style={{ color: 'var(--drv-text-secondary)' }}
                        >
                            <svg
                                width="16"
                                height="16"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                strokeWidth="2"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                aria-hidden="true"
                            >
                                <path d="m15 18-6-6 6-6" />
                            </svg>
                            Back
                        </button>
                    )}
                    <h1 className="text-2xl font-semibold" style={{ color: 'var(--drv-text)' }}>
                        Security
                    </h1>
                    <p className="mt-1 text-sm" style={{ color: 'var(--drv-text-secondary)' }}>
                        Live attestation of the Drive enclave that seals and stores your files.
                        Verify it yourself — you don&apos;t have to trust the operator.
                    </p>
                </header>

                {!attestUrl ? (
                    <div
                        className="rounded-xl border p-5 text-sm"
                        style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}
                    >
                        Attestation is not configured for this instance.
                    </div>
                ) : state.error && !state.result ? (
                    <div className="space-y-3 rounded-xl border border-red-200/50 bg-red-50/40 p-5 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-900/10 dark:text-red-300">
                        <div>{state.error}</div>
                        <button
                            type="button"
                            onClick={() => void actions.inspect()}
                            className="rounded-lg border px-3 py-1.5 text-xs font-medium"
                            style={{ borderColor: 'var(--drv-border)' }}
                        >
                            Retry
                        </button>
                    </div>
                ) : !state.result ? (
                    <div
                        className="rounded-xl border p-5 text-sm"
                        style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}
                    >
                        Verifying the enclave…
                    </div>
                ) : (
                    <AttestationResultView
                        result={state.result}
                        quoteVerify={state.quoteVerify}
                        quoteVerifying={state.verifying}
                        quoteVerifyError={state.quoteVerifyError}
                        challenge={state.challenge}
                        onRegenerateChallenge={actions.regenerateChallenge}
                        onRefresh={() => void actions.inspect()}
                        loading={state.loading}
                        verifyQuoteUrl={AS_VERIFY}
                    />
                )}
            </div>
        </div>
    );
}
