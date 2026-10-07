import type { Metadata } from 'next';
import { AuthProvider } from '~/lib/auth-provider';
import { DriveProvider } from '~/lib/use-drive';
import '~/styles/globals.css';

// Favicon assets are the canonical Privasys set (single source of truth in
// /assets/favicon), the same icons the developer portal serves.
const FAVICON = '/favicon';

export const metadata: Metadata = {
    title: 'Privasys Drive',
    description:
        'Your files, sealed. Privasys Drive stores every file end-to-end encrypted inside a hardware-protected enclave, so the operator cannot read your data and access is verifiable by remote attestation.',
    icons: [
        { rel: 'apple-touch-icon', sizes: '180x180', url: `${FAVICON}/apple-touch-icon.png` },
        { rel: 'icon', type: 'image/png', sizes: '96x96', url: `${FAVICON}/favicon-96x96.png` },
        { rel: 'icon', type: 'image/svg+xml', url: `${FAVICON}/favicon.svg` },
        { rel: 'shortcut icon', url: `${FAVICON}/favicon.svg` }
    ],
    manifest: `${FAVICON}/site.webmanifest`
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
        <html lang="en">
            <body className="min-h-screen">
                <AuthProvider>
                    <DriveProvider>{children}</DriveProvider>
                </AuthProvider>
            </body>
        </html>
    );
}
