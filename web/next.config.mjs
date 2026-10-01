// The Drive UI is a static export served by the Drive service itself, from
// inside the attested image (service/internal/api/webui.go). Nothing here is
// per-environment: the backend it talks to comes from /privasys-config.js,
// which the service writes at runtime.

/** @type {import('next').NextConfig} */
const nextConfig = {
    experimental: {
        reactCompiler: true
    },
    transpilePackages: ['@privasys/ui', '@privasys/attestation-view', '@privasys/drive-client'],
    output: 'export',
    trailingSlash: true,
    poweredByHeader: false,
    images: {
        unoptimized: true
    },
    env: {
        NEXT_PUBLIC_COMMIT_SHA: process.env.NEXT_PUBLIC_COMMIT_SHA ?? ''
    }
};

export default nextConfig;
