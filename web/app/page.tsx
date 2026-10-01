'use client';

import { useDrive } from '~/lib/use-drive';
import { SignInGate } from '~/components/sign-in-gate';
import { DriveApp } from '~/components/drive-app';

export default function Page() {
    const { status } = useDrive();

    if (status === 'ready') return <DriveApp />;
    return <SignInGate />;
}
