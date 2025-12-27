import React from 'react';
import type { Tool } from '../../../types';

// ====================================================================
// LINUX TOOLS - Consolidated
// ====================================================================

export const LINUX_TOOLS: Tool[] = [
    // --- Enumeration ---
    {
        id: 'linux_enumeration',
        name: 'Linux Enumeration',
        category: 'LINUX',
        subcategory: 'Enumeration',
        desc: 'TTY shell upgrade and comprehensive Linux system enumeration',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/LinuxEnumTool')),
    },
];
