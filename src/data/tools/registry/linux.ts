import type { Tool } from '../../../types';
import React from 'react';

export const LINUX_REGISTRY: Tool[] = [
    {
        id: 'linux_enumeration',
        name: 'Linux Enumeration',
        category: 'LINUX',
        subcategory: 'Enumeration',
        desc: 'TTY shell upgrade and comprehensive Linux system enumeration',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/LinuxEnumTool')),
    },
];
