import type { Tool } from '../../../types';
import React from 'react';

export const MOBILE_TOOLS: Tool[] = [
    {
        id: 'adb_commands',
        name: 'ADB Commands',
        category: 'MOBILE',
        subcategory: 'Android',
        desc: 'Android Debug Bridge commands for device enumeration, app manipulation, and file operations',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/ADBTool')),
    },
    {
        id: 'mobile_hooking',
        name: 'Hooking & Reversing',
        category: 'MOBILE',
        subcategory: 'Android',
        desc: 'Dynamic analysis with Frida scripts and Objection commands',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/MobileHookingTool')),
    },
];
