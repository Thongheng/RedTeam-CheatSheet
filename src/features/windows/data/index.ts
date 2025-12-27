import React from 'react';
import type { Tool } from '../../../types';

// ====================================================================
// WINDOWS TOOLS - Consolidated
// ====================================================================

export const WINDOWS_TOOLS: Tool[] = [
    // --- Enumeration ---
    {
        id: 'powershell_commands',
        name: 'PowerShell Commands',
        category: 'WINDOWS',
        subcategory: 'Enumeration',
        desc: 'System enumeration, Active Directory reconnaissance, and AMSI bypass commands',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/PowerShellTool')),
    },
    {
        id: 'windows_host_enum',
        name: 'Host Enumeration',
        category: 'WINDOWS',
        subcategory: 'Enumeration',
        desc: 'Windows host enumeration commands',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/WindowsHostEnumTool')),
    },

    // --- Exfiltration ---
    {
        id: 'file_transfer',
        name: 'File Transfer',
        category: 'WINDOWS',
        subcategory: 'Exfiltration',
        desc: 'Generate file transfer payloads (SMB, FTP, PowerShell, Certutil)',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/FileTransferTool')),
    },

    // --- Evasion ---
    {
        id: 'obfuscation_tool',
        name: 'Obfuscation',
        category: 'WINDOWS',
        subcategory: 'Evasion',
        desc: 'Polymorphic obfuscation for Python, Bash, Perl, and PowerShell payloads',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/ObfuscationTool')),
    },
];
