import type { Tool } from '../../../types';
import React from 'react';

export const WINDOWS_TOOLS: Tool[] = [
    {
        id: 'powershell_commands',
        name: 'PowerShell Commands',
        category: 'WINDOWS',
        subcategory: 'Enumeration',
        desc: 'System enumeration, Active Directory reconnaissance, and AMSI bypass commands',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/PowerShellTool')),
    },
    {
        id: 'windows_host_enum',
        name: 'Host Enumeration',
        category: 'WINDOWS',
        subcategory: 'Host Enumeration',
        desc: 'Windows system and network information gathering commands',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/WindowsHostEnumTool')),
    },
    {
        id: 'file_transfer',
        name: 'File Transfer',
        category: 'WINDOWS',
        subcategory: 'Exfiltration',
        desc: 'Generate file transfer payloads (SMB, FTP, PowerShell, Certutil)',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/FileTransferTool')),
    },
    {
        id: 'obfuscation_tool',
        name: 'Obfuscation',
        category: 'WINDOWS',
        subcategory: 'Evasion',
        desc: 'Polymorphic obfuscation for Python, Bash, Perl, and PowerShell payloads',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/ObfuscationTool')),
    },
];
