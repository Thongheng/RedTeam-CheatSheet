import React from 'react';
import type { Tool } from '../../../types';
import { createArg } from '../../../utils/toolHelpers';

// ====================================================================
// UTILITY TOOLS - Consolidated (Network, Research, File Transfer, Encoding)
// ====================================================================

export const UTILITY_TOOLS: Tool[] = [
    // --- Network Scanning ---
    {
        id: 'nmap_parser',
        name: 'Nmap Report Parser',
        category: 'UTILITIES',
        subcategory: 'Network Scanning',
        desc: 'Upload and parse Nmap XML scan results with sortable/filterable table view.',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/NmapParser')),
    },

    // --- Vulnerability Research ---
    {
        id: 'cve_research',
        name: 'CVE Research',
        category: 'UTILITIES',
        subcategory: 'Vulnerability Research',
        desc: 'Search Common Vulnerabilities and Exposures (CVEs) with CVSS scoring and detailed information.',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/CVEResearch')),
    },

    // --- File Transfer ---
    {
        id: 'scp',
        name: 'SCP',
        category: 'UTILITIES',
        subcategory: 'File Transfer',
        desc: 'Secure copy (remote file copy program).',
        authMode: 'required',
        generate: (v, args) => {
            return `scp -r ${v.filepath || '$FILEPATH'} ${v.username || '$USERNAME'}@${v.target || '$TARGET'}:/home/${v.username || '$DESTINATION'}/`;
        }
    },
    {
        id: 'bash',
        name: 'Bash',
        category: 'UTILITIES',
        subcategory: 'File Transfer',
        desc: 'Bash built-in file transfer',
        authMode: 'none',
        args: [],
        generate: (v, args) => {
            return `# Sender
nc -lvnp 8000 < ${v.filepath || '$FILEPATH'}

# Receiver
nc -q 0 ${v.target || '$TARGET'} 8000 > ${v.filepath || '$FILEPATH'}`;
        }
    },
    {
        id: 'impacket-smb',
        name: 'Impacket SMB Server',
        category: 'UTILITIES',
        subcategory: 'File Transfer',
        desc: 'Impacket SMB Server for file sharing.',
        authMode: 'none',
        generate: (v, args) => {
            return `sudo impacket-smbserver share -smb2support .`;
        }
    },

    // --- Encoding ---
    // (Note: Data encoding is in WEB category, but could be moved here if needed)
];
