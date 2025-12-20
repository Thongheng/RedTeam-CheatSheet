import React from 'react';
import type { Tool } from '../../../types';

// ============================================
// Interactive component-based Common Tools
// ============================================

export const COMMON_TOOLS: Tool[] = [
    {
        id: 'revshell',
        name: 'Reverse Shell Generator',
        category: 'EXPLOIT',
        subcategory: 'Reverse Shell',
        desc: 'Generate reverse shell payloads for 56+ languages and platforms (bash, python, powershell, nc, java, etc.)',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/ReverseShell')),
    },
    {
        id: 'msfvenom_builder',
        name: 'MSFVenom Builder',
        category: 'EXPLOIT',
        subcategory: 'Payloads',
        desc: 'Interactive MSFVenom payload generator with visual interface. Configure payload, encoder, format, and more.',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/MSFVenomBuilder')),
    },
    {
        id: 'cve_research',
        name: 'CVE Research',
        category: 'RECON',
        subcategory: 'Vulnerability Research',
        desc: 'Search Common Vulnerabilities and Exposures (CVEs) with CVSS scoring and detailed information.',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/CVEResearch')),
    },
    {
        id: 'nmap_parser',
        name: 'Nmap Report Parser',
        category: 'RECON',
        subcategory: 'Network Scanning',
        desc: 'Upload and parse Nmap XML scan results with sortable/filterable table view.',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/NmapParser')),
    },
];
