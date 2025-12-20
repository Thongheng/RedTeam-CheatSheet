import {
    Globe, Terminal, Monitor, Smartphone,
    Box, Shield, Zap, Search, Layout
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

export interface Category {
    label: string;
    icon: LucideIcon;
    description?: string;
}

export const CATEGORIES: Record<string, Category> = {
    RECON: {
        label: 'Reconnaissance',
        icon: Search,
        description: 'Information gathering and scanning tools'
    },
    WEB: {
        label: 'Web Exploitation',
        icon: Globe,
        description: 'Web application security tools'
    },
    EXPLOIT: {
        label: 'Exploitation',
        icon: Zap,
        description: 'Shells, payloads, and exploitation frameworks'
    },
    WINDOWS: {
        label: 'Windows',
        icon: Monitor,
        description: 'Windows-specific post-exploitation'
    },
    LINUX: {
        label: 'Linux',
        icon: Terminal,
        description: 'Linux-specific post-exploitation'
    },
    MOBILE: {
        label: 'Mobile',
        icon: Smartphone,
        description: 'Android and iOS assessment'
    },
    OTHER: {
        label: 'Other / Misc',
        icon: Box,
        description: 'Miscellaneous utilities'
    }
};

export const CATEGORY_ORDER = [
    'RECON',
    'WEB',
    'EXPLOIT',
    'WINDOWS',
    'LINUX',
    'MOBILE',
    'OTHER'
];

export const SUBCATEGORIES: Record<string, string[]> = {
    RECON: [
        'Network Scanning',
        'Vulnerability Research'
    ],
    WEB: [
        'Subdomain Enum',
        'Fingerprinting',
        'XSS',
        'SQLi',
        'NoSQLi',
        'SSTI',
        'File Inclusion',
        'XXE',
        'CSRF',
        'Data Manipulation',
        'JWT',
        'SSRF',
        'Web Shells'
    ],
    EXPLOIT: [
        'Reverse Shell',
        'Payloads'
    ],
    WINDOWS: [
        'Enumeration',
        'Host Enumeration',
        'Exfiltration',
        'Evasion'
    ],
    LINUX: [
        'Enumeration'
    ],
    MOBILE: [
        'Android'
    ],
    OTHER: [
        'File Transfer'
    ]
};
