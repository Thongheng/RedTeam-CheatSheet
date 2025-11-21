import { Server, Settings, Wifi, Globe, Terminal, Shield, BookOpen, Map } from 'lucide-react';
import { CategoryDef } from '../types';

export const CATEGORIES: Record<string, CategoryDef> = {
    SMB: { icon: Server, label: 'SMB & Windows' },
    AD: { icon: Settings, label: 'Active Directory' },
    SCAN: { icon: Wifi, label: 'Network Scanning' },
    WEB: { icon: Globe, label: 'Web Enumeration' },
    REMOTE: { icon: Terminal, label: 'Remote Access' },
    VULN: { icon: Shield, label: 'Vuln & Exploit' },
    GUIDE: { icon: Map, label: 'Guides' },
    REF: { icon: BookOpen, label: 'References' },
};