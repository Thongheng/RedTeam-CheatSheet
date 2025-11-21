import { Server, Settings, Wifi, Globe, Terminal, Shield, BookOpen, Map } from 'lucide-react';
import { CategoryDef } from '../types';

export const CATEGORIES: Record<string, CategoryDef> = {
    WINDOWS: { icon: Server, label: 'Windows' },
    AD: { icon: Settings, label: 'Active Directory' },
    SERVICE: { icon: Wifi, label: 'Service Enumeration' },
    WEB: { icon: Globe, label: 'Web Enumeration' },
    OTHER: { icon: Terminal, label: 'Other' },
    EXPLOIT: { icon: Shield, label: 'Exploitation' },
    GUIDE: { icon: Map, label: 'Guides' },
    REF: { icon: BookOpen, label: 'References' },
};