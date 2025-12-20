import { Copy } from 'lucide-react';
import { useClipboard } from '../../hooks/useClipboard';

export default function WindowsHostEnumTool() {
    const { copied, copy } = useClipboard();

    const systemCommands = [
        { name: 'System Information', desc: 'Retrieve detailed information about the system', cmd: 'systeminfo' },
        { name: 'Computer System Information', desc: 'Retrieve information about the computer system', cmd: 'Get-WmiObject Win32_ComputerSystem' },
        { name: 'Computer and Domain Name', desc: 'Display the computer and user domain name', cmd: 'echo "$env:COMPUTERNAME.$env:USERDNSDOMAIN"' },
        { name: 'Security Patches', desc: 'List all security patches', cmd: 'Get-Hotfix -description "Security update"' },
        { name: 'Detailed Security Patches', desc: 'List all security patches with detailed information', cmd: 'wmic qfe get HotfixID,ServicePackInEffect,InstallDate,InstalledBy,InstalledOn' },
        { name: 'Environment Variables', desc: 'List all environment variables', cmd: 'Get-ChildItem Env: | ft Key,Value' },
        { name: 'CMD Environment Variables', desc: 'List all environment variables using CMD', cmd: 'set' },
        { name: 'Add AV Exclusion Path', desc: 'Add an exclusion path to the antivirus', cmd: 'Add-MpPreference -ExclusionPath "<Path to be excluded>"' },
        { name: 'List AV Exclusion Paths', desc: 'List all exclusion paths in the antivirus', cmd: 'Get-MpPreference | select -ExpandProperty ExclusionPath' },
    ];

    const networkCommands = [
        { name: 'IP Configuration', desc: 'Display the IP configuration', cmd: 'ipconfig /all' },
        { name: 'ARP Table', desc: 'Display the ARP table', cmd: 'arp -a' },
        { name: 'WLAN Profiles', desc: 'Show all WLAN profiles', cmd: 'netsh wlan show profiles' },
        { name: 'Specific WLAN Profile', desc: 'Show a specific WLAN profile', cmd: 'netsh wlan show profile name="PROFILE-NAME" key=clear' },
    ];

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white mb-2">Windows Host Enumeration</h2>
                <p className="text-gray-400 text-sm">
                    System and network information gathering commands for Windows environments
                </p>
            </div>

            {/* System Information */}
            <div className="htb-card">
                <h3 className="text-lg font-bold text-[#a2ff00] mb-4">System Information Gathering</h3>
                <p className="text-gray-400 text-sm mb-4">Commands to retrieve system information</p>
                <div className="space-y-3">
                    {systemCommands.map((item, idx) => (
                        <div key={idx} className="border-b border-white/5 last:border-0 pb-3 last:pb-0">
                            <div className="flex items-start justify-between gap-3 mb-2">
                                <div className="flex-1">
                                    <span className="text-sm font-bold text-white">{item.name}</span>
                                    <p className="text-xs text-gray-400 mt-1">{item.desc}</p>
                                </div>
                                <button
                                    onClick={() => copy(item.cmd)}
                                    className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#a2ff00]/10 hover:bg-[#a2ff00]/20 text-[#a2ff00] text-xs font-bold transition-colors flex-shrink-0"
                                >
                                    <Copy size={12} />
                                    {copied ? 'Copied!' : 'Copy'}
                                </button>
                            </div>
                            <div className="htb-terminal-content">
                                <pre className="font-mono text-xs text-gray-300 whitespace-pre-wrap break-all">
                                    {item.cmd}
                                </pre>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Network Information */}
            <div className="htb-card">
                <h3 className="text-lg font-bold text-[#a2ff00] mb-4">Network Information Gathering</h3>
                <div className="space-y-3">
                    {networkCommands.map((item, idx) => (
                        <div key={idx} className="border-b border-white/5 last:border-0 pb-3 last:pb-0">
                            <div className="flex items-start justify-between gap-3 mb-2">
                                <div className="flex-1">
                                    <span className="text-sm font-bold text-white">{item.name}</span>
                                    <p className="text-xs text-gray-400 mt-1">{item.desc}</p>
                                </div>
                                <button
                                    onClick={() => copy(item.cmd)}
                                    className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#a2ff00]/10 hover:bg-[#a2ff00]/20 text-[#a2ff00] text-xs font-bold transition-colors flex-shrink-0"
                                >
                                    <Copy size={12} />
                                    {copied ? 'Copied!' : 'Copy'}
                                </button>
                            </div>
                            <div className="htb-terminal-content">
                                <pre className="font-mono text-xs text-gray-300 whitespace-pre-wrap break-all">
                                    {item.cmd}
                                </pre>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
