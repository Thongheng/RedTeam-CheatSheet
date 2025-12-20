import React, { useState } from 'react';
import { Upload, FileText, AlertCircle } from 'lucide-react';

interface NmapHost {
    ip: string;
    hostname?: string;
    ports: Array<{
        portid: string;
        protocol: string;
        state: string;
        service?: string;
        version?: string;
    }>;
}

export default function NmapParser() {
    const [hosts, setHosts] = useState<NmapHost[]>([]);
    const [error, setError] = useState('');
    const [fileName, setFileName] = useState('');

    const parseNmapXML = (xmlText: string) => {
        try {
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(xmlText, 'text/xml');

            // Check for parsing errors
            const parserError = xmlDoc.querySelector('parsererror');
            if (parserError) {
                throw new Error('Invalid XML format');
            }

            const parsedHosts: NmapHost[] = [];
            const hostElements = xmlDoc.querySelectorAll('host');

            hostElements.forEach((hostEl) => {
                const statusEl = hostEl.querySelector('status');
                if (statusEl?.getAttribute('state') !== 'up') return;

                const addressEl = hostEl.querySelector('address[addrtype="ipv4"]');
                const hostnameEl = hostEl.querySelector('hostname');

                const ip = addressEl?.getAttribute('addr') || 'Unknown';
                const hostname = hostnameEl?.getAttribute('name');

                const ports: NmapHost['ports'] = [];
                const portElements = hostEl.querySelectorAll('port');

                portElements.forEach((portEl) => {
                    const stateEl = portEl.querySelector('state');
                    const serviceEl = portEl.querySelector('service');

                    ports.push({
                        portid: portEl.getAttribute('portid') || '',
                        protocol: portEl.getAttribute('protocol') || '',
                        state: stateEl?.getAttribute('state') || 'unknown',
                        service: serviceEl?.getAttribute('name') || undefined,
                        version: serviceEl?.getAttribute('product')
                            ? `${serviceEl.getAttribute('product')} ${serviceEl.getAttribute('version') || ''}`.trim()
                            : undefined,
                    });
                });

                if (ports.length > 0) {
                    parsedHosts.push({ ip, hostname: hostname || undefined, ports });
                }
            });

            return parsedHosts;
        } catch (err) {
            throw new Error('Failed to parse Nmap XML: ' + (err instanceof Error ? err.message : 'Unknown error'));
        }
    };

    const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;

        setFileName(file.name);
        setError('');

        const reader = new FileReader();
        reader.onload = (event) => {
            try {
                const xmlText = event.target?.result as string;
                const parsed = parseNmapXML(xmlText);

                if (parsed.length === 0) {
                    setError('No active hosts with open ports found in the scan');
                    setHosts([]);
                } else {
                    setHosts(parsed);
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : 'Failed to parse file');
                setHosts([]);
            }
        };
        reader.onerror = () => {
            setError('Failed to read file');
            setHosts([]);
        };
        reader.readAsText(file);
    };

    return (
        <div className="animate-fade-in">
            <div className="mb-6">
                <h2 className="text-2xl font-bold text-white mb-2">Nmap Report Parser</h2>
                <p className="text-gray-400 text-sm leading-relaxed">
                    Upload and parse Nmap XML scan results. Displays hosts, ports, services, and versions in a sortable table view.
                </p>
            </div>

            {/* File Upload */}
            <div className="htb-card mb-6">
                <label className="block cursor-pointer">
                    <div className="border-2 border-dashed border-white/10 rounded-lg p-8 text-center hover:border-[#a2ff00]/50 transition-colors">
                        <Upload size={48} className="mx-auto mb-3 text-gray-500" />
                        <p className="text-sm font-bold text-gray-300 mb-1">
                            {fileName || 'Click to upload Nmap XML file'}
                        </p>
                        <p className="text-xs text-gray-500">
                            Supports nmap -oX output format
                        </p>
                    </div>
                    <input
                        type="file"
                        accept=".xml"
                        onChange={handleFileUpload}
                        className="hidden"
                    />
                </label>
            </div>

            {/* Error Display */}
            {error && (
                <div className="htb-card mb-6 border-red-500/20 bg-red-500/5">
                    <div className="flex items-start gap-3">
                        <AlertCircle size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
                        <div>
                            <div className="text-sm font-bold text-red-300 mb-1">Error</div>
                            <div className="text-xs text-red-400">{error}</div>
                        </div>
                    </div>
                </div>
            )}

            {/* Results Table */}
            {hosts.length > 0 && (
                <div className="htb-card">
                    <div className="flex items-center gap-2 mb-4">
                        <FileText size={18} className="text-[#a2ff00]" />
                        <h3 className="text-lg font-bold text-white">
                            Scan Results ({hosts.length} {hosts.length === 1 ? 'host' : 'hosts'})
                        </h3>
                    </div>

                    <div className="space-y-6">
                        {hosts.map((host, idx) => (
                            <div key={idx} className="border border-white/5 rounded-lg overflow-hidden">
                                <div className="bg-white/5 px-4 py-3">
                                    <div className="flex items-center gap-3">
                                        <span className="text-sm font-bold text-[#a2ff00]">{host.ip}</span>
                                        {host.hostname && (
                                            <span className="text-xs text-gray-400">({host.hostname})</span>
                                        )}
                                        <span className="text-xs text-gray-500">
                                            {host.ports.length} {host.ports.length === 1 ? 'port' : 'ports'}
                                        </span>
                                    </div>
                                </div>

                                <div className="overflow-x-auto">
                                    <table className="w-full">
                                        <thead>
                                            <tr className="border-b border-white/5">
                                                <th className="text-left px-4 py-2 text-xs font-bold text-gray-400 uppercase">Port</th>
                                                <th className="text-left px-4 py-2 text-xs font-bold text-gray-400 uppercase">Protocol</th>
                                                <th className="text-left px-4 py-2 text-xs font-bold text-gray-400 uppercase">State</th>
                                                <th className="text-left px-4 py-2 text-xs font-bold text-gray-400 uppercase">Service</th>
                                                <th className="text-left px-4 py-2 text-xs font-bold text-gray-400 uppercase">Version</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {host.ports.map((port, portIdx) => (
                                                <tr key={portIdx} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                                                    <td className="px-4 py-2 text-sm font-mono text-white">{port.portid}</td>
                                                    <td className="px-4 py-2 text-sm text-gray-400">{port.protocol}</td>
                                                    <td className="px-4 py-2">
                                                        <span className={`inline-block px-2 py-0.5 rounded text-xs font-bold ${port.state === 'open'
                                                            ? 'bg-green-500/20 text-green-300'
                                                            : port.state === 'closed'
                                                                ? 'bg-red-500/20 text-red-300'
                                                                : 'bg-gray-500/20 text-gray-300'
                                                            }`}>
                                                            {port.state}
                                                        </span>
                                                    </td>
                                                    <td className="px-4 py-2 text-sm text-gray-300">{port.service || '-'}</td>
                                                    <td className="px-4 py-2 text-sm text-gray-400 font-mono">{port.version || '-'}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {hosts.length === 0 && !error && fileName && (
                <div className="htb-card text-center py-8">
                    <FileText size={48} className="mx-auto mb-3 text-gray-600" />
                    <p className="text-sm text-gray-400">No scan results to display</p>
                </div>
            )}
        </div>
    );
}
