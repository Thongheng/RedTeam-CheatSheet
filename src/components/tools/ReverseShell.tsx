import React, { useState, useMemo } from 'react';
import { Copy, ChevronDown, Globe, Hash, Terminal, Check } from 'lucide-react';
import payloads from '../../assets/data/RevShell.json';
import { Input, Select, Tag, Button, Card } from '../ui';
import { ToolHeader } from '../ui/ToolHeader';
import { Table } from '../ui/Table';
import type { Column } from '../ui/Table';

interface ShellPayload {
    name: string;
    command: string;
    tags: string[];
}

interface ShellConfig {
    ip: string;
    port: string;
    shell: string;
}

const SHELL_OPTIONS = [
    { label: '/bin/sh', value: '/bin/sh' },
    { label: '/bin/bash', value: '/bin/bash' },
    { label: 'sh', value: 'sh' },
    { label: 'bash', value: 'bash' },
    { label: 'cmd', value: 'cmd' },
    { label: 'powershell', value: 'powershell' },
    { label: 'pwsh', value: 'pwsh' },
];

const TAG_COLORS: Record<string, 'orange' | 'green' | 'blue'> = {
    linux: 'orange',
    mac: 'green',
    windows: 'blue',
};

export default function ReverseShell() {
    const [config, setConfig] = useState<ShellConfig>(() => {
        const saved = localStorage.getItem('redsploit_revshell_config');
        return saved ? JSON.parse(saved) : { ip: '', port: '4444', shell: '/bin/sh' };
    });

    const [copiedId, setCopiedId] = useState<string | null>(null);
    const [showToast, setShowToast] = useState(false);

    // Process payloads with variable substitution
    const processedPayloads = useMemo(() => {
        return (payloads as ShellPayload[]).map((payload, idx) => {
            let cmd = payload.command;
            cmd = cmd.replace(/\$\{values\.ip\}/g, config.ip || '$IP');
            cmd = cmd.replace(/\$\{values\.port\}/g, config.port || '$PORT');
            cmd = cmd.replace(/\{shell\}/g, config.shell || '/bin/sh');
            return {
                id: `shell-${idx}`,
                name: payload.name,
                command: cmd,
                tags: payload.tags,
            };
        });
    }, [config]);

    const handleConfigChange = (key: keyof ShellConfig, value: string) => {
        setConfig(prev => {
            const next = { ...prev, [key]: value };
            localStorage.setItem('redsploit_revshell_config', JSON.stringify(next));
            return next;
        });
    };

    const copyToClipboard = (text: string, id: string, encoding?: 'base64' | 'url' | 'doubleurl') => {
        let encoded = text;
        if (encoding === 'base64') {
            // For PowerShell, use UTF-16LE
            if (text.toLowerCase().includes('powershell')) {
                const utf16le = new TextEncoder().encode(
                    Array.from(text).map(c => c + '\0').join('')
                );
                encoded = 'powershell -encodedcommand ' + btoa(String.fromCharCode(...utf16le));
            } else {
                encoded = btoa(text);
            }
        } else if (encoding === 'url') {
            encoded = encodeURIComponent(text);
        } else if (encoding === 'doubleurl') {
            encoded = encodeURIComponent(encodeURIComponent(text));
        }

        navigator.clipboard.writeText(encoded);
        setCopiedId(id);
        setShowToast(true);
        setTimeout(() => {
            setCopiedId(null);
            setShowToast(false);
        }, 2000);
    };

    const columns: Column<typeof processedPayloads[0]>[] = [
        {
            key: 'name',
            title: 'Name',
            dataIndex: 'name',
            sortable: true,
            width: '200px',
        },
        {
            key: 'tags',
            title: 'Platform',
            dataIndex: 'tags',
            filters: [
                { text: 'Linux', value: 'linux' },
                { text: 'macOS', value: 'mac' },
                { text: 'Windows', value: 'windows' },
            ],
            render: (tags: string[]) => (
                <div className="flex flex-wrap gap-1">
                    {tags.map(tag => (
                        <Tag key={tag} color={TAG_COLORS[tag] || 'gray'}>
                            {tag}
                        </Tag>
                    ))}
                </div>
            ),
        },
        {
            key: 'action',
            title: 'Action',
            dataIndex: 'id',
            render: (_, record) => (
                <div className="flex items-center gap-2">
                    <Button
                        size="sm"
                        variant={copiedId === record.id ? 'primary' : 'secondary'}
                        icon={copiedId === record.id ? <Check size={14} /> : <Copy size={14} />}
                        onClick={() => copyToClipboard(record.command, record.id)}
                    >
                        {copiedId === record.id ? 'Copied!' : 'Copy'}
                    </Button>
                    <div className="relative group">
                        <Button size="sm" variant="ghost" icon={<ChevronDown size={14} />} />
                        <div className="absolute right-0 mt-1 w-44 bg-[#0d1117] border border-white/10 rounded-lg shadow-xl z-50 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all">
                            <button
                                onClick={() => copyToClipboard(record.command, record.id + '-b64', 'base64')}
                                className="w-full px-4 py-2 text-left text-xs text-gray-300 hover:bg-[#a2ff00]/10 hover:text-[#a2ff00]"
                            >
                                Base64 Encoded
                            </button>
                            <button
                                onClick={() => copyToClipboard(record.command, record.id + '-url', 'url')}
                                className="w-full px-4 py-2 text-left text-xs text-gray-300 hover:bg-[#a2ff00]/10 hover:text-[#a2ff00]"
                            >
                                URL Encoded
                            </button>
                            <button
                                onClick={() => copyToClipboard(record.command, record.id + '-durl', 'doubleurl')}
                                className="w-full px-4 py-2 text-left text-xs text-gray-300 hover:bg-[#a2ff00]/10 hover:text-[#a2ff00]"
                            >
                                Double URL Encoded
                            </button>
                        </div>
                    </div>
                </div>
            ),
        },
    ];

    return (
        <div className="space-y-6">
            {/* Header */}
            <ToolHeader
                title="Reverse Shell Generator"
                description="Generate reverse shell payloads for various languages and platforms. Enter your listener IP and port, then copy the command."
                badge="RT"
                icon={<Terminal size={20} />}
            />

            {/* Configuration */}
            <Card className="!p-6">
                <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-4">Configuration</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <Input
                        label="Listener IP"
                        icon={<Globe size={16} />}
                        placeholder="10.10.14.5"
                        value={config.ip}
                        onChange={(e) => handleConfigChange('ip', e.target.value)}
                    />
                    <Input
                        label="Listener Port"
                        icon={<Hash size={16} />}
                        placeholder="4444"
                        value={config.port}
                        onChange={(e) => handleConfigChange('port', e.target.value)}
                    />
                    <Select
                        label="Shell Type"
                        options={SHELL_OPTIONS}
                        value={config.shell}
                        onChange={(v) => handleConfigChange('shell', v)}
                    />
                </div>
            </Card>

            {/* Payloads Table */}
            <Table
                columns={columns}
                data={processedPayloads}
                rowKey={(record) => record.id}
                searchable
                searchPlaceholder="Search payloads..."
                emptyText="No payloads match your search"
                expandable={{
                    expandedRowRender: (record) => (
                        <div className="htb-terminal">
                            <div className="htb-terminal-header">
                                <div className="htb-terminal-dots">
                                    <span className="htb-terminal-dot htb-terminal-dot--red"></span>
                                    <span className="htb-terminal-dot htb-terminal-dot--yellow"></span>
                                    <span className="htb-terminal-dot htb-terminal-dot--green"></span>
                                </div>
                                <span className="text-xs text-gray-500 font-mono">{record.name}</span>
                            </div>
                            <div className="htb-terminal-content">
                                <pre className="whitespace-pre-wrap break-all text-[#a2ff00]">{record.command}</pre>
                            </div>
                        </div>
                    ),
                }}
            />

            {/* Stats */}
            <div className="text-xs text-gray-500 flex items-center gap-4">
                <span>{processedPayloads.length} payloads available</span>
                <span>•</span>
                <span>Config saved to browser storage</span>
            </div>

            {/* Toast */}
            <div
                className={`fixed bottom-6 left-1/2 transform -translate-x-1/2 bg-[#0d1117] border-2 border-[#a2ff00] px-6 py-4 rounded-xl flex items-center gap-3 shadow-2xl shadow-[#a2ff00]/20 transition-all duration-300 ${showToast
                    ? 'translate-y-0 opacity-100'
                    : 'translate-y-20 opacity-0 pointer-events-none'
                    }`}
                style={{ zIndex: 9999 }}
            >
                <div className="bg-[#a2ff00] rounded-full p-1.5 text-black">
                    <Check size={16} strokeWidth={3} />
                </div>
                <span className="font-bold text-sm text-white">Copied to clipboard!</span>
            </div>
        </div>
    );
}
