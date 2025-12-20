import React, { useState } from 'react';
import { Card, TextArea, Button, Select, Input } from '../ui';
import { FileCode, Settings, Copy, Check, Terminal } from 'lucide-react';

export default function ObfuscationTool() {
    const [command, setCommand] = useState('');
    const [output, setOutput] = useState('');
    const [filename, setFilename] = useState('payload');
    const [mode, setMode] = useState('bash');
    const [showToast, setShowToast] = useState(false);

    const MODE_OPTIONS = [
        { label: 'Bash (Base64 + Decode)', value: 'bash' },
        { label: 'Powershell (Base64 -e)', value: 'ps1' },
        { label: 'CMD / Batch (Certutil)', value: 'cmd' },
        { label: 'Python (Exec Base64)', value: 'python' },
        { label: 'Perl (Exec Base64)', value: 'perl' },
    ];

    const generatePayload = () => {
        if (!command) {
            setOutput('');
            return;
        }

        const b64 = btoa(command);
        let payload = '';
        const file = filename || 'payload';

        switch (mode) {
            case 'bash':
                payload = `echo "${b64}" | base64 -d | bash`;
                break;
            case 'ps1':
                // Powershell uses UTF-16LE for base64 encoded commands
                const str = command;
                const utf16le = new Uint16Array(str.length);
                for (let i = 0; i < str.length; i++) {
                    utf16le[i] = str.charCodeAt(i);
                }
                // We can't easily do proper UTF-16LE in browser JS without more logic or hacks
                // HackTools usually just did standard base64 for 'bash' styles, but for PS -Enc it needs specific encoding.
                // For simplicity/parity with HackTools "Obfuscated Files" which often just does:
                // echo "base64" > file.sh; chmod +x file.sh; ./file.sh

                // Let's stick to the "File Dropper" style if that's what the tool was
                // "Obfuscated Files" in HackTools creates a hidden file from base64.

                payload = `powershell -nop -e ${b64}`; // This is likely incorrect for PS without unicode, but standard for simple stuff. 
                // Let's use the file dropper technique instead which is safer for standard b64
                payload = `echo ${b64} > ${file}.b64 && certutil -decode ${file}.b64 ${file}.ps1 && powershell ./${file}.ps1`;
                break;
            case 'cmd':
                payload = `echo ${b64} > ${file}.tv && certutil -decode ${file}.tv ${file}.bat && ${file}.bat`;
                break;
            case 'python':
                payload = `python -c "import base64;exec(base64.b64decode('${b64}'))"`;
                break;
            case 'perl':
                payload = `perl -e 'use MIME::Base64;eval(decode_base64("${b64}"))'`;
                break;
            default:
                payload = '';
        }

        setOutput(payload);
    };

    // Auto-generate
    React.useEffect(() => {
        generatePayload();
    }, [command, mode, filename]);

    const copyToClipboard = () => {
        if (!output) return;
        navigator.clipboard.writeText(output);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white flex items-center gap-2">
                    <Terminal className="text-htb-green" size={24} />
                    Obfuscated Files / Command Generator
                </h2>
                <p className="text-gray-400">
                    Generate file-less or file-dropping one-liners to execute commands via Base64 decoding.
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Input */}
                <Card className="!p-6 space-y-4 flex flex-col h-full">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Configuration</h3>

                    <Select
                        label="Target Loader"
                        options={MODE_OPTIONS}
                        value={mode}
                        onChange={setMode}
                    />

                    <Input
                        label="Command to Obfuscate"
                        placeholder="whoami /all"
                        value={command}
                        onChange={(e) => setCommand(e.target.value)}
                        icon={<Terminal size={14} />}
                    />

                    {(mode === 'cmd' || mode === 'ps1') && (
                        <Input
                            label="Temporary Filename"
                            placeholder="payload"
                            value={filename}
                            onChange={(e) => setFilename(e.target.value)}
                        />
                    )}
                </Card>

                {/* Output */}
                <Card className="!p-6 space-y-4 flex flex-col h-full">
                    <div className="flex items-center justify-between">
                        <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">One-Liner Payload</h3>
                        <Button
                            size="sm"
                            variant={output ? 'primary' : 'secondary'}
                            disabled={!output}
                            onClick={copyToClipboard}
                            icon={<Copy size={14} />}
                        >
                            Copy Payload
                        </Button>
                    </div>

                    <TextArea
                        readOnly
                        value={output}
                        className="flex-1 min-h-[200px] font-mono text-sm text-yellow-300 break-all"
                        placeholder="// Payload will appear here..."
                    />
                </Card>
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
