import React, { useState } from 'react';
import { Card, TextArea, Button, Select } from '../../../components/ui';
import { Copy, Check, Code } from 'lucide-react';

export default function XSSObfuscator() {
    const [input, setInput] = useState('');
    const [output, setOutput] = useState('');
    const [method, setMethod] = useState('base64');
    const [showToast, setShowToast] = useState(false);

    const handleObfuscate = () => {
        if (!input) {
            setOutput('');
            return;
        }

        try {
            if (method === 'base64') {
                const obf = btoa(input);
                setOutput(`eval(atob('${obf}'))`);
            } else if (method === 'charcode') {
                const charObf = input
                    .split("")
                    .map((c) => c.charCodeAt(0))
                    .join(",");
                setOutput(`eval(String.fromCharCode(${charObf}))`);
            }
        } catch (e) {
            setOutput('Error generating payload');
        }
    };

    const copyToClipboard = () => {
        if (!output) return;
        navigator.clipboard.writeText(output);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white">XSS Obfuscator</h2>
                <p className="text-gray-400">Obfuscate XSS payloads to bypass WAF and filters.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Card className="!p-6 space-y-4">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Input JavaScript</h3>
                    <TextArea
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        placeholder="alert('XSS')"
                        className="flex-1 min-h-[200px]"
                    />
                    <div className="flex gap-2">
                        <Select
                            className="flex-1"
                            value={method}
                            onChange={setMethod}
                            options={[
                                { label: 'Base64 Wrapper', value: 'base64' },
                                { label: 'String.fromCharCode', value: 'charcode' },
                            ]}
                        />
                        <Button onClick={handleObfuscate} icon={<Code size={16} />}>
                            Obfuscate
                        </Button>
                    </div>
                </Card>

                <Card className="!p-6 space-y-4">
                    <div className="flex items-center justify-between">
                        <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Obfuscated Output</h3>
                        <Button
                            size="sm"
                            variant={output ? 'primary' : 'secondary'}
                            disabled={!output}
                            onClick={copyToClipboard}
                            icon={<Copy size={14} />}
                        >
                            Copy
                        </Button>
                    </div>
                    <TextArea
                        readOnly
                        value={output}
                        placeholder="// Result will appear here..."
                        className="flex-1 min-h-[200px] text-orange-300"
                    />
                </Card>
            </div>

            {/* Toast */}
            <div className={`fixed bottom-6 left-1/2 -translate-x-1/2 bg-[#0d1117] border border-[#a2ff00] px-4 py-2 rounded-lg flex items-center gap-2 transition-all ${showToast ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
                <Check size={16} className="text-[#a2ff00]" />
                <span className="text-sm font-bold text-white">Copied!</span>
            </div>
        </div>
    );
}
