import React, { useState } from 'react';
import { Card, TextArea, Button, Select } from '../ui';
import { Lock, Unlock, Copy, FileText, Delete, Check } from 'lucide-react';
// @ts-ignore
import escape_quotes from 'escape-quotes';

export default function DataEncodingTool() {
    const [input, setInput] = useState('');
    const [output, setOutput] = useState('');
    const [mode, setMode] = useState('base64');
    const [showToast, setShowToast] = useState(false);

    const MODE_OPTIONS = [
        { label: 'Base64', value: 'base64' },
        { label: 'URI / URL', value: 'uri' },
        { label: 'Hexadecimal', value: 'hex' },
    ];

    const toHex = (str: string) => {
        let result = '';
        for (let i = 0; i < str.length; i++) {
            let hex = str.charCodeAt(i).toString(16).toUpperCase();
            if (hex.length === 1) {
                hex = '0' + hex;
            }
            result += hex;
        }
        return result;
    };

    const hex2a = (hex: string) => {
        let str = '';
        for (let i = 0; i < hex.length; i += 2) {
            const code = parseInt(hex.substr(i, 2), 16);
            if (!isNaN(code)) {
                str += String.fromCharCode(code);
            }
        }
        return str;
    };

    const handleAction = (type: 'encode' | 'decode') => {
        let res = '';
        try {
            switch (mode) {
                case 'base64':
                    res = type === 'encode' ? btoa(input) : atob(input);
                    break;
                case 'uri':
                    res = type === 'encode' ? encodeURI(input) : decodeURI(input);
                    break;
                case 'hex':
                    res = type === 'encode' ? toHex(input) : hex2a(input);
                    break;
            }
            setOutput(res);
        } catch (e) {
            setOutput('Error: Invalid input for this operation');
        }
    };

    const handleQuoteEscape = () => {
        try {
            setOutput(escape_quotes(input));
        } catch (e) {
            setOutput('Error escaping quotes');
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
                <h2 className="text-2xl font-black text-white flex items-center gap-2">
                    <FileText className="text-htb-green" size={24} />
                    Data Encoding
                </h2>
                <p className="text-gray-400">
                    Encode and decode data for evasion or analysis. Supports Base64, URL, Hex, and Quote Escaping.
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Input Section */}
                <Card className="!p-6 space-y-4 flex flex-col h-full">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Input Data</h3>
                    <TextArea
                        placeholder="Enter text to encode or decode..."
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        className="flex-1 min-h-[200px] font-mono text-sm"
                    />

                    <div className="flex flex-col gap-3">
                        <Select
                            label="Encoding Mode"
                            options={MODE_OPTIONS}
                            value={mode}
                            onChange={setMode}
                        />
                        <div className="flex flex-wrap gap-2">
                            <Button
                                onClick={() => handleAction('encode')}
                                icon={<Lock size={16} />}
                                className="flex-1"
                            >
                                Encode
                            </Button>
                            <Button
                                onClick={() => handleAction('decode')}
                                variant="secondary"
                                icon={<Unlock size={16} />}
                                className="flex-1"
                            >
                                Decode
                            </Button>
                            <Button
                                onClick={handleQuoteEscape}
                                variant="ghost"
                                className="w-full md:w-auto"
                            >
                                Quote Escape
                            </Button>
                        </div>
                    </div>
                </Card>

                {/* Output Section */}
                <Card className="!p-6 space-y-4 flex flex-col h-full">
                    <div className="flex items-center justify-between">
                        <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Result</h3>
                        <div className="flex items-center gap-2">
                            <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => setOutput('')}
                                icon={<Delete size={14} />}
                            >
                                Clear
                            </Button>
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
                    </div>
                    <TextArea
                        readOnly
                        value={output}
                        placeholder="// Result will appear here"
                        className="flex-1 min-h-[200px] font-mono text-sm text-blue-300"
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
