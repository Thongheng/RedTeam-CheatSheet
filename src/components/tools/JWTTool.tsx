import React from 'react';
import { Copy, Download } from 'lucide-react';

const JWTTool: React.FC = () => {
    const [rawToken, setRawToken] = React.useState('');
    const [header, setHeader] = React.useState('');
    const [payload, setPayload] = React.useState('');
    const [secretKey, setSecretKey] = React.useState('');
    const [alg, setAlg] = React.useState('HS256');
    const [noneAlgToken, setNoneAlgToken] = React.useState('');

    const handleCopy = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    const decodeToken = (token: string) => {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                setHeader('Invalid JWT - must have 3 parts');
                setPayload('');
                return;
            }

            const decodedHeader = JSON.parse(atob(parts[0]));
            const decodedPayload = JSON.parse(atob(parts[1]));

            setHeader(JSON.stringify(decodedHeader, null, 2));
            setPayload(JSON.stringify(decodedPayload, null, 2));

            // None algorithm attack
            if (alg === 'none') {
                const modifiedHeader = { ...decodedHeader, alg: 'none' };
                const noneHeader = btoa(JSON.stringify(modifiedHeader));
                setNoneAlgToken(`${noneHeader}.${parts[1]}.`);
            }
        } catch (err) {
            setHeader('Invalid JWT format');
            setPayload('');
        }
    };

    React.useEffect(() => {
        if (rawToken) {
            decodeToken(rawToken);
        }
    }, [rawToken, alg]);

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-white mb-2">JSON Web Token (JWT)</h2>
                <p className="text-gray-400 text-sm">
                    Decode, verify, and manipulate JWT tokens. Test for common vulnerabilities like the "none" algorithm attack.
                </p>
            </div>

            <div className="space-y-4">
                <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">JWT Token</label>
                    <textarea
                        value={rawToken}
                        onChange={(e) => setRawToken(e.target.value)}
                        className="w-full bg-black/30 border border-white/10 rounded-lg p-3 text-white font-mono text-sm h-32 focus:border-[#a2ff00]/50 focus:outline-none"
                        placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ..."
                    />
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">Secret Key</label>
                        <input
                            type="text"
                            value={secretKey}
                            onChange={(e) => setSecretKey(e.target.value)}
                            className="w-full bg-black/30 border border-white/10 rounded-lg p-3 text-white text-sm focus:border-[#a2ff00]/50 focus:outline-none"
                            placeholder="your-secret-key"
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">Algorithm</label>
                        <select
                            value={alg}
                            onChange={(e) => setAlg(e.target.value)}
                            className="w-full bg-black/30 border border-white/10 rounded-lg p-3 text-white text-sm focus:border-[#a2ff00]/50 focus:outline-none"
                        >
                            <option value="HS256">HS256</option>
                            <option value="none">None (Attack)</option>
                        </select>
                    </div>
                </div>

                {alg === 'none' && noneAlgToken && (
                    <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-red-400">JWT without Signature (None Attack)</span>
                            <button
                                onClick={() => handleCopy(noneAlgToken)}
                                className="text-red-400 hover:text-red-300 transition-colors"
                            >
                                <Copy size={16} />
                            </button>
                        </div>
                        <code className="text-xs text-red-300 break-all block">{noneAlgToken}</code>
                    </div>
                )}

                <div>
                    <div className="flex items-center justify-between mb-2">
                        <label className="text-sm font-medium text-gray-300">Header (Algorithm & Token Type)</label>
                        <button
                            onClick={() => handleCopy(header)}
                            className="text-gray-400 hover:text-white transition-colors"
                            disabled={!header}
                        >
                            <Copy size={16} />
                        </button>
                    </div>
                    <textarea
                        value={header}
                        readOnly
                        className="w-full bg-black/30 border border-white/10 rounded-lg p-3 text-[#a2ff00] font-mono text-sm h-24"
                        placeholder='{\n  "alg": "HS256",\n  "typ": "JWT"\n}'
                    />
                </div>

                <div>
                    <div className="flex items-center justify-between mb-2">
                        <label className="text-sm font-medium text-gray-300">Payload (JWT Claims)</label>
                        <button
                            onClick={() => handleCopy(payload)}
                            className="text-gray-400 hover:text-white transition-colors"
                            disabled={!payload}
                        >
                            <Copy size={16} />
                        </button>
                    </div>
                    <textarea
                        value={payload}
                        readOnly
                        className="w-full bg-black/30 border border-white/10 rounded-lg p-3 text-[#a2ff00] font-mono text-sm h-48"
                        placeholder='{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022\n}'
                    />
                </div>
            </div>
        </div>
    );
};

export default JWTTool;
