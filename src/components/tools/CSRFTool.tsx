import React, { useEffect, useState } from 'react';
import { Card, Input, TextArea, Button } from '../ui';
import { useCSRFStore } from '../../stores/csrfStore';
import { AlertCircle, FileCode, Play, Copy, Check } from 'lucide-react';

export default function CSRFTool() {
    const {
        error,
        setError,
        request,
        setRequest,
        parsedPostBody,
        setParsedPostBody,
    } = useCSRFStore();

    const [csrfPayload, setCsrfPayload] = useState<string>('');
    const [autoSubmit, setAutoSubmit] = useState<boolean>(false);
    const [showToast, setShowToast] = useState(false);

    // Parse Body helper
    const parsePostBody = (contentType: string, body: string) => {
        try {
            if (contentType && contentType.includes('application/x-www-form-urlencoded')) {
                return body.split('&').reduce((obj: Record<string, string>, pair) => {
                    const [key, value] = pair.split('=');
                    if (key) obj[key] = decodeURIComponent(value || '');
                    return obj;
                }, {});
            }

            if (contentType && contentType.includes('application/json')) {
                return JSON.parse(body);
            }

            // Default fallback or error
            return {};
        } catch (err) {
            setError('Failed to parse the request body. Please check your input.');
            return {};
        }
    };

    // Generate Payload helper
    const generateCSRFPayload = (postBody: any) => {
        if (!postBody) return;

        const requestParts = request.split('\n\n');
        if (requestParts.length < 2) {
            // Might be just headers if user is typing
            return;
        }

        const headers = requestParts[0].split('\n');
        const methodParts = headers[0]?.split(' ');

        if (!methodParts || methodParts.length < 2 || methodParts[0].trim().toUpperCase() !== 'POST') {
            setError('Invalid HTTP request format. Only POST method is supported.');
            return;
        }

        const hostHeader = headers.find((header) => header.toLowerCase().startsWith('host:'));
        if (!hostHeader) {
            setError('Host header is missing in the request.');
            return;
        }

        const url = hostHeader.split(':')[1]?.trim() || hostHeader.split(' ')[1]?.trim(); // Handle "Host: example.com"
        // Note: HackTools implementation was simpler: hostHeader.split(" ")[1]
        // But headers often come as "Host: example.com"
        const cleanHost = hostHeader.replace(/host:\s*/i, '').trim();
        const actionUrl = `http://${cleanHost}${methodParts[1]}`;

        const inputs = Object.entries(postBody)
            .map(
                ([key, value]) =>
                    `      <input type="hidden" name="${key}" value="${(value as string) || ''
                    }"/>\n`
            )
            .join('');

        const method = methodParts[0].toUpperCase();
        const autoSubmitScript = autoSubmit
            ? `    <script>document.forms[0].submit();</script>`
            : '';

        const form = `<html>
  <body>
    <form method="${method}" action="${actionUrl}">
${inputs}      <input type="submit" value="Submit">
    </form>
${autoSubmitScript}
  </body>
</html>`;

        setCsrfPayload(form);
    };

    // Handling changes
    const handleRequestChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        const newRequest = e.target.value;
        setRequest(newRequest);
        setError('');

        if (!newRequest) {
            setCsrfPayload('');
            return;
        }

        // Logic from HackTools to parse immediately on change
        const contentTypeHeader = newRequest
            .split('\n')
            .find((line) => line.toLowerCase().startsWith('content-type:'));

        const contentType = contentTypeHeader
            ? contentTypeHeader.split(':')[1].trim()
            : '';

        const requestParts = newRequest.split('\n\n');
        if (requestParts.length >= 2) {
            const body = requestParts[1];
            const postBody = parsePostBody(contentType, body);
            setParsedPostBody(postBody);
            generateCSRFPayload(postBody);
        }
    };

    // Re-generate when autoSubmit changes
    useEffect(() => {
        if (request && Object.keys(parsedPostBody).length > 0) {
            generateCSRFPayload(parsedPostBody);
        }
    }, [autoSubmit, request]);

    const copyToClipboard = () => {
        navigator.clipboard.writeText(csrfPayload);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white flex items-center gap-2">
                    <FileCode className="text-htb-green" size={24} />
                    CSRF Generator
                </h2>
                <p className="text-gray-400">
                    Generate Cross-Site Request Forgery (CSRF) Proof of Concept HTML forms from raw HTTP requests.
                </p>
            </div>

            {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 flex items-center gap-3 text-red-500">
                    <AlertCircle size={20} />
                    <span className="font-mono text-sm">{error}</span>
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Input */}
                <Card className="!p-6 flex flex-col h-full space-y-4">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Raw HTTP Request</h3>
                    <TextArea
                        placeholder={`POST /change-email HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com`}
                        value={request}
                        onChange={handleRequestChange}
                        className="flex-1 font-mono text-xs min-h-[300px]"
                    />
                    <p className="text-xs text-gray-500">
                        Paste the full raw HTTP request, including headers and body. Ensure there is a blank line between headers and body.
                    </p>
                </Card>

                {/* Output */}
                <Card className="!p-6 flex flex-col h-full space-y-4">
                    <div className="flex items-center justify-between">
                        <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Generated HTML PoC</h3>
                        <div className="flex items-center gap-2">
                            <label className="flex items-center gap-2 text-xs text-gray-300 font-bold cursor-pointer hover:text-white transition-colors">
                                <input
                                    type="checkbox"
                                    checked={autoSubmit}
                                    onChange={(e) => setAutoSubmit(e.target.checked)}
                                    className="accent-htb-green w-4 h-4 rounded cursor-pointer"
                                />
                                Auto-Submit
                            </label>
                            <Button
                                size="sm"
                                variant={csrfPayload ? 'primary' : 'secondary'}
                                disabled={!csrfPayload}
                                onClick={copyToClipboard}
                                icon={<Copy size={14} />}
                            >
                                Copy
                            </Button>
                        </div>
                    </div>

                    <TextArea
                        readOnly
                        value={csrfPayload}
                        className="flex-1 font-mono text-xs text-blue-300 min-h-[300px]"
                        placeholder="// Generated HTML will appear here..."
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
