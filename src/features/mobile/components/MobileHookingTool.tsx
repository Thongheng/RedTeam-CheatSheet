import React, { useState } from 'react';
import { Card, Button, Input, TabNav, PayloadBlock, Toast } from '../../../components/ui';
import { ToolHeader } from '../../../components/ui/ToolHeader';
import { Smartphone, Copy, Info, Code, Terminal } from 'lucide-react';

export default function MobileHookingTool() {
    const [activeTab, setActiveTab] = useState('frida');
    const [config, setConfig] = useState({
        package: 'com.example.app',
        class: 'com.example.app.MainActivity',
        method: 'isSecure',
        value: 'true',
    });
    const [showToast, setShowToast] = useState(false);

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const tabs = [
        { id: 'frida', label: 'Frida Scripts' },
        { id: 'objection', label: 'Objection' },
    ];

    const FRIDA_SCRIPTS = [
        {
            name: 'Java Method Hook',
            desc: 'Hook a specific Java method and print arguments',
            code: `Java.perform(function() {
    var TargetClass = Java.use("${config.class}");
    TargetClass.${config.method}.implementation = function(arg1) {
        console.log("[*] ${config.method} called with: " + arg1);
        return this.${config.method}(arg1);
    };
});`
        },
        {
            name: 'Method Replacement',
            desc: 'Replace method return value',
            code: `Java.perform(function() {
    var TargetClass = Java.use("${config.class}");
    TargetClass.${config.method}.implementation = function() {
        console.log("[*] ${config.method} called - returning ${config.value}");
        return ${config.value};
    };
});`
        },
        {
            name: 'SSL Pinning Bypass (Pro)',
            desc: 'Universal SSL Pinning Bypass',
            code: `Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    ApiClient.checkServerTrusted.implementation = function(chain, authType) {
        console.log("[+] Bypassing SSL Pinning");
        return;
    }
});`
        },
        {
            name: 'Root Detection Bypass',
            desc: 'Generic Root Detection Bypass',
            code: `Java.perform(function() {
    var RootPackages = ["com.noshufou.android.su", "com.thirdparty.superuser", "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.zachspong.temprootremoveramdisk", "com.ramdroid.appquarantine"];
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var name = this.getAbsolutePath();
        for(var i = 0; i < RootPackages.length; i++) {
            if(name.indexOf(RootPackages[i]) > -1) {
                console.log("[+] Root detection bypass for: " + name);
                return false;
            }
        }
        return this.exists();
    }
});`
        }
    ];

    const OBJECTION_COMMANDS = [
        { name: 'Explore', cmd: `objection -g ${config.package} explore` },
        { name: 'Disable SSL Pinning', cmd: 'android sslpinning disable' },
        { name: 'Disable Root Detection', cmd: 'android root disable' },
        { name: 'Dump Keystore', cmd: 'android keystore list' },
        { name: 'List Activities', cmd: 'android hooking list activities' },
        { name: 'Hook Method', cmd: `android hooking watch class_method ${config.class}.${config.method} --dump-args --dump-return` },
    ];

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setConfig((prev) => ({ ...prev, [name]: value }));
    };

    return (
        <div className="space-y-6">
            <ToolHeader
                title="Mobile App Hooking"
                description="Frida scripts and commands for iOS and Android application security testing"
            />

            {/* Configuration */}
            <Card className="!p-6 space-y-4 border-l-4 border-l-htb-green">
                <h3 className="text-sm font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                    <Info size={16} /> Target Configuration
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-gray-400">Package Name</label>
                        <Input
                            name="package"
                            value={config.package}
                            onChange={handleChange}
                            placeholder="com.example.app"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-gray-400">Target Class</label>
                        <Input
                            name="class"
                            value={config.class}
                            onChange={handleChange}
                            placeholder="com.example.app.MainActivity"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-gray-400">Method Name</label>
                        <Input
                            name="method"
                            value={config.method}
                            onChange={handleChange}
                            placeholder="isSecure"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-gray-400">Return Value Override</label>
                        <Input
                            name="value"
                            value={config.value}
                            onChange={handleChange}
                            placeholder="true / 1 / 'string'"
                        />
                    </div>
                </div>
            </Card>

            <TabNav tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab} />

            {/* Frida Tab */}
            {activeTab === 'frida' && (
                <div className="space-y-4">
                    <PayloadBlock
                        content={FRIDA_SCRIPTS.map(script => `/* ${script.name} - ${script.desc} */\n${script.code}`).join('\n\n')}
                        language="javascript"
                    />
                </div>
            )}

            {/* Objection Tab */}
            {activeTab === 'objection' && (
                <div className="space-y-4">
                    <PayloadBlock
                        content={OBJECTION_COMMANDS.map(cmd => `# ${cmd.name}\n${cmd.cmd}`).join('\n\n')}
                    />
                </div>
            )}

            {/* Toast Notification */}
            <Toast show={showToast} message="Copied to clipboard!" />
        </div>
    );
}
