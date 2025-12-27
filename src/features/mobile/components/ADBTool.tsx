import React, { useState } from 'react';
import { Card, Button, Input, Select, PayloadBlock, Toast } from '../../../components/ui';
import { Smartphone, Copy, Wifi, Usb } from 'lucide-react';

export default function ADBTool() {
    const [showToast, setShowToast] = useState(false);
    const [mode, setMode] = useState<'usb' | 'remote'>('usb');
    const [deviceId, setDeviceId] = useState('');
    const [port, setPort] = useState('5555');

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const formatCommand = (cmd: string) => {
        const deviceFlag = deviceId ?
            (mode === 'remote' ? `-s ${deviceId}:${port}` : `-s ${deviceId}`)
            : '';
        return cmd.replace('${device}', deviceFlag);
    };

    const ADB_COMMANDS = [
        { name: 'List Devices', desc: 'Show all connected ADB devices', cmd: 'adb devices' },
        { name: 'Connect Remote', desc: 'Connect to device over WiFi', cmd: 'adb connect ${device}' },
        { name: 'Disconnect', desc: 'Disconnect from remote device', cmd: 'adb disconnect' },
        { name: 'Shell Access', desc: 'Open interactive shell on device', cmd: 'adb ${device} shell' },
        { name: 'Root Shell', desc: 'Restart ADB with root privileges', cmd: 'adb ${device} root' },
        { name: 'Install APK', desc: 'Install application package', cmd: 'adb ${device} install app.apk' },
        { name: 'Uninstall App', desc: 'Remove application by package name', cmd: 'adb ${device} uninstall com.example.app' },
        { name: 'List Packages', desc: 'Show all installed packages', cmd: 'adb ${device} shell pm list packages' },
        { name: 'List 3rd Party Apps', desc: 'Show user-installed packages only', cmd: 'adb ${device} shell pm list packages -3' },
        { name: 'App Info', desc: 'Get package information', cmd: 'adb ${device} shell dumpsys package com.example.app' },
        { name: 'App Path', desc: 'Find APK location on device', cmd: 'adb ${device} shell pm path com.example.app' },
        { name: 'Pull APK', desc: 'Download APK from device', cmd: 'adb ${device} pull /data/app/com.example.app/base.apk' },
        { name: 'Push File', desc: 'Upload file to device', cmd: 'adb ${device} push local.txt /sdcard/remote.txt' },
        { name: 'Pull File', desc: 'Download file from device', cmd: 'adb ${device} pull /sdcard/file.txt' },
        { name: 'Screen Capture', desc: 'Take screenshot', cmd: 'adb ${device} shell screencap -p /sdcard/screen.png' },
        { name: 'Screen Record', desc: 'Record screen video', cmd: 'adb ${device} shell screenrecord /sdcard/demo.mp4' },
        { name: 'System Properties', desc: 'View device properties', cmd: 'adb ${device} shell getprop' },
        { name: 'Android Version', desc: 'Get OS version', cmd: 'adb ${device} shell getprop ro.build.version.release' },
        { name: 'Device Model', desc: 'Get device model', cmd: 'adb ${device} shell getprop ro.product.model' },
        { name: 'App Data Dir', desc: 'Access app private data (requires root)', cmd: 'adb ${device} shell run-as com.example.app' },
        { name: 'List Running Apps', desc: 'Show active processes', cmd: 'adb ${device} shell ps' },
        { name: 'Logcat', desc: 'View system logs', cmd: 'adb ${device} logcat' },
        { name: 'Logcat Filter', desc: 'Filter logs by tag', cmd: 'adb ${device} logcat -s TAG_NAME' },
        { name: 'Clear Logcat', desc: 'Clear log buffer', cmd: 'adb ${device} logcat -c' },
        { name: 'Backup App', desc: 'Backup app data (no APK)', cmd: 'adb ${device} backup -f app.ab com.example.app' },
        { name: 'Backup with APK', desc: 'Backup app with APK', cmd: 'adb ${device} backup -f app.ab -apk com.example.app' },
        { name: 'Restore Backup', desc: 'Restore app from backup', cmd: 'adb ${device} restore app.ab' },
        { name: 'Reboot Device', desc: 'Restart the device', cmd: 'adb ${device} reboot' },
        { name: 'Reboot to Recovery', desc: 'Boot into recovery mode', cmd: 'adb ${device} reboot recovery' },
        { name: 'Reboot to Bootloader', desc: 'Boot into fastboot mode', cmd: 'adb ${device} reboot bootloader' },
        { name: 'Forward Port', desc: 'Forward TCP port from device to local', cmd: 'adb ${device} forward tcp:8080 tcp:8080' },
        { name: 'Reverse Port', desc: 'Forward local port to device', cmd: 'adb ${device} reverse tcp:8080 tcp:8080' },
        { name: 'Enable WiFi ADB', desc: 'Enable ADB over TCP/IP', cmd: 'adb ${device} tcpip 5555' },
        { name: 'Disable WiFi ADB', desc: 'Disable WiFi debugging', cmd: 'adb ${device} usb' },
    ];

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white">
                    ADB Commands
                </h2>
                <p className="text-gray-400">
                    Android Debug Bridge commands for device enumeration and app manipulation
                </p>
            </div>

            {/* Connection Settings */}
            <Card className="!p-6">
                <h3 className="text-lg font-bold text-white mb-4">Connection Settings</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <label className="block text-xs font-bold text-gray-400 mb-2">Connection Mode</label>
                        <Select
                            value={mode}
                            onChange={(value) => setMode(value as 'usb' | 'remote')}
                            className="w-full"
                            options={[
                                { label: 'USB', value: 'usb' },
                                { label: 'Remote (WiFi)', value: 'remote' },
                            ]}
                        />
                    </div>
                    <div>
                        <label className="block text-xs font-bold text-gray-400 mb-2">
                            {mode === 'usb' ? 'Device ID (adb devices)' : 'IP Address'}
                        </label>
                        <Input
                            placeholder={mode === 'usb' ? 'emulator-5554' : '192.168.1.100'}
                            value={deviceId}
                            onChange={(e) => setDeviceId(e.target.value)}
                            icon={mode === 'usb' ? <Usb size={16} /> : <Wifi size={16} />}
                        />
                    </div>
                    {mode === 'remote' && (
                        <div>
                            <label className="block text-xs font-bold text-gray-400 mb-2">Port</label>
                            <Input
                                placeholder="5555"
                                value={port}
                                onChange={(e) => setPort(e.target.value)}
                            />
                        </div>
                    )}
                </div>
                {deviceId && (
                    <div className="mt-4 bg-yellow-500/10 border border-yellow-500/20 rounded p-3">
                        <p className="text-xs text-yellow-300">
                            {mode === 'remote'
                                ? `Commands will target: ${deviceId}:${port}`
                                : `Commands will target: ${deviceId}`}
                        </p>
                    </div>
                )}
            </Card>

            {/* Command List */}
            <div className="mb-6">
                <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3 border-b border-white/10 pb-2">
                    ADB Commands
                </h3>
                <PayloadBlock
                    content={ADB_COMMANDS.map(item => `# ${item.name} - ${item.desc}\n${formatCommand(item.cmd)}`).join('\n\n')}
                />
            </div>

            {/* Toast */}
                    <Toast show={showToast} message="Copied to clipboard!" />
        </div>
    );
}
