import type { Tool } from '../../types';
import {
    ARG_OUTPUT, ARG_WL_SUB, ARG_WL_VHOST, ARG_WL_DIR, ARG_HTTPS,
    getUrlPrefix, formatTargetWithPort
} from './common';

export const WEB_TOOLS: Tool[] = [
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
    {
        id: 'httpx',
        name: 'Httpx',
        category: 'WEB',
        subcategory: 'Fingerprinting',
        desc: 'HTTP toolkit for single target.',
        authMode: 'none',
        args: [ARG_OUTPUT],
        generate: (v, args) => {
            let cmd = `httpx -list -status-code -title -no-fallback ${v.filepath || '$FILEPATH'}`;
            if (args.saveOutput) cmd += ` -o httpx.txt`;
            return cmd;
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
