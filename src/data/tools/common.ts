
import type { ToolArg } from '../../types';

// --- Helpers ---

export const getUrlPrefix = (isHttps: boolean) => isHttps ? 'https://' : 'http://';

export const formatTargetWithPort = (target: string) => {
    return target || '$TARGET';
};

// Helper to create arguments easily
export const createArg = {
    toggle: (key: string, label: string, defaultValue: boolean = false): ToolArg => ({
        key, type: 'toggle', label, defaultValue
    }),
    input: (key: string, label: string, defaultValue: string = '', placeholder: string = ''): ToolArg => ({
        key, type: 'text', label, defaultValue, placeholder
    })
};

// --- Common Args Definitions ---
export const ARG_HTTPS = createArg.toggle('useHttps', 'Use HTTPS', false);
export const ARG_OUTPUT = createArg.toggle('saveOutput', 'Save Output', false);
export const ARG_CREDS = createArg.toggle('useCreds', 'Credentials', false);

export const ARG_WL_DIR = createArg.input('wordlistDir', 'Dir Wordlist', '/usr/share/wordlists/dirb/common.txt');
export const ARG_WL_SUB = createArg.input('wordlistSub', 'Subdomain Wordlist', '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt');
export const ARG_WL_VHOST = createArg.input('wordlistVhost', 'VHost Wordlist', '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt');
export const ARG_SHARE = createArg.toggle('accessShare', 'Access Share', false);
export const ARG_SHARE_NAME = createArg.input('shareName', 'Share Name', '', 'ShareName');
