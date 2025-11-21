import { GuideItem } from '../types';

export const GUIDES: GuideItem[] = [
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