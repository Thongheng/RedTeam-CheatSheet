import { ReferenceItem } from '../types';

export const REFERENCES: ReferenceItem[] = [
    {
        id: 'ired_team',
        name: 'Red Teaming Experiments',
        category: 'REF',
        subcategory: 'Red Teaming',
        desc: 'A comprehensive collection of Red Teaming notes, tactics, and experiments by spotheplanet.',
        url: 'https://www.ired.team/'
    },
    {
        id: 'hacktricks',
        name: 'HackTricks',
        category: 'REF',
        subcategory: 'General',
        desc: 'A massive wiki of hacking tricks and techniques maintained by Carlos Polop.',
        url: 'https://book.hacktricks.xyz/'
    },
    {
        id: 'payloads_all_things',
        name: 'Payloads All The Things',
        category: 'REF',
        subcategory: 'Cheat Sheets',
        desc: 'A list of useful payloads and bypasses for Web Application Security.',
        url: 'https://github.com/swisskyrepo/PayloadsAllTheThings'
    },
    {
        id: 'gtfobins',
        name: 'GTFOBins',
        category: 'REF',
        subcategory: 'Linux',
        desc: 'Curated list of Unix binaries that can be used to bypass local security restrictions.',
        url: 'https://gtfobins.github.io/'
    },
    {
        id: 'lolbas',
        name: 'LOLBAS',
        category: 'REF',
        subcategory: 'Windows',
        desc: 'Living Off The Land Binaries, Scripts and Libraries for Windows.',
        url: 'https://lolbas-project.github.io/'
    }
];