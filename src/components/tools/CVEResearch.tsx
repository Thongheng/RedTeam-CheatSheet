import { useState } from 'react';
import { Input, Button, Card } from '../ui';
import { ToolHeader } from '../ui/ToolHeader';
import { Search } from 'lucide-react';

interface CVEResult {
    id: string;
    title: string;
    description: string;
    cvss: {
        score: number;
        vector: string;
    };
    published: string;
    modified: string;
    href: string;
    type: string;
    bulletinFamily: string;
}

export default function CVEResearch() {
    const [search, setSearch] = useState('');
    const [results, setResults] = useState<CVEResult[]>([]);
    const [loading, setLoading] = useState(false);
    const [searched, setSearched] = useState(false);

    const handleSearch = async () => {
        if (!search.trim()) return;

        setLoading(true);
        setSearched(true);

        try {
            // Note: Vulners API requires CORS proxy or backend proxy
            // Using mock data for now - replace with actual API call in production

            // Real API call (commented out - requires CORS proxy):
            // const response = await fetch('https://corsproxy.io/?https://vulners.com/api/v3/search/lucene', {
            //     method: 'POST',
            //     headers: { 'Content-Type': 'application/json' },
            //     body: JSON.stringify({
            //         query: search,
            //         skip: 0,
            //         size: 20,
            //         fields: ['id', 'title', 'description', 'type', 'bulletinFamily', 'cvss', 'published', 'modified', 'href']
            //     })
            // });
            // const data = await response.json();
            // setResults(data.data.search || []);

            // Mock data for demonstration
            await new Promise(resolve => setTimeout(resolve, 500));
            setResults(getMockResults(search));
        } catch (error) {
            console.error('CVE search error:', error);
            setResults([]);
        } finally {
            setLoading(false);
        }
    };

    const getCVSSColor = (score: number) => {
        if (score >= 9.0) return 'text-red-500';
        if (score >= 7.0) return 'text-orange-500';
        if (score >= 4.0) return 'text-yellow-500';
        return 'text-htb-green';
    };

    const getCVSSBadge = (score: number) => {
        if (score >= 9.0) return 'bg-red-500/20 text-red-400 border-red-500/30';
        if (score >= 7.0) return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
        if (score >= 4.0) return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
        return 'bg-htb-green/20 text-htb-green border-htb-green/30';
    };

    return (
        <div className="space-y-6">
            <ToolHeader
                title="CVE Research"
                description="Search for Common Vulnerabilities and Exposures (CVEs) with CVSS scoring"
                badge="RT"
                icon={<Search size={24} />}
            />

            {/* Search Bar */}
            <Card>
                <div className="flex gap-3">
                    <Input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                        placeholder="Search CVE ID, product, or vulnerability..."
                        className="flex-1"
                    />
                    <Button
                        onClick={handleSearch}
                        disabled={loading || !search.trim()}
                    >
                        {loading ? 'Searching...' : 'Search'}
                    </Button>
                </div>
                <p className="text-sm text-gray-500 mt-2">
                    💡 Example: CVE-2021-44228, Apache Log4j, SQL Injection
                </p>
            </Card>

            {/* Results */}
            {searched && (
                <div className="space-y-4">
                    <div className="flex items-center justify-between">
                        <h3 className="text-lg font-semibold text-white">
                            {results.length} Results Found
                        </h3>
                    </div>

                    {results.length === 0 ? (
                        <Card>
                            <div className="text-center py-8 text-gray-400">
                                <p className="text-lg">No vulnerabilities found</p>
                                <p className="text-sm mt-2">Try a different search term</p>
                            </div>
                        </Card>
                    ) : (
                        results.map((result) => (
                            <Card key={result.id} className="hover:border-htb-green/30 transition-colors">
                                <div className="space-y-3">
                                    {/* Header */}
                                    <div className="flex items-start justify-between gap-4">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-3 mb-2">
                                                <h4 className="text-lg font-semibold text-htb-green">
                                                    {result.id}
                                                </h4>
                                                <span className={`px-2 py-1 rounded text-xs font-mono border ${getCVSSBadge(result.cvss.score)}`}>
                                                    CVSS {result.cvss.score}
                                                </span>
                                            </div>
                                            <p className="text-white font-medium">
                                                {result.title}
                                            </p>
                                        </div>
                                    </div>

                                    {/* Description */}
                                    <p className="text-gray-300 text-sm leading-relaxed">
                                        {result.description.length > 300
                                            ? result.description.substring(0, 300) + '...'
                                            : result.description}
                                    </p>

                                    {/* Metadata */}
                                    <div className="flex items-center gap-6 text-sm text-gray-400 pt-2 border-t border-white/5">
                                        <div>
                                            <span className="text-gray-500">Type:</span>{' '}
                                            <span className="text-htb-green font-mono">{result.type}</span>
                                        </div>
                                        <div>
                                            <span className="text-gray-500">Family:</span>{' '}
                                            <span className="text-white">{result.bulletinFamily}</span>
                                        </div>
                                        <div>
                                            <span className="text-gray-500">Published:</span>{' '}
                                            <span className="text-white">
                                                {new Date(result.published).toLocaleDateString()}
                                            </span>
                                        </div>
                                    </div>

                                    {/* CVSS Vector */}
                                    <div className="bg-black/30 rounded p-2">
                                        <span className="text-xs text-gray-500">CVSS Vector: </span>
                                        <span className="text-xs font-mono text-gray-300">{result.cvss.vector}</span>
                                    </div>

                                    {/* Link */}
                                    {result.href && (
                                        <a
                                            href={result.href}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="inline-flex items-center gap-2 text-htb-green hover:text-htb-green/80 transition-colors text-sm"
                                        >
                                            View Details →
                                        </a>
                                    )}
                                </div>
                            </Card>
                        ))
                    )}
                </div>
            )}

            {/* API Note */}
            <Card className="bg-yellow-500/10 border-yellow-500/30">
                <div className="flex gap-3">
                    <span className="text-yellow-500">⚠️</span>
                    <div className="text-sm text-yellow-200/80">
                        <p className="font-semibold mb-1">Demo Mode</p>
                        <p>Currently showing mock data. To use live CVE data, configure Vulners API access or use a backend proxy to avoid CORS issues.</p>
                    </div>
                </div>
            </Card>
        </div>
    );
}

// Mock data generator
function getMockResults(query: string): CVEResult[] {
    const mockData: CVEResult[] = [
        {
            id: 'CVE-2021-44228',
            title: 'Apache Log4j2 Remote Code Execution Vulnerability',
            description: 'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.',
            cvss: { score: 10.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
            published: '2021-12-10T10:00:00',
            modified: '2023-11-07T03:00:00',
            href: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
            type: 'cve',
            bulletinFamily: 'NVD'
        },
        {
            id: 'CVE-2023-23397',
            title: 'Microsoft Outlook Elevation of Privilege Vulnerability',
            description: 'Microsoft Outlook Elevation of Privilege Vulnerability allows an attacker to steal Net-NTLMv2 hash through a specially crafted email message.',
            cvss: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
            published: '2023-03-14T00:00:00',
            modified: '2023-11-30T00:00:00',
            href: 'https://nvd.nist.gov/vuln/detail/CVE-2023-23397',
            type: 'cve',
            bulletinFamily: 'Microsoft'
        },
        {
            id: 'CVE-2017-0144',
            title: 'Microsoft Windows SMB Remote Code Execution Vulnerability (EternalBlue)',
            description: 'The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability."',
            cvss: { score: 8.1, vector: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' },
            published: '2017-03-17T00:00:00',
            modified: '2020-09-28T00:00:00',
            href: 'https://nvd.nist.gov/vuln/detail/CVE-2017-0144',
            type: 'cve',
            bulletinFamily: 'Microsoft'
        },
        {
            id: 'CVE-2014-6271',
            title: 'GNU Bash Shellshock Vulnerability',
            description: 'GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment.',
            cvss: { score: 9.8, vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
            published: '2014-09-24T00:00:00',
            modified: '2021-02-01:00:00',
            href: 'https://nvd.nist.gov/vuln/detail/CVE-2014-6271',
            type: 'cve',
            bulletinFamily: 'NVD'
        }
    ];

    // Simple filter based on query
    return mockData.filter(item =>
        item.id.toLowerCase().includes(query.toLowerCase()) ||
        item.title.toLowerCase().includes(query.toLowerCase()) ||
        item.description.toLowerCase().includes(query.toLowerCase())
    );
}
