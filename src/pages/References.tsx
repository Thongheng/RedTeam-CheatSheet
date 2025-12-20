import { ExternalLink, BookmarkCheck } from 'lucide-react';
import { REFERENCES, type ReferenceItem } from '../data/references';

export default function ReferencesPage() {
    // Group references by subcategory
    const referencesByCategory = REFERENCES.reduce((acc, ref) => {
        if (!acc[ref.subcategory]) {
            acc[ref.subcategory] = [];
        }
        acc[ref.subcategory].push(ref);
        return acc;
    }, {} as Record<string, ReferenceItem[]>);

    return (
        <div className="min-h-screen animate-fade-in">
            <div className="max-w-6xl mx-auto px-6 py-8">
                {/* Header */}
                <div className="mb-8">
                    <div className="flex items-center gap-3 mb-3">
                        <BookmarkCheck size={32} className="text-[#a2ff00]" />
                        <h1 className="text-3xl font-black tracking-tight">External References</h1>
                    </div>
                    <p className="text-gray-400 text-sm leading-relaxed">
                        Curated collection of essential external resources for penetration testing and security research
                    </p>
                </div>

                {/* References Grid */}
                <div className="space-y-8">
                    {Object.entries(referencesByCategory).map(([subcategory, refs]) => (
                        <div key={subcategory}>
                            <div className="flex items-center gap-2 mb-4">
                                <h2 className="text-xl font-bold text-[#a2ff00]">{subcategory}</h2>
                                <div className="flex-1 h-px bg-white/10"></div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {refs.map((ref) => (
                                    <a
                                        key={ref.id}
                                        href={ref.url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="htb-card group hover:border-[#a2ff00]/30 transition-all"
                                    >
                                        <div className="flex items-start justify-between mb-3">
                                            <h3 className="text-lg font-bold text-white group-hover:text-[#a2ff00] transition-colors">
                                                {ref.name}
                                            </h3>
                                            <ExternalLink
                                                size={18}
                                                className="text-gray-500 group-hover:text-[#a2ff00] flex-shrink-0 mt-1 transition-colors"
                                            />
                                        </div>
                                        <p className="text-sm text-gray-400 leading-relaxed">
                                            {ref.desc}
                                        </p>
                                        <div className="mt-3 text-xs font-mono text-gray-600 truncate">
                                            {ref.url}
                                        </div>
                                    </a>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
