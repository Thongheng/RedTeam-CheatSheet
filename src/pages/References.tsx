import { useState } from 'react';
import { ExternalLink } from 'lucide-react';
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

    const categories = Object.keys(referencesByCategory);
    const [activeCategory, setActiveCategory] = useState(categories[0] || '');

    const currentRefs = referencesByCategory[activeCategory] || [];

    return (
        <div className="h-[calc(100vh-65px)] overflow-y-auto">
            <div className="max-w-7xl mx-auto px-6 py-8">
                {/* Category Tabs */}
                <div className="flex items-center gap-2 mb-8 overflow-x-auto pb-2">
                    {categories.map(cat => (
                        <button
                            key={cat}
                            onClick={() => setActiveCategory(cat)}
                            className={`px-4 py-2 rounded-lg text-xs font-bold whitespace-nowrap transition-all cursor-pointer flex-shrink-0 ${activeCategory === cat
                                ? 'bg-[#a2ff00] text-[#05080d]'
                                : 'bg-[#1a1f28] text-gray-400 hover:bg-[#252a35] hover:text-white border border-white/5'
                                }`}
                        >
                            {cat}
                        </button>
                    ))}
                </div>

                {/* References Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                    {currentRefs.map((ref) => (
                        <a
                            key={ref.id}
                            href={ref.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="group block p-5 rounded-xl bg-[#0d1117] border border-white/10 hover:border-[#a2ff00]/40 hover:bg-[#0d1117]/80 transition-all duration-200 hover:shadow-lg hover:shadow-[#a2ff00]/5"
                        >
                            <div className="flex items-start justify-between gap-3 mb-3">
                                <h3 className="text-base font-bold text-white group-hover:text-[#a2ff00] transition-colors leading-tight">
                                    {ref.name}
                                </h3>
                                <ExternalLink
                                    size={16}
                                    className="text-gray-600 group-hover:text-[#a2ff00] flex-shrink-0 mt-0.5 transition-colors"
                                />
                            </div>
                            <p className="text-sm text-gray-400 leading-relaxed line-clamp-2 mb-4">
                                {ref.desc}
                            </p>
                            <div className="pt-3 border-t border-white/5">
                                <div className="text-xs font-mono text-gray-600 truncate group-hover:text-gray-500 transition-colors">
                                    {new URL(ref.url).hostname}
                                </div>
                            </div>
                        </a>
                    ))}
                </div>
            </div>
        </div>
    );
}
