import { useState } from 'react';
import { BookOpen, Copy, Check } from 'lucide-react';
import { GUIDES, type GuideItem } from '../data/guides';
import { useClipboard } from '../hooks/useClipboard';

export default function GuidesPage() {
    const [selectedGuide, setSelectedGuide] = useState<GuideItem | null>(GUIDES[0]);
    const { copied, copy } = useClipboard();

    // Group guides by subcategory
    const guidesByCategory = GUIDES.reduce((acc, guide) => {
        if (!acc[guide.subcategory]) {
            acc[guide.subcategory] = [];
        }
        acc[guide.subcategory].push(guide);
        return acc;
    }, {} as Record<string, GuideItem[]>);

    return (
        <div className="min-h-screen animate-fade-in">
            <div className="max-w-7xl mx-auto px-6 py-8">
                {/* Header */}
                <div className="mb-8">
                    <div className="flex items-center gap-3 mb-3">
                        <BookOpen size={32} className="text-[#a2ff00]" />
                        <h1 className="text-3xl font-black tracking-tight">Quick Reference Guides</h1>
                    </div>
                    <p className="text-gray-400 text-sm leading-relaxed">
                        Step-by-step guides for common penetration testing tasks and workflows
                    </p>
                </div>

                <div className="grid grid-cols-12 gap-6">
                    {/* Sidebar */}
                    <div className="col-span-3">
                        <div className="htb-card sticky top-24">
                            {Object.entries(guidesByCategory).map(([subcategory, guides]) => (
                                <div key={subcategory} className="mb-4 last:mb-0">
                                    <div className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2 px-3">
                                        {subcategory}
                                    </div>
                                    <div className="space-y-1">
                                        {guides.map((guide) => (
                                            <button
                                                key={guide.id}
                                                onClick={() => setSelectedGuide(guide)}
                                                className={`w-full text-left px-3 py-2 rounded text-sm font-medium transition-colors ${selectedGuide?.id === guide.id
                                                    ? 'bg-[#a2ff00]/10 text-[#a2ff00]'
                                                    : 'text-gray-400 hover:bg-white/5 hover:text-white'
                                                    }`}
                                            >
                                                {guide.name}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Guide Content */}
                    <div className="col-span-9">
                        {selectedGuide ? (
                            <div className="htb-card">
                                <div className="mb-6">
                                    <div className="flex items-start justify-between mb-3">
                                        <div>
                                            <h2 className="text-2xl font-bold text-white">{selectedGuide.name}</h2>
                                            <span className="inline-block mt-2 px-2 py-1 rounded text-xs font-bold bg-[#a2ff00]/10 text-[#a2ff00]">
                                                {selectedGuide.subcategory}
                                            </span>
                                        </div>
                                        <button
                                            onClick={() => copy(selectedGuide.content)}
                                            className="flex items-center gap-2 px-4 py-2 rounded bg-[#a2ff00] hover:bg-[#8dd900] text-[#05080d] text-sm font-bold transition-colors"
                                        >
                                            {copied ? <Check size={16} /> : <Copy size={16} />}
                                            {copied ? 'Copied!' : 'Copy All'}
                                        </button>
                                    </div>
                                    <p className="text-gray-400 text-sm leading-relaxed">
                                        {selectedGuide.desc}
                                    </p>
                                </div>

                                <div className="htb-terminal-content">
                                    <pre className="font-mono text-sm text-gray-300 whitespace-pre-wrap">
                                        {selectedGuide.content}
                                    </pre>
                                </div>
                            </div>
                        ) : (
                            <div className="htb-card text-center py-12">
                                <BookOpen size={48} className="mx-auto mb-3 text-gray-600" />
                                <p className="text-gray-400">Select a guide from the sidebar</p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
