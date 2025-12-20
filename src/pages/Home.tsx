import { Terminal, Shield, Zap } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { TOOLS } from '../data/tools';
import { CATEGORIES, CATEGORY_ORDER } from '../data/categories';

export default function Home() {
    const navigate = useNavigate();

    return (
        <div className="max-w-7xl mx-auto px-6 py-20 animate-fade-in">
            {/* Hero */}
            <div className="text-center mb-20">
                <h1 className="text-5xl md:text-7xl font-black tracking-tight mb-8">
                    Offensive Security <span className="text-[#a2ff00]">Toolkit</span>
                </h1>
                <p className="text-gray-400 text-xl max-w-3xl mx-auto leading-relaxed mb-10">
                    The all-in-one command generator and cheatsheet for penetration testers, red teamers, and security researchers. Merged from <span className="text-[#a2ff00]">HackTools</span> + <span className="text-[#a2ff00]">RedToy</span>.
                </p>
                <div className="flex items-center justify-center gap-4">
                    <button
                        onClick={() => navigate('/tools')}
                        className="px-8 py-4 bg-[#a2ff00] text-[#05080d] font-black uppercase tracking-wider rounded-lg hover:scale-105 transition-transform shadow-lg shadow-[#a2ff00]/20 cursor-pointer"
                    >
                        Get Started
                    </button>
                    <button
                        onClick={() => window.open('https://github.com', '_blank')}
                        className="px-8 py-4 border border-[#a2ff00] text-[#a2ff00] font-bold rounded-lg hover:bg-[#a2ff00]/10 transition-colors cursor-pointer"
                    >
                        View on GitHub
                    </button>
                </div>
            </div>

            {/* Feature Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-16">
                <div className="p-10 rounded-2xl bg-[#0d1117] border border-[#a2ff00]/20 hover:border-[#a2ff00]/40 transition-colors">
                    <div className="w-12 h-12 rounded-lg bg-[#a2ff00]/10 border border-[#a2ff00]/20 flex items-center justify-center text-[#a2ff00] mb-6">
                        <Terminal size={24} />
                    </div>
                    <h3 className="text-xl font-bold mb-3">{TOOLS.length} Tools</h3>
                    <p className="text-gray-500 text-sm leading-relaxed">
                        Command generators for reverse shells, web exploitation, privilege escalation, and more.
                    </p>
                </div>

                <div className="p-10 rounded-2xl bg-[#0d1117] border border-purple-500/20 hover:border-purple-500/40 transition-colors">
                    <div className="w-12 h-12 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-500 mb-6">
                        <Shield size={24} />
                    </div>
                    <h3 className="text-xl font-bold mb-3">Multiple Sources</h3>
                    <p className="text-gray-500 text-sm leading-relaxed">
                        Merged from HackTools and RedToy, covering web, mobile, Windows, Linux, and AD attacks.
                    </p>
                </div>

                <div className="p-10 rounded-2xl bg-[#0d1117] border border-orange-500/20 hover:border-orange-500/40 transition-colors">
                    <div className="w-12 h-12 rounded-lg bg-orange-500/10 border border-orange-500/20 flex items-center justify-center text-orange-500 mb-6">
                        <Zap size={24} />
                    </div>
                    <h3 className="text-xl font-bold mb-3">Instant Copy</h3>
                    <p className="text-gray-500 text-sm leading-relaxed">
                        One-click copy to clipboard. Customize parameters and generate commands in real-time.
                    </p>
                </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
                {[
                    { label: 'Tools', value: TOOLS.length.toString() },
                    { label: 'Categories', value: CATEGORY_ORDER.length.toString() },
                    { label: 'HackTools', value: '85+' },
                    { label: 'RedToy', value: '11' },
                ].map(stat => (
                    <div key={stat.label} className="p-8 rounded-xl bg-[#0d1117] border border-white/5 text-center">
                        <div className="text-4xl font-black mb-2">{stat.value}</div>
                        <div className="text-xs text-gray-500 uppercase font-mono tracking-widest">{stat.label}</div>
                    </div>
                ))}
            </div>

            {/* Category Preview */}
            <div className="p-12 rounded-[2rem] border border-white/5 bg-[#0d1117]/30">
                <h2 className="text-2xl font-bold mb-8 text-center">Browse by Category</h2>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {CATEGORY_ORDER.map(catKey => {
                        const cat = CATEGORIES[catKey];
                        if (!cat) return null;
                        const Icon = cat.icon;
                        const colors: Record<string, string> = {
                            RECON: 'border-cyan-500/20 text-cyan-500',
                            WEB: 'border-[#a2ff00]/20 text-[#a2ff00]',
                            EXPLOIT: 'border-red-500/20 text-red-500',
                            WINDOWS: 'border-blue-500/20 text-blue-500',
                            LINUX: 'border-orange-500/20 text-orange-500',
                            MOBILE: 'border-pink-500/20 text-pink-500',
                            POST: 'border-purple-500/20 text-purple-500',
                            OTHER: 'border-yellow-500/20 text-yellow-500',
                        };
                        const color = colors[catKey] || 'border-white/10 text-gray-400';
                        const toolCount = TOOLS.filter(t => t.category === catKey).length;

                        return (
                            <button
                                key={catKey}
                                onClick={() => navigate(`/tools/${catKey}`)}
                                className={`p-6 rounded-xl bg-[#11161d] border ${color.split(' ')[0]} hover:bg-white/5 transition-all group cursor-pointer`}
                            >
                                <div className={`w-10 h-10 rounded-lg bg-current/10 flex items-center justify-center mb-4 ${color.split(' ')[1]}`}>
                                    {Icon && <Icon size={20} />}
                                </div>
                                <div className="font-bold text-white group-hover:text-[#a2ff00] transition-colors">{cat.label}</div>
                                <div className="text-xs text-gray-500 mt-1">{toolCount} tools</div>
                            </button>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}
