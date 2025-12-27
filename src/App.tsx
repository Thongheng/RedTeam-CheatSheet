import { useState, useEffect, useRef, Suspense } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { Search } from 'lucide-react';
import type { GlobalInputs } from './types';
import Home from './pages/Home';
import GuidesPage from './pages/Guides';
import ReferencesPage from './pages/References';
import ToolsLayout from './layouts/ToolsLayout';
import { ErrorBoundary } from './components/core/ErrorBoundary';
import { CommandPalette } from './components/core/CommandPalette';
import './index.css';

function App() {
    const navigate = useNavigate();
    const location = useLocation();

    // Global State: Inputs (Target, IP, etc.) persisted across app
    // This is OK to be global as it changes rarely compared to tool-specific typing
    const [globalInputs, setGlobalInputs] = useState<GlobalInputs>(() => {
        const saved = localStorage.getItem('redsploit_inputs');
        return saved ? JSON.parse(saved) : { target: '', domain: '', username: '', password: '', filepath: '' };
    });

    const [searchQuery, setSearchQuery] = useState('');

    useEffect(() => {
        localStorage.setItem('redsploit_inputs', JSON.stringify(globalInputs));
    }, [globalInputs]);

    const handleSearch = (value: string) => {
        setSearchQuery(value);
        if (value.trim() && !location.pathname.startsWith('/tools')) {
            navigate('/tools');
        }
    };

    const clearSearch = () => setSearchQuery('');

    return (
        <div className="min-h-screen bg-[#05080d] text-white selection:bg-[#a2ff00] selection:text-black antialiased">
            {/* Grid Background */}
            <div className="fixed inset-0 grid-bg pointer-events-none opacity-[0.08] z-0"></div>

            <div className="relative z-10 flex flex-col min-h-screen">
                {/* Navbar */}
                <nav className="sticky top-0 z-50 bg-[#05080d]/95 backdrop-blur-md border-b border-white/5">
                    <div className="w-full px-4 py-1.5 flex items-center justify-between">
                        {/* Logo - Left */}
                        <div className="flex items-center gap-1.5 cursor-pointer flex-shrink-0" onClick={() => { navigate('/'); clearSearch(); }}>
                            <div className="w-7 h-7 rounded-lg bg-[#a2ff00]/10 border border-[#a2ff00]/30 flex items-center justify-center">
                                <span className="text-[#a2ff00] font-black text-xs">&gt;</span>
                            </div>
                            <span className="text-white font-black text-base tracking-tight">HackToy</span>
                        </div>

                        {/* Category Navigation */}
                        <div className="flex items-center gap-0.5">
                            <button onClick={() => navigate('/tools/WEB/xss_payloads')} className={`px-2 py-1 rounded text-xs font-medium transition-colors ${location.pathname.includes('/tools/WEB') ? 'bg-[#a2ff00]/10 text-[#a2ff00]' : 'text-gray-400 hover:bg-white/5 hover:text-white'}`}>Web</button>
                            <button onClick={() => navigate('/tools/WINDOWS/powershell_commands')} className={`px-2 py-1 rounded text-xs font-medium transition-colors ${location.pathname.includes('/tools/WINDOWS') ? 'bg-[#a2ff00]/10 text-[#a2ff00]' : 'text-gray-400 hover:bg-white/5 hover:text-white'}`}>Win</button>
                            <button onClick={() => navigate('/tools/LINUX/linux_enumeration')} className={`px-2 py-1 rounded text-xs font-medium transition-colors ${location.pathname.includes('/tools/LINUX') ? 'bg-[#a2ff00]/10 text-[#a2ff00]' : 'text-gray-400 hover:bg-white/5 hover:text-white'}`}>Linux</button>
                            <button onClick={() => navigate('/tools/MOBILE/adb_commands')} className={`px-2 py-1 rounded text-xs font-medium transition-colors ${location.pathname.includes('/tools/MOBILE') ? 'bg-[#a2ff00]/10 text-[#a2ff00]' : 'text-gray-400 hover:bg-white/5 hover:text-white'}`}>Mobile</button>
                            <button onClick={() => navigate('/tools/UTILITIES/cve_research')} className={`px-2 py-1 rounded text-xs font-medium transition-colors ${location.pathname.includes('/tools/UTILITIES') ? 'bg-[#a2ff00]/10 text-[#a2ff00]' : 'text-gray-400 hover:bg-white/5 hover:text-white'}`}>Utils</button>
                            <div className="w-px h-4 bg-white/10 mx-1"></div>
                            <button
                                onClick={() => { navigate('/guides'); clearSearch(); }}
                                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${location.pathname === '/guides'
                                    ? 'bg-[#a2ff00]/10 text-[#a2ff00]'
                                    : 'text-gray-400 hover:bg-white/5 hover:text-white'
                                    }`}
                            >
                                Guides
                            </button>
                            <button
                                onClick={() => { navigate('/references'); clearSearch(); }}
                                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${location.pathname === '/references'
                                    ? 'bg-[#a2ff00]/10 text-[#a2ff00]'
                                    : 'text-gray-400 hover:bg-white/5 hover:text-white'
                                    }`}
                            >
                                Refs
                            </button>
                        </div>

                        {/* Search - Right */}
                        <div className="relative group flex-shrink-0">
                            <Search className="absolute left-2 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-[#a2ff00] transition-colors pointer-events-none" size={14} />
                            <input
                                type="text"
                                placeholder="Search..."
                                value={searchQuery}
                                onChange={(e) => handleSearch(e.target.value)}
                                className="w-32 bg-white/5 border border-white/10 rounded pl-7 pr-2 py-1 text-xs text-white placeholder:text-gray-500 focus:outline-none focus:border-[#a2ff00]/50 focus:bg-white/10 transition-all"
                            />
                            {searchQuery && (
                                <button
                                    onClick={clearSearch}
                                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white cursor-pointer"
                                >
                                    ×
                                </button>
                            )}
                        </div>
                    </div>
                </nav>

                {/* Main Content */}
                <main className="flex-1">
                    <ErrorBoundary>
                        <Suspense fallback={<div className="p-10 text-center text-gray-500">Loading components...</div>}>
                            <Routes>
                                <Route path="/" element={<Home />} />
                                <Route path="/guides" element={<GuidesPage />} />
                                <Route path="/references" element={<ReferencesPage />} />

                                {/* Tools Routes */}
                                <Route path="/tools" element={<ToolsLayout globalInputs={globalInputs} searchQuery={searchQuery} clearSearch={clearSearch} />} />
                                <Route path="/tools/:category" element={<ToolsLayout globalInputs={globalInputs} searchQuery={searchQuery} clearSearch={clearSearch} />} />
                                <Route path="/tools/:category/:toolId" element={<ToolsLayout globalInputs={globalInputs} searchQuery={searchQuery} clearSearch={clearSearch} />} />

                                {/* Fallback */}
                                <Route path="*" element={<Navigate to="/" replace />} />
                            </Routes>
                        </Suspense>
                    </ErrorBoundary>
                </main>
            </div>

            <CommandPalette onSelectTool={(toolId, category) => {
                navigate(`/tools/${category}/${toolId}`);
                clearSearch();
            }} />
        </div>
    );
}

export default App;
