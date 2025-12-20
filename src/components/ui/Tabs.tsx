import React, { useState } from 'react';

interface TabItem {
    id: string;
    label: string;
    content: React.ReactNode;
    icon?: React.ReactNode;
}

interface TabsProps {
    items: TabItem[];
    defaultActiveId?: string;
    className?: string;
}

export const Tabs: React.FC<TabsProps> = ({ items, defaultActiveId, className = '' }) => {
    const [activeId, setActiveId] = useState(defaultActiveId || items[0]?.id);

    const activeItem = items.find((item) => item.id === activeId);

    return (
        <div className={`space-y-6 ${className}`}>
            {/* Tab Navigation */}
            <div className="flex space-x-1 bg-[#0d1117]/50 p-1 rounded-xl border border-white/5 backdrop-blur-sm overflow-x-auto">
                {items.map((item) => (
                    <button
                        key={item.id}
                        onClick={() => setActiveId(item.id)}
                        className={`
                            flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-all duration-200 whitespace-nowrap
                            ${activeId === item.id
                                ? 'bg-[#a2ff00] text-black shadow-lg shadow-[#a2ff00]/10'
                                : 'text-gray-400 hover:text-white hover:bg-white/5'
                            }
                        `}
                    >
                        {item.icon}
                        {item.label}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            <div className="animate-fadeIn">
                {activeItem?.content}
            </div>
        </div>
    );
};

// TabNav - Navigation-only tabs (no content managed by this component)
interface TabNavItem {
    id: string;
    label: string;
    icon?: React.ReactNode;
}

interface TabNavProps {
    tabs: TabNavItem[];
    activeTab: string;
    onTabChange: (id: string) => void;
    className?: string;
}

export const TabNav: React.FC<TabNavProps> = ({ tabs, activeTab, onTabChange, className = '' }) => {
    return (
        <div className={`flex space-x-1 bg-[#0d1117]/50 p-1 rounded-xl border border-white/5 backdrop-blur-sm overflow-x-auto ${className}`}>
            {tabs.map((tab) => (
                <button
                    key={tab.id}
                    onClick={() => onTabChange(tab.id)}
                    className={`
                        flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-all duration-200 whitespace-nowrap
                        ${activeTab === tab.id
                            ? 'bg-[#a2ff00] text-black shadow-lg shadow-[#a2ff00]/10'
                            : 'text-gray-400 hover:text-white hover:bg-white/5'
                        }
                    `}
                >
                    {tab.icon}
                    {tab.label}
                </button>
            ))}
        </div>
    );
};
