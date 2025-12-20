import React from 'react';
import { Terminal } from 'lucide-react';

interface ToolHeaderProps {
    title: string;
    description: string;
    badge?: string;
    icon?: React.ReactNode;
}

export const ToolHeader: React.FC<ToolHeaderProps> = ({
    title,
    description,
    badge = 'RT',
    icon
}) => {
    return (
        <div className="flex items-start justify-between mb-6 animate-fade-in">
            <div>
                <div className="flex items-center gap-3 mb-2">
                    {/* Badge */}
                    <span className="bg-[#a2ff00]/10 text-[#a2ff00] px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider border border-[#a2ff00]/20">
                        {badge}
                    </span>

                    {/* Title with optional Icon */}
                    <h2 className="text-2xl font-black text-white flex items-center gap-3">
                        {icon && (
                            <div className="w-8 h-8 rounded bg-[#a2ff00]/5 border border-[#a2ff00]/10 flex items-center justify-center text-[#a2ff00]">
                                {icon}
                            </div>
                        )}
                        {title}
                    </h2>
                </div>

                {/* Description */}
                <p className="text-gray-400 max-w-3xl leading-relaxed">
                    {description}
                </p>
            </div>
        </div>
    );
};
