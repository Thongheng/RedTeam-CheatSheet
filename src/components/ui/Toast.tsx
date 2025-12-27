import React from 'react';
import { Check, X, Info, AlertCircle } from 'lucide-react';

export interface ToastProps {
    show: boolean;
    message: string;
    variant?: 'success' | 'error' | 'info' | 'warning';
    className?: string;
}

const VARIANT_STYLES = {
    success: {
        border: 'border-[#a2ff00]',
        shadow: 'shadow-[#a2ff00]/20',
        iconBg: 'bg-[#a2ff00]',
        iconColor: 'text-black',
        Icon: Check,
    },
    error: {
        border: 'border-red-500',
        shadow: 'shadow-red-500/20',
        iconBg: 'bg-red-500',
        iconColor: 'text-white',
        Icon: X,
    },
    warning: {
        border: 'border-yellow-500',
        shadow: 'shadow-yellow-500/20',
        iconBg: 'bg-yellow-500',
        iconColor: 'text-black',
        Icon: AlertCircle,
    },
    info: {
        border: 'border-blue-500',
        shadow: 'shadow-blue-500/20',
        iconBg: 'bg-blue-500',
        iconColor: 'text-white',
        Icon: Info,
    },
};

export function Toast({ show, message, variant = 'success', className = '' }: ToastProps) {
    const styles = VARIANT_STYLES[variant];
    const Icon = styles.Icon;

    return (
        <div
            className={`fixed bottom-6 left-1/2 transform -translate-x-1/2 bg-[#0d1117] border-2 ${styles.border} px-6 py-4 rounded-xl flex items-center gap-3 shadow-2xl ${styles.shadow} transition-all duration-300 ${show ? 'translate-y-0 opacity-100' : 'translate-y-20 opacity-0 pointer-events-none'
                } ${className}`}
            style={{ zIndex: 9999 }}
        >
            <div className={`${styles.iconBg} rounded-full p-1.5 ${styles.iconColor}`}>
                <Icon size={16} strokeWidth={3} />
            </div>
            <span className="font-bold text-sm text-white">{message}</span>
        </div>
    );
}
