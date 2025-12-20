import React, { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCcw } from 'lucide-react';

interface Props {
    children: ReactNode;
    fallback?: ReactNode;
}

interface State {
    hasError: boolean;
    error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
    public state: State = {
        hasError: false,
        error: null,
    };

    public static getDerivedStateFromError(error: Error): State {
        return { hasError: true, error };
    }

    public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        console.error('Uncaught error:', error, errorInfo);
    }

    public render() {
        if (this.state.hasError) {
            if (this.props.fallback) {
                return this.props.fallback;
            }

            return (
                <div className="flex flex-col items-center justify-center h-full min-h-[400px] p-8 text-center bg-[#0d1117]/50 rounded-xl border border-red-500/20">
                    <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mb-6">
                        <AlertTriangle className="w-8 h-8 text-red-500" />
                    </div>
                    <h2 className="text-2xl font-bold text-white mb-2">Something went wrong</h2>
                    <p className="text-gray-400 mb-6 max-w-md">
                        The component crashed. This usually happens due to a network error loading a tool or an internal logic bug.
                    </p>
                    <div className="bg-black/30 p-4 rounded-lg text-left w-full max-w-lg mb-6 overflow-x-auto border border-white/5">
                        <code className="text-xs text-red-400 font-mono">
                            {this.state.error?.message}
                        </code>
                    </div>
                    <button
                        onClick={() => window.location.reload()}
                        className="flex items-center gap-2 px-6 py-3 bg-white/5 hover:bg-white/10 text-white font-bold rounded-lg transition-colors"
                    >
                        <RefreshCcw size={16} />
                        Reload Application
                    </button>
                </div>
            );
        }

        return this.props.children;
    }
}
