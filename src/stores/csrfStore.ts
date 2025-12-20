import { create } from 'zustand';

interface CSRFState {
    error: string;
    setError: (error: string) => void;
    request: string;
    setRequest: (request: string) => void;
    parsedPostBody: Record<string, any>;
    setParsedPostBody: (body: Record<string, any>) => void;
}

export const useCSRFStore = create<CSRFState>((set) => ({
    error: '',
    setError: (error: string) => set({ error }),
    request: '',
    setRequest: (request: string) => set({ request }),
    parsedPostBody: {},
    setParsedPostBody: (parsedPostBody: Record<string, any>) => set({ parsedPostBody }),
}));
