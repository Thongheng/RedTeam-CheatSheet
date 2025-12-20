
export interface GlobalInputs {
    target: string;
    domain: string;
    username: string;
    password: string;
    filepath: string;
}

export type ArgType = 'toggle' | 'text';

export interface ToolArg {
    key: string;
    type: ArgType;
    label: string;
    defaultValue: any;
    placeholder?: string; // For text input
}

export interface Tool {
    id: string;
    name: string;
    category: string;
    subcategory: string;
    desc: string;
    authMode: 'none' | 'optional' | 'required';
    args?: ToolArg[];
    generate: (inputs: GlobalInputs, args: Record<string, any>) => string;
    source?: 'hacktools' | 'redtoy'; // Track origin for v1/v2
    component?: React.ComponentType; // For refactored legacy components
}

export interface ReferenceItem {
    id: string;
    name: string;
    category: string;
    subcategory: string;
    desc: string;
    url: string;
}

export interface GuideItem {
    id: string;
    name: string;
    category: string;
    subcategory: string;
    desc: string;
    content: string; // The markdown/code content
}

export interface CategoryDef {
    icon: any;
    label: string;
}

export type Theme = 'light' | 'dark';
