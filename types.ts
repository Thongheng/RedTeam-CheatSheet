
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

export interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  text: string;
  isError?: boolean;
}

export type Theme = 'light' | 'dark';