import type { Tool } from '../types';
import { WEB_TOOLS } from '../features/web';
import { WINDOWS_TOOLS } from '../features/windows';
import { LINUX_TOOLS } from '../features/linux';
import { MOBILE_TOOLS } from '../features/mobile';
import { UTILITY_TOOLS } from '../features/utilities';

// ====================================================================
// MASTER TOOLS REGISTRY
// All tools consolidated from feature modules
// ====================================================================

export const TOOLS: Tool[] = [
    ...WEB_TOOLS,
    ...WINDOWS_TOOLS,
    ...LINUX_TOOLS,
    ...MOBILE_TOOLS,
    ...UTILITY_TOOLS,
];
