import { COMMON_TOOLS } from './common';
import { WEB_REGISTRY } from './web';
import { LINUX_REGISTRY } from './linux';
import { OTHER_TOOLS } from '../other';
import { WEB_TOOLS } from '../web';
import { WEB_EXTRA_TOOLS } from './web-extra';
import { WINDOWS_TOOLS } from './windows';
import { MOBILE_TOOLS } from './mobile';

// Combined Tools Registry
export const HACKTOOLS_REGISTRY = [
    ...COMMON_TOOLS,
    ...WEB_REGISTRY,
    ...WEB_TOOLS,
    ...WEB_EXTRA_TOOLS,
    ...LINUX_REGISTRY,
    ...WINDOWS_TOOLS,
    ...MOBILE_TOOLS,
    ...OTHER_TOOLS,
];
