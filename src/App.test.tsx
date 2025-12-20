import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { describe, it, expect, vi } from 'vitest';
import React from 'react';

// Mock the heavy tools to avoid lazy loading issues in test
vi.mock('./data/tools/registry/web', () => ({ WEB_REGISTRY: [] }));
vi.mock('./data/tools/registry/linux', () => ({ LINUX_REGISTRY: [] }));
vi.mock('./data/tools/registry/common', () => ({ COMMON_TOOLS: [] }));

describe('App', () => {
    it('renders the Get Started button on home page', async () => {
        render(
            <BrowserRouter>
                <App />
            </BrowserRouter>
        );

        // Check for specific text from the Home component
        expect(screen.getByText(/Offensive Security/i)).toBeInTheDocument();
        expect(screen.getByText(/Get Started/i)).toBeInTheDocument();
    });
});
