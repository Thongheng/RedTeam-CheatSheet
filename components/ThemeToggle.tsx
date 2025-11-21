import React from 'react';
import { Theme } from '../types';

interface ThemeToggleProps {
  theme: Theme;
  toggleTheme: () => void;
}

export const ThemeToggle: React.FC<ThemeToggleProps> = ({ theme, toggleTheme }) => {
  return (
    <button
      onClick={toggleTheme}
      className={`
        relative w-16 h-8 rounded-full border-2 border-toy-border shadow-hard-sm transition-colors duration-300
        ${theme === 'dark' ? 'bg-gray-700' : 'bg-yellow-300'}
      `}
      aria-label="Toggle Theme"
    >
      <div
        className={`
          absolute top-1/2 -translate-y-1/2 w-6 h-6 rounded-full border-2 border-toy-border transition-all duration-300
          flex items-center justify-center text-xs font-bold shadow-sm
          ${theme === 'dark' 
            ? 'left-[calc(100%-1.75rem)] bg-gray-900 text-white' 
            : 'left-1 bg-white text-yellow-600'
          }
        `}
      >
        {theme === 'dark' ? '🌙' : '☀️'}
      </div>
    </button>
  );
};