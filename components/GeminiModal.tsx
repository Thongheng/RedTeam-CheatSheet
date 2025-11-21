
import React, { useState, useRef, useEffect } from 'react';
import { ChatMessage } from '../types';
import { generateRedTeamAdvice } from '../services/geminiService';

interface GeminiModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const GeminiModal: React.FC<GeminiModalProps> = ({ isOpen, onClose }) => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const initializedRef = useRef(false);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    // Reset when closed
    if (!isOpen) {
        initializedRef.current = false;
        setMessages([]);
        return;
    }

    // Initialize with a generic greeting only if empty
    if (isOpen && !initializedRef.current && messages.length === 0) {
        setMessages([{
            id: 'init',
            role: 'model',
            text: `RedTeam AI Assistant online.\n\nI can help you understand tools, generate payloads, or explain concepts. What's your objective?`
        }]);
        initializedRef.current = true;
    }
  }, [isOpen, messages.length]);

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      role: 'user',
      text: input
    };

    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    const responseText = await generateRedTeamAdvice(input);

    const botMsg: ChatMessage = {
      id: (Date.now() + 1).toString(),
      role: 'model',
      text: responseText
    };

    setMessages(prev => [...prev, botMsg]);
    setIsLoading(false);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
      <div className="w-full max-w-2xl h-[600px] bg-white dark:bg-toy-cardDark border-4 border-black rounded-2xl shadow-hard flex flex-col overflow-hidden animate-[fadeIn_0.2s_ease-out]">
        
        {/* Header */}
        <div className="p-4 bg-toy-red border-b-4 border-black flex justify-between items-center">
            <h2 className="text-xl font-black text-white tracking-wider">🤖 RED TEAM ASSISTANT</h2>
            <button onClick={onClose} className="w-8 h-8 bg-white text-black font-bold rounded-lg border-2 border-black shadow-hard-sm hover:translate-y-1 hover:shadow-none transition-all">
                X
            </button>
        </div>

        {/* Chat Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-toy-bg dark:bg-gray-800">
            {messages.map((msg) => (
                <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-[80%] p-3 rounded-xl border-2 border-black shadow-hard-sm text-sm whitespace-pre-wrap
                        ${msg.role === 'user' 
                            ? 'bg-yellow-300 text-black rounded-br-none' 
                            : 'bg-white dark:bg-gray-700 dark:text-white rounded-bl-none'
                        }
                    `}>
                        {msg.text}
                    </div>
                </div>
            ))}
            {isLoading && (
                <div className="flex justify-start">
                    <div className="bg-white dark:bg-gray-700 p-3 rounded-xl border-2 border-black shadow-hard-sm rounded-bl-none">
                        <div className="flex gap-1">
                            <div className="w-2 h-2 bg-black dark:bg-white rounded-full animate-bounce"></div>
                            <div className="w-2 h-2 bg-black dark:bg-white rounded-full animate-bounce [animation-delay:0.1s]"></div>
                            <div className="w-2 h-2 bg-black dark:bg-white rounded-full animate-bounce [animation-delay:0.2s]"></div>
                        </div>
                    </div>
                </div>
            )}
            <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className="p-4 border-t-4 border-black bg-gray-100 dark:bg-gray-900 flex gap-2">
            <input 
                type="text" 
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                placeholder="Ask for advice or payloads..."
                className="flex-1 p-3 border-2 border-black rounded-xl shadow-inner focus:outline-none focus:ring-2 focus:ring-toy-red dark:bg-gray-800 dark:text-white"
            />
            <button 
                onClick={handleSend}
                disabled={isLoading || !input.trim()}
                className="bg-black text-white font-bold px-6 py-2 rounded-xl border-2 border-black shadow-hard-sm active:translate-y-1 active:shadow-none disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
                SEND
            </button>
        </div>
      </div>
    </div>
  );
};
