# RedToy Cheatsheet

A playful yet powerful Red Team cheatsheet. It is powered by Google's Gemini AI to assist with command generation and explanations.

Link : https://thongheng.github.io/RedToy/

## 🚀 Local Setup

1.  **Clone the repository**
    ```bash
    git clone <your-repo-url>
    cd RedToy
    ```

2.  **Install Dependencies**
    ```bash
    npm install
    ```

3.  **Set Environment Variable**
    To use the AI features, you need a Google Gemini API key.
    Create a `.env` file in the root directory:
    ```
    API_KEY=your_google_gemini_api_key_here
    ```

4.  **Run Development Server**
    ```bash
    npm run dev
    ```
    Open the link shown in the terminal (usually `http://localhost:5173`).

## 🤖 AI Assistance

RedToy includes an AI assistant powered by Google Gemini. It can help explain tools, generate complex commands, and provide Red Teaming tips.

Note : AI features are disabled by default.

### Configuration
The AI features are controlled by the `ENABLE_AI` constant in `constants.ts`.

-   **To Enable/Disable:**
    Open `constants.ts` and set `ENABLE_AI` to `true` or `false`.
    ```typescript
    export const ENABLE_AI = true; // Set to false to disable
    ```

-   **Requirements:**
    You must have a valid API key in your `.env` file as described in the setup steps.

## 🛠 Adding Your Own Data

The application is designed to be easily extensible. All data is located in the `data/` folder. You do not need to modify the main application code to add new tools or guides.

### 1. Adding a New Tool
Open `data/tools.ts` and add a new object to the `TOOLS` array.

```typescript
import { createArg } from './tools';

{
    id: 'unique_tool_id',
    name: 'Tool Name',
    category: 'WEB', // Must match a category in data/categories.ts
    subcategory: 'Enumeration',
    desc: 'Description of what the tool does.',
    authMode: 'none', // 'none' | 'optional' | 'required'
    args: [
        createArg.toggle('useHttps', 'Use HTTPS', true),
        createArg.input('target', 'Target IP/Domain', '', '--target')
    ],
    generate: (v, args) => {
        // v = Global Inputs (v.target, v.domain, etc.)
        // args = Your custom args defined above
        return `tool-name ${args.target}`;
    }
}
```

### 2. Adding a New Guide
Open `data/guides.ts` and add to the `GUIDES` array.

```typescript
{
    id: 'guide_unique_id',
    name: 'Guide Title',
    category: 'GUIDE',
    subcategory: 'Topic',
    desc: 'Brief description.',
    content: `# Step 1: Initial Scan
nmap -sC -sV <target>

# Step 2: Analysis
Analyze the output...`
}
```

### 3. Adding References
Open `data/references.ts` and add to the `REFERENCES` array.

```typescript
{
    id: 'ref_unique_id',
    name: 'Resource Name',
    category: 'REF',
    subcategory: 'Topic',
    desc: 'Description of the resource.',
    url: 'https://example.com'
}
```
