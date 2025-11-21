
# RedToy Cheatsheet

A playful yet powerful Red Team cheatsheet with a Neubrutalist design, powered by Gemini AI. Now available as a Progressive Web App (PWA).

Link : https://thongheng.github.io/RedToy/

## 🚀 Local Setup

1.  **Clone the repository**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-name>
    ```

2.  **Install Dependencies**
    ```bash
    npm install
    ```

3.  **Set Environment Variable**
    Create a `.env` file in the root directory:
    ```
    API_KEY=your_google_gemini_api_key_here
    ```

4.  **Run Development Server**
    ```bash
    npm run dev
    ```
    Open the link shown in the terminal (usually `http://localhost:5173`).

## 🤖 AI Assistant Configuration

The "RedTeam AI" assistant is enabled by default. It uses the Google Gemini API.

### To Disable AI Features:
1.  Open `constants.ts`.
2.  Change `ENABLE_AI` to `false`:
    ```typescript
    export const ENABLE_AI = false; 
    ```
    This will remove the AI button from the header and prevent any API calls.

## 📱 PWA Setup (Desktop App)

This app is configured as a PWA. To make it look professional when installed:

1.  Create a `public` folder in the root directory.
2.  Add your icons to `public/`:
    *   `pwa-192x192.png` (192x192 px)
    *   `pwa-512x512.png` (512x512 px)
    *   `apple-touch-icon.png` (180x180 px)
    *   `favicon.ico`
3.  Rebuild the app: `npm run build`

Once deployed, users will see an "Install" icon in their browser address bar (Chrome/Edge), allowing them to install it as a standalone desktop application.

## 🌐 Hosting on GitHub Pages

This project is configured to deploy automatically via GitHub Actions using your secure API Key.

1.  Go to your GitHub repository **Settings**.
2.  Navigate to **Secrets and variables** > **Actions**.
3.  Click **New repository secret**.
4.  Name: `API_KEY`
5.  Value: Your Google Gemini API Key.
6.  Navigate to **Pages** (in the left sidebar).
7.  Under **Build and deployment**, ensure Source is set to **GitHub Actions**.
8.  Push your code to the `main` branch. The Action will trigger and deploy your site with the API key safely embedded.

## 🛠 Adding Features Manually

The data is now organized in the `data/` folder. You do not need to touch the UI code (`App.tsx`) to add new content.

### 1. Adding a New Tool (Command Generator)
Open `data/tools.ts`.
Add a new object to the `TOOLS` array:

```typescript
import { createArg } from './tools';

{
    id: 'unique_id_here',
    name: 'Tool Name',
    category: 'WEB', // Must match a key in data/categories.ts
    subcategory: 'Your Subcategory',
    desc: 'Description of what the tool does.',
    authMode: 'none', // 'none' | 'optional' | 'required'
    // Define your custom configuration toggles/inputs here
    args: [
        createArg.toggle('useHttps', 'Use HTTPS', true),
        createArg.input('extraParam', 'Custom Flag', '', '--default')
    ],
    generate: (v, args) => {
        // v = Global Inputs (v.target, v.domain, v.port, v.username, v.password)
        // args = Your custom defined args (args.useHttps, args.extraParam)
        
        const proto = args.useHttps ? 'https://' : 'http://';
        return `your-command ${proto}${v.target} ${args.extraParam}`;
    }
}
```

### 2. Adding a New Guide (Walkthrough)
Open `data/guides.ts`.
Add to the `GUIDES` array:

```typescript
{
    id: 'guide_id',
    name: 'Guide Tab Name',
    category: 'GUIDE',
    subcategory: 'Section Name', // e.g., 'Mobile'
    desc: 'Short description.',
    content: `# Step 1: Do this
command here

# Step 2: Do that
another command`
}
```
*Tip: Lines starting with `#` are highlighted as comments in yellow.*

### 3. Adding External References
Open `data/references.ts`.
Add to the `REFERENCES` array:

```typescript
{
    id: 'ref_id',
    name: 'Website Name',
    category: 'REF',
    subcategory: 'Category Name',
    desc: 'Short description of the resource.',
    url: 'https://example.com'
}
```
