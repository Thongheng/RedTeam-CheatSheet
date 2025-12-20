# RedSploit V2

<p align="center">
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react" alt="React">
  <img src="https://img.shields.io/badge/Vite-7-646CFF?style=for-the-badge&logo=vite" alt="Vite">
  <img src="https://img.shields.io/badge/TailwindCSS-4-38B2AC?style=for-the-badge&logo=tailwindcss" alt="Tailwind">
  <img src="https://img.shields.io/badge/TypeScript-5-3178C6?style=for-the-badge&logo=typescript" alt="TypeScript">
</p>

**The all-in-one offensive security toolkit** — merged from [HackTools](https://github.com/LasCC/Hack-Tools) and [RedToy](https://github.com/...), featuring a dark, cyberpunk UI inspired by [Hack The Box](https://hackthebox.ai).

## ✨ Features

- **100+ Tools** — Reverse shells, web exploitation, privilege escalation, and more
- **Multiple Sources** — Combined tools from HackTools and RedToy
- **Real-time Generation** — Dynamic command generation with customizable parameters
- **One-click Copy** — Instant copy to clipboard
- **Dark Theme** — Premium HTB-inspired cyberpunk aesthetic
- **Categorized** — 8 categories: Recon, Web, Exploit, Windows, Linux, Mobile, Post-Exploitation, Other

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/redsploit-v2.git
cd redsploit-v2

# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

## 📦 Build

```bash
# Production build
npm run build

# Preview production build
npm run preview
```

## 🎨 Design System

Built with the HTB cyberpunk aesthetic:

| Element | Color |
|---------|-------|
| Primary Background | `#05080d` |
| Secondary Background | `#0d1117` |
| Accent | `#a2ff00` |
| Text | `#ffffff` |
| Muted Text | `#6b7280` |

### Typography
- **UI Font**: Inter
- **Code Font**: JetBrains Mono

## 🗂️ Project Structure

```
src/
├── components/
│   ├── tools/
│   │   ├── ToolRenderer.tsx    # Data-driven tool renderer
│   │   └── legacy/             # HackTools components (to refactor)
│   ├── layout/
│   └── ui/
├── data/
│   ├── tools/                  # RedToy tool definitions
│   │   ├── common.ts
│   │   ├── web.ts
│   │   ├── windows.ts
│   │   └── other.ts
│   └── categories.ts
├── types/
│   └── index.ts                # TypeScript interfaces
├── App.tsx                     # Main application
└── index.css                   # HTB design system
```

## 🔧 Tool Types

### Data-Driven Tools (RedToy)
Simple tools defined as data objects:

```typescript
{
  id: 'subdomain_enum',
  name: 'All-in-One Subdomain',
  category: 'WEB',
  subcategory: 'Subdomain Enum',
  desc: 'Comprehensive subdomain enumeration script',
  authMode: 'none',
  generate: (inputs, args) => `subfinder -d ${inputs.domain}`,
}
```

### Legacy Tools (HackTools)
Complex components in `components/tools/legacy/`. These require refactoring from Ant Design to Tailwind CSS.

## 🛣️ Roadmap

- [x] Phase 1: HTB Design System foundation
- [x] Phase 2: Tool migration (HackTools + RedToy)
- [x] Phase 3: Testing & UI integration
- [x] Phase 4: Polish & documentation
- [ ] Phase 5: Refactor legacy HackTools components
- [ ] Phase 6: Browser extension support

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Credits

- [HackTools](https://github.com/LasCC/Hack-Tools) — Original browser extension
- [RedToy](https://github.com/...) — Data-driven tool framework
- [Hack The Box](https://hackthebox.com) — UI/UX inspiration
