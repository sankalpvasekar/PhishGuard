# Design System: PhishGuard - Real-Time Phishing Detection
**Project ID:** 1648464863595435202

## 1. Visual Theme & Atmosphere

PhishGuard embodies a **ruthless, precision-focused Security Operations Center (SOC)** aesthetic — the visual language of professionals who live at the front line of cybersecurity. The interface feels **dense yet navigable**, radiating technical authority and constant vigilance. Every element is purposeful: no decorative padding, no soft gradients without meaning.

The mood is **deep-space black command center**: dark enough to be worn for 8-hour shifts without eye strain, with critical information punctuated by electric, phosphor-tinted highlights that demand attention without causing panic. Threat indicators glow like alarm systems; safe indicators pulse like steady vitals.

**Key Characteristics:**
- Near-black deep void backgrounds with controlled depth using navy-tinted surfaces
- Cyberpunk-inspired electric accents used with surgical restraint
- Monospaced fonts for data/log outputs (terminal aesthetic)
- Color-coded threat/safe states as a core communication system
- Glassmorphism-lite: subtle translucency on modal overlays and status cards
- Micro-animations: pulsing status dots, glow effects on active states, smooth tab transitions

## 2. Color Palette & Roles

### Core Foundation
- **Deep Void Black** (`#0A0E1A`) – Primary application background. The foundational dark canvas evoking a void that lets all data elements pop with clarity.
- **Midnight Navy** (`#0D1B2A`) – Card, panel, and surface color. Provides the first tier of elevation above the background, used for email list panels, input areas, and engine cards.
- **Steel Shadow** (`#152233`) – Secondary surface for hover states and selected rows. Provides depth without breaking the dark immersion.

### Accent & Interactive
- **Electric Cyber Blue** (`#00D4FF`) – The primary action color. Used for: primary CTA buttons ("Scan for Phishing", "Analyze for Threats"), active tab indicators, input field focus borders, selected email row glow, hyperlinks, and status icons. This is the "alive and connected" signal.
- **Phosphor Green** (`#00FF88`) – The "safe" state color. Used for: SAFE threat badges on email rows, SPF/DKIM pass indicators, "connected" status dots, and safe result screens. Evokes terminal phosphor output — data that passed the check.

### Threat System
- **Threat Red** (`#FF3B3B`) – Critical threat indicator. Used for: THREAT badges, SPF/DKIM FAIL flags, malicious URL labels, the high-risk score gauge fill, and the "PHISHING DETECTED" badge. Must never be used decoratively.
- **Caution Amber** (`#FFA500`) – Moderate/suspicious state. Used for: SUSPICIOUS URL labels (bit.ly style shortened links), SOFTFAIL SPF results, warnings that are not yet confirmed threats.

### Typography Hierarchy
- **Pure White** (`#FFFFFF`) – Primary text for headlines, email subjects, and key data values.
- **Silver Mist** (`#A8B7C7`) – Secondary text for timestamps, metadata, sender domains, and supporting body text.
- **Deep Steel** (`#4A5568`) – Tertiary text for placeholders, disabled states, and quiet labels.

---

## 3. Typography Rules

**Primary Font Family:** Inter (sans-serif, loaded from Google Fonts)
**Data/Log Font:** `Courier New`, `monospace` – used exclusively for the reasoning log output, SPF/DKIM raw results, URL display strings, and terminal-style blocks.

### Weight & Size Usage
- **Dashboard Titles / Tab Labels:** Semi-bold (600), 1rem, slight letter-spacing (0.04em), uppercase
- **Email Subject Lines:** Medium (500), 0.9rem, truncated with ellipsis
- **Threat Percentage (Hero):** Extra-bold (800), 3.5rem, Threat Red or Phosphor Green depending on result
- **Card Section Headers:** Semi-bold (600), 0.875rem, uppercase, Silver Mist
- **Body / Email Preview Text:** Regular (400), 0.85rem, Silver Mist, 1.6 line-height
- **Badge Labels:** Bold (700), 0.7rem, uppercase, pill-shaped containers
- **Monospace Log Text:** Regular (400), 0.8rem, Phosphor Green on Deep Void Black background, 1.8 line-height

---

## 4. Component Stylings

### Buttons
- **Primary CTA (Scan / Analyze):** Full-width or wide, Midnight Navy background transitioning to Electric Cyber Blue on hover. Bold uppercase text in Deep Void Black. Subtle outer glow `0 0 12px rgba(0, 212, 255, 0.4)` on hover. Subtly rounded corners (8px radius). Transition: 200ms ease.
- **Secondary / Override Buttons:** Outlined style — 1px Electric Cyber Blue or Phosphor Green border, transparent background, text in the border color. Hover fills softly.
- **Danger Action (Mark as Spam):** Outlined Threat Red, fills on hover.

### Cards & Containers
- **Email List Panel:** Midnight Navy (`#0D1B2A`) background. Email rows separated by 1px Steel Shadow dividers. Selected row: Steel Shadow background + thin Electric Cyber Blue left border (3px) + faint Blue glow `box-shadow: inset 0 0 0 1px rgba(0,212,255,0.2)`.
- **Engine Result Cards:** Midnight Navy background, subtly rounded corners (8px). Top-border accent in the relevant color (Red for failed engine, Green for passed). Internal padding: 1.5rem. Hover: slightly elevated shadow `0 4px 16px rgba(0,0,0,0.4)`.
- **Threat Score Hero Card:** Gradient border or glow effect based on threat level. High threat: `0 0 40px rgba(255,59,59,0.3)`. Safe: `0 0 40px rgba(0,255,136,0.3)`.
- **Reasoning Log Block:** Deep Void Black background, Phosphor Green text, 1px Steel Shadow border, `border-radius: 6px`, `font-family: monospace`.

### Navigation
- **Top Nav Bar:** Midnight Navy background with 1px Steel Shadow bottom border. Tab items spaced 2rem apart. Active tab: Electric Cyber Blue bottom border (2px), Electric Cyber Blue text. Inactive: Silver Mist text, hover brightens to White.
- **App Logo/Name:** Bold uppercase "PhishGuard" with a shield + radar icon in Electric Cyber Blue.

### Badges / Pills
- **THREAT Badge:** `background: rgba(255,59,59,0.15)`, `border: 1px solid #FF3B3B`, `color: #FF3B3B`. Pill-shaped (full border-radius). Uppercase, bold.
- **SAFE Badge:** `background: rgba(0,255,136,0.12)`, `border: 1px solid #00FF88`, `color: #00FF88`. Same pill shape.
- **SUSPICIOUS Badge:** Amber (`#FFA500`) variant of same pattern.

### Inputs & Forms
- **Textarea / Text Inputs:** Background: `#0D1B2A`, `border: 1px solid #152233`. Focus state: `border-color: #00D4FF`, `box-shadow: 0 0 0 3px rgba(0,212,255,0.15)`. Placeholder text: Deep Steel (`#4A5568`). Text: White. `border-radius: 8px`. Font: Inter for inputs, monospace for textarea.
- **Input Row (3-column):** Displayed in a CSS Grid with `gap: 1rem`.

### Status Bar
- **Bottom Status Bar:** Midnight Navy, small text in Silver Mist. Pulsing green dot using CSS `@keyframes pulse` animation. Text: "Auto-scanning every 15s... | Last scan: 2 min ago".

---

## 5. Layout Principles

### Grid & Structure
- **Full-width desktop app:** No max-width limit on the outermost container; fills the viewport.
- **Inbox View split:** Left panel = `35% width` (email list), Right panel = `65% width` (email detail). `display: flex`.
- **Engine Cards:** 3-column CSS Grid, `grid-template-columns: repeat(3, 1fr)`, `gap: 1.5rem`.
- **Breakpoints:** Desktop-first. Responsive collapse at `< 900px` → stacked single column.

### Whitespace Strategy
- **Internal Card Padding:** 1.5rem (24px) consistently.
- **Section gaps:** 2rem (32px) between major UI sections.
- **Compact density:** This is a data-dense SOC UI — whitespace is functional, not decorative. Tighter than consumer apps.

### Alignment
- **Left-aligned** for all data text (email lists, metadata, log output).
- **Center-aligned** for hero elements only (Threat Score gauge, action buttons on results page).
- **Consistent left column alignment** using `padding-left: 1.5rem` on all panels.

---

## 6. Design System Notes for Stitch Generation

When creating additional screens, reference these exact phrases:

### Language to Use
- **Atmosphere:** "Deep-space black SOC command center with Electric Cyber Blue highlights"
- **Buttons:** "Subtly rounded corners (8px)" with "Electric Cyber Blue glow on hover"
- **Badges:** "Pill-shaped with a translucent tinted background and matching border"
- **Cards:** "Midnight Navy surface with an 8px border-radius and no outer glow in default state"
- **Threat State:** "Threat Red (#FF3B3B) radial glow pulsing outward"
- **Safe State:** "Phosphor Green (#00FF88) with terminal monitor character"

### Color References (always use descriptive name + hex)
- Primary BG: "Deep Void Black (#0A0E1A)"
- Surface: "Midnight Navy (#0D1B2A)"
- Accent/CTA: "Electric Cyber Blue (#00D4FF)"
- Threat: "Threat Red (#FF3B3B)"
- Safe: "Phosphor Green (#00FF88)"
- Caution: "Caution Amber (#FFA500)"

### Screens Generated
- **Inbox Dashboard** – Screen ID: `46aefef2e3ef4c3abfbaf9d6cd4ecd6a`
- **Manual Scan** – Screen ID: `4010390213b849ac8846971475edd37d`
- **Threat Analysis Results** – Screen ID: `498c9a0858054a02b415eb90f2bcce04`
