## Design System: SecuredDoc

### Pattern
- **Name:** Conversion-Optimized
- **CTA Placement:** Above fold
- **Sections:** Hero > Features > CTA

### Style
- **Name:** Glassmorphism
- **Keywords:** Frosted glass, transparent, blurred background, layered, vibrant background, light source, depth, multi-layer
- **Best For:** Modern SaaS, financial dashboards, high-end corporate, lifestyle apps, modal overlays, navigation
- **Performance:** ⚠ Good | **Accessibility:** ⚠ Ensure 4.5:1

### Colors
| Role | Hex |
|------|-----|
| Primary | #F59E0B |
| Secondary | #FBBF24 |
| CTA | #8B5CF6 |
| Background | #0F172A |
| Text | #F8FAFC |

*Notes: Dark tech colors + trust + vibrant accents*

### Typography
- **Heading:** Orbitron
- **Body:** Exo 2
- **Mood:** crypto, web3, futuristic, tech, blockchain, digital
- **Best For:** Crypto platforms, NFT, blockchain, web3, futuristic tech
- **Google Fonts:** https://fonts.google.com/share?selection.family=Exo+2:wght@300;400;500;600;700|Orbitron:wght@400;500;600;700
- **CSS Import:**
```css
@import url('https://fonts.googleapis.com/css2?family=Exo+2:wght@300;400;500;600;700&family=Orbitron:wght@400;500;600;700&display=swap');
```

### Key Effects
Backdrop blur (10-20px), subtle border (1px solid rgba white 0.2), light reflection, Z-depth

### Avoid (Anti-patterns)
- Light backgrounds
- No security indicators

### Pre-Delivery Checklist
- [ ] No emojis as icons (use SVG: Heroicons/Lucide)
- [ ] cursor-pointer on all clickable elements
- [ ] Hover states with smooth transitions (150-300ms)
- [ ] Light mode: text contrast 4.5:1 minimum
- [ ] Focus states visible for keyboard nav
- [ ] prefers-reduced-motion respected
- [ ] Responsive: 375px, 768px, 1024px, 1440px

