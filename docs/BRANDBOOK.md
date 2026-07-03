# VEIL Brandbook

## 1. Brand idea

**VEIL** is a privacy and network-tunnel brand built around three visual metaphors:

- **Shield** — protection, private network boundary, safe tunnel.
- **Veil / folded layer** — hidden transport, stealth, DPI resistance, obscured metadata.
- **Signal tunnel** — connectivity between distant devices and subnets.

The visual language should feel: **private, technical, precise, premium, calm, and fast**.

---

## 2. Logo concept

The core mark is a shield-shaped emblem with a folded veil at the top and a central **V** / tunnel opening.

Meaning:

- outer shield = protection;
- folded purple layers = veil / concealment;
- inner V = VEIL initial + secure route;
- cyan arcs/dots = encrypted signal path / private network tunnel.

Recommended name for this style:

> **Cyber Veil Shield**

Alternative internal style names:

- **VeilShield**
- **Stealth Tunnel Mark**
- **Encrypted Veil Emblem**

---

## 3. Primary colors

| Token | Hex | Usage |
|---|---:|---|
| `veil-navy-950` | `#050814` | Deep app background |
| `veil-navy-900` | `#071126` | Main dark UI surface |
| `veil-indigo-700` | `#343B8F` | Shield base |
| `veil-violet-600` | `#6D43E6` | Main V / folded veil |
| `veil-purple-500` | `#8758FF` | Highlights and gradients |
| `veil-cyan-400` | `#25D7E8` | Network signal accents |
| `veil-teal-300` | `#46F0E5` | Active glow / connection |
| `veil-slate-500` | `#53627F` | Muted secondary shapes |

---

## 4. Gradient style

Primary logo gradient:

```css
background: linear-gradient(145deg, #343B8F 0%, #6D43E6 52%, #8758FF 100%);
```

Signal glow gradient:

```css
background: radial-gradient(circle, #46F0E5 0%, #25D7E8 38%, rgba(37,215,232,0) 72%);
```

Dark app background:

```css
background: radial-gradient(circle at 50% 42%, #101D48 0%, #071126 48%, #050814 100%);
```

---

## 5. Typography direction

Recommended font categories:

- UI / app: **Inter**, **SF Pro**, **Segoe UI Variable**
- Technical docs: **JetBrains Mono**, **IBM Plex Mono**
- Brand headings: **Space Grotesk**, **Sora**, **Manrope**

Recommended wordmark style:

```text
VEIL
```

Use uppercase, medium-to-semibold weight, wide tracking:

```css
letter-spacing: 0.08em;
font-weight: 600;
```

---

## 6. Icon usage

### Primary app icon

Use `VEIL-icon-app-background.png` or `VEIL-icon-dark-bg.jpg` for:

- Windows GUI launcher;
- app store / release pages;
- GitHub README hero;
- documentation covers.

### Transparent mark

Use `VEIL-icon-transparent.png` and `VEIL-icon-transparent.ico` for:

- Windows `.ico`;
- tray icon;
- overlays;
- splash screen;
- websites with custom background.

### Minimum sizes

| Context | Recommended |
|---|---:|
| Windows ICO | 16, 24, 32, 48, 64, 128, 256 |
| Website favicon | 32 or 48 |
| App icon | 256+ |
| README/logo | 512+ |

At very small sizes, prefer the transparent shield mark without extra text.

---

## 7. Do and do not

### Do

- Use the shield centered with enough clear space.
- Keep dark navy backgrounds.
- Use cyan only as an accent, not the dominant color.
- Preserve the folded veil top silhouette.
- Preserve the central V shape.

### Do not

- Do not place the logo on bright white without a dark container.
- Do not flatten the cyan glow into pure green.
- Do not add small text inside the icon.
- Do not stretch or rotate the shield.
- Do not use red/orange warning colors as primary brand colors.

---

## 8. Product tone

Recommended wording:

- private tunnel
- secure route
- hidden transport
- stealth networking
- encrypted path
- private mesh
- DPI-resistant transport

Avoid overclaiming:

- “invisible”
- “undetectable”
- “unblockable”
- “military-grade”
- “absolute anonymity”

Better phrasing:

> VEIL is designed to avoid known WireGuard/OpenVPN wire signatures while preserving high-performance private networking.

---

## 9. UI style direction

VEIL UI should feel like:

- dark mode first;
- simple connection state;
- low-noise technical controls;
- advanced settings hidden behind profiles;
- cyan for active/connected state;
- purple/indigo for brand surfaces.

State colors:

| State | Color |
|---|---:|
| Connected | `#46F0E5` |
| Connecting | `#8758FF` |
| Warning | `#F4B740` |
| Error | `#FF5D73` |
| Disabled | `#53627F` |

---

## 10. File package

Included assets:

- `VEIL-icon-transparent.png`
- `VEIL-icon-transparent.ico`
- `VEIL-icon-dark-bg.jpg`
- `VEIL-icon-app-background.png`
- `VEIL-icon-transparent-16.png`
- `VEIL-icon-transparent-32.png`
- `VEIL-icon-transparent-48.png`
- `VEIL-icon-transparent-64.png`
- `VEIL-icon-transparent-128.png`
- `VEIL-icon-transparent-256.png`
- `VEIL-icon-transparent-512.png`

Note: JPEG does **not** support transparent backgrounds. For transparent usage, use PNG or ICO.
