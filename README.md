# Devil-3DS Custom Build & Save Editor (v1.0)
Created by **MickeeDee495**

## Credits & Upstream Attribution
- **DevilutionX**: Core Diablo & Hellfire engine port by the [DevilutionX Team](https://github.com).
- **devil-3ds**: Nintendo 3DS port and dual-screen UI foundation (`devil-3ds`).
- This repository includes a standalone Nintendo 3DS Save & Stash Editor (`Devil-3DS Save Editor v1.0`) along with a derivative patch/custom build of `devil-3ds`.

---

## Features

### 1. Devil-3DS Save Editor (`v1.0`)
- **Dual Folder & Save Mode Support**:
  - Automatically detects or lets you choose between `sdmc:/3ds/devil3ds` and `sdmc:/3ds/devilutionx`.
  - Supports **Single Player** (`single_0..3.sv` / `.hsv`) and **Multiplayer** (`multi_0..3.sv` / `.hsv`) saves for both **Diablo** and **Hellfire**.
- **Shared Stash Editor (`stash.sv` / `stash.hsv`)**:
  - Add **+100,000 Gold** directly to Single Player (`spstashitems`) or Multiplayer (`mpstashitems`) stash.
  - Inject **Base Weapons**, **Arcane Magic Weapons/Staves**, **Armor**, **Unique / Special Items** (with authentic stats, resistances, and special effects), **5x Potions/Elixirs**, and **5x Scrolls** across up to 20 stash pages with immediate inventory sprites.
- **Character Spell & Stat Editing**:
  - Unlock individual spells at **Level 15** or **Learn All 41 Spells** at once.
  - Apply **+25 Base Stat Boosts** (`STR`, `MAG`, `DEX`, `VIT`) or set **All Base Stats = 255** (updating both `"hero"` and active `"game"` snapshots so **Load Game** reflects changes immediately).
- **Hellfire Test Class Unlocker**:
  - One-click option to enable **Bard** and **Barbarian** in `diablo.ini` (`[Hellfire]`) across both save folders.
- **Instant Undo (`B` Button)**:
  - Automatically creates `.bak` backups before every modification and restores the previous save, stash, or `diablo.ini` with a single press of **B**.

### 2. Custom `devil-3ds` Build (`devil-3ds-changes.patch`)
- **Top-Screen Shared Stash UI**: Full `10×10` grid display on the 3DS top screen.
- **Instant Stash Item Transfer (`Y` Button)**: Press **Y** while Stash is open to move highlighted items directly between Inventory and Stash without dropping them.
- **Shop Repair & Recharge All (`SELECT` Button)**: Press **SELECT** while browsing Griswold or Adria to repair all equipped/inventory items or recharge all staves at once.

---

## Repository Structure
- `release/`
  - `devil3ds_save_editor.cia` / `devil3ds_save_editor.3dsx` — Standalone 3DS Save & Stash Editor (`v1.0`).
  - `devil-3ds.cia` / `devil-3ds.3dsx` — Custom `devil-3ds` build with Stash & Shop QoL controls.
- `source/`
  - `save_editor/` — Full C++ source code, item catalog (`items_catalog.h`), `CMakeLists.txt`, `app.rsf`, and `icon_editor.png`.
  - `devil-3ds-modified/` — Modified `Source/` files for `devil-3ds`.
  - `devil-3ds-changes.patch` — Standard `git diff` patch for applying changes onto upstream `devil-3ds`.

---

## Installation (Nintendo 3DS)
1. Copy the `.cia` files from `release/` to your 3DS SD card and install them using **FBI** (or copy the `.3dsx` files to `sdmc:/3ds/` for the Homebrew Launcher).
2. Always keep a backup of your `sdmc:/3ds/devil3ds/` or `sdmc:/3ds/devilutionx/` save folder before editing saves.
