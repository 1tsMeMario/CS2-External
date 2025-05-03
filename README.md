# CS2 External Cheat

An advanced Counter-Strike 2 cheat with an auto-update system, handle hijack for memory reading/writing, and CreateWindowInBand overlay.

> **Disclaimer:** This project is for educational purposes only. I do not condone cheating in multiplayer games. Use at your own risk.

---

## Features

### Keyauth Login System
- **Keyauth Library:** Uses the keyauth library to provider a user login system. So far thats all there is for keyauth.

### Security & Stealth
- **Streamproof:** Fully Streamproof et all times, including startup.
- **Hijacked Handle:** Hijacks a handle from the game process to read/write memory.

### Auto-Offset Management
- **Offset Auto-Updater:** Uses [a2x dumper](https://github.com/a2x/cs2-dumper) to always stay updated with the latest CS2 structures and addresses.

### External Overlay
- **Overlay Rendering:** Utilizes CreateWindowInBand to create a overlay, allowing the cheat to run even in fullscreen games.

---

## Requirements
- Windows 10/11 x64
- Administrator privileges (for handle and memory operations)
- Visual Studio 2022 (C++17 or higher)

---

## Handle Hijack Modes

| Mode        | Description                                                                                                           |
|-------------|-----------------------------------------------------------------------------------------------------------------------|
| External    | Executes core logic from a separate process using a handle that belongs to the game.                                  |
| Fallback    | Capable of many configurations including fallback to OpenProcess if a handle cant be hijacked                         |

---

## Usage

1. **Build** the solution using Visual Studio.
2. **Run EXE** and follow the directions.
4. The cheat will:
   - Hijack a valid handle.
   - Duplicate and use it for further operations.
   - Render overlay and execute logic.

---

> **Disclaimer:** This was put together in a day so there may be issues and the code isnt that great.

## TODO
- Add Features Lol (rn its barebones, but the offsets that it has rn are enough to make glow esp with.)

## Credits
- **a2x:** for his amazing code thats been keeping chairs alive https://github.com/a2x/cs2-dumper
- **t0ughknuckle:** for portions of his code i used to make my auto-updater https://github.com/t0ughknuckles/cs2-offset-auto-updater
- **exp1007:** for his CreateWindowInBand code https://github.com/exp1007/CreateWindowInBand
- **Apxaey:** for his handle hijack bypass code https://github.com/Apxaey/Handle-Hijacking-Anti-Cheat-Bypass
- **Me:** for my ability to hack together code from a c# program that i completely didnt fkin understand & having any sanity left after dealing with undocumented structures and apis all day.