// Builds the one-click Mac installer: a .zip (Safari unzips it automatically) holding ONE double-clickable
// "Install ParentGuard.command" that carries the agent files and this Mac's config.json inside it.
const enc = new TextEncoder();
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = b => { let c = 0xFFFFFFFF; for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
export const toB64 = bytes => { let s = ""; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000)); return btoa(s); };
const wrap = s => s.replace(/(.{76})/g, "$1\n").replace(/\n$/, "");

// Minimal ZIP writer (stored, no compression) that keeps the Unix "executable" permission bit.
export function makeZip(entries) {          // entries: [{name, data: Uint8Array, mode: 0o755}]
  const parts = [], central = []; let offset = 0;
  const u16 = n => [n & 255, (n >> 8) & 255], u32 = n => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];
  for (const e of entries) {
    const name = enc.encode(e.name), crc = crc32(e.data), size = e.data.length;
    const local = new Uint8Array([0x50, 0x4b, 3, 4, ...u16(20), ...u16(0x0800), ...u16(0), ...u16(0), ...u16(0x21), ...u32(crc), ...u32(size), ...u32(size), ...u16(name.length), ...u16(0)]);
    parts.push(local, name, e.data);
    central.push(new Uint8Array([0x50, 0x4b, 1, 2, ...u16(0x031E), ...u16(20), ...u16(0x0800), ...u16(0), ...u16(0), ...u16(0x21), ...u32(crc), ...u32(size), ...u32(size), ...u16(name.length), ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(((0o100000 | e.mode) << 16) >>> 0), ...u32(offset)]), name);
    offset += local.length + name.length + size;
  }
  const cdSize = central.reduce((a, b) => a + b.length, 0);
  const end = new Uint8Array([0x50, 0x4b, 5, 6, 0, 0, 0, 0, ...u16(entries.length), ...u16(entries.length), ...u32(cdSize), ...u32(offset), 0, 0]);
  const all = [...parts, ...central, end], out = new Uint8Array(all.reduce((a, b) => a + b.length, 0));
  let p = 0; for (const x of all) { out.set(x, p); p += x.length; } return out;
}

// files: {filename: Uint8Array} for agent.py, blocklists.py, ... install.command ; config: object ; childName: string
export function buildInstaller(files, config, childName) {
  const safe = String(childName || "").replace(/[^A-Za-z0-9 ._-]/g, "").trim().slice(0, 40);
  const all = { ...files, "config.json": enc.encode(JSON.stringify(config, null, 2)) };
  let sh = `#!/bin/bash
# ParentGuard one-click installer${safe ? " for " + safe : ""}. Contains this Mac's private device key: do not share this file.
clear
echo "=============================================="
echo "  ParentGuard - installing on this Mac${safe ? " (" + safe + ")" : ""}"
echo "=============================================="
echo
echo "When asked for a password, type the password you use to log in to this Mac."
echo "Nothing appears while you type - that is normal. Press Return when done."
echo
D="$(mktemp -d /tmp/parentguard.XXXXXX)"
trap 'rm -rf "$D"' EXIT
mkdir -p "$D/macos"
`;
  for (const [n, b] of Object.entries(all)) sh += `openssl base64 -d > "$D/macos/${n}" <<'MFG_EOF'\n${wrap(toB64(b))}\nMFG_EOF\n`;
  sh += `for f in ${Object.keys(all).join(" ")}; do
  if [ ! -s "$D/macos/$f" ]; then echo "The installer file is damaged (missing $f). Please download it again."; read -r -p "Press Return to close." _; exit 1; fi
done
chmod +x "$D/macos/install.command"
bash "$D/macos/install.command" "$D/macos/config.json"
RC=$?
echo
if [ $RC -eq 0 ]; then echo "All done. You can close this window."; else echo "Something needs attention - read the messages above."; fi
read -r -p "Press Return to close." _
exit $RC
`;
  const readme = `PARENTGUARD - INSTALL ON THIS MAC (3 steps)

1. Double-click "Install ParentGuard.command".
   If macOS says it "cannot be opened" because it is from an unidentified developer:
   right-click (or Control-click) the file, choose Open, then click Open again.
   (On newer macOS: System Settings > Privacy & Security > scroll down > "Open Anyway".)
2. A Terminal window opens. Type this Mac's login password when asked (nothing shows as you type), press Return.
3. Wait for "INSTALLATION VERIFIED". Then follow the short on-screen list of one-time permissions.

Do not share this file: it contains the private key for this device.
`;
  return makeZip([
    { name: "Install ParentGuard.command", data: enc.encode(sh), mode: 0o755 },
    { name: "READ ME FIRST.txt", data: enc.encode(readme), mode: 0o644 }]);
}
