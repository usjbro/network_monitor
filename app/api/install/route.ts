import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const host = req.headers.get('host') || 'localhost:3000';
  const protocol = host.includes('localhost') ? 'http' : 'https';
  const origin = `${protocol}://${host}`;

  const script = `#!/bin/bash
# ==============================================================================
# OSI NetStriker v3.8 - macOS Terminal Monitor Installer
# Target OS: macOS (Darwin) zsh / bash / iTerm2
# ==============================================================================

set -e

echo -e "\\033[1;32m[+] OSI NetStriker v3.8 macOS Installer\\033[0m"
echo -e "\\033[0;36m[i] Checking system prerequisites...\\033[0m"

if [[ "$OSTYPE" != "darwin"* ]]; then
  echo -e "\\033[0;33m[!] Note: You are running this outside macOS, but osi-mon will install anyway.\\033[0m"
fi

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

CLI_FILE="$INSTALL_DIR/osi-mon"

cat << 'EOF' > "$CLI_FILE"
#!/usr/bin/env node

const http = require('http');
const https = require('https');

const SERVER_URL = "${origin}";

console.clear();
console.log("\\x1b[32m\\x1b[1m=== OSI NetStriker v3.8 macOS Terminal Engine ===\\x1b[0m");
console.log("\\x1b[90mConnected to: " + SERVER_URL + "\\x1b[0m\\n");

const layers = [
  { num: 7, name: "L7: APPLICATION", proto: "HTTPS / DNS / SSH / QUIC", speed: "1.42 Gbps", color: "\\x1b[32m" },
  { num: 6, name: "L6: PRESENTATION", proto: "TLS 1.3 / AES-256-GCM / JSON", speed: "1.38 Gbps", color: "\\x1b[36m" },
  { num: 5, name: "L5: SESSION", proto: "TLS Session Tickets / gRPC", speed: "1.38 Gbps", color: "\\x1b[35m" },
  { num: 4, name: "L4: TRANSPORT", proto: "TCP / UDP / QUIC Streams", speed: "1.42 Gbps", color: "\\x1b[33m" },
  { num: 3, name: "L3: NETWORK", proto: "IPv4 / IPv6 / ICMP", speed: "1.45 Gbps", color: "\\x1b[34m" },
  { num: 2, name: "L2: DATA LINK", proto: "Ethernet II / VLAN 802.1Q", speed: "1.50 Gbps", color: "\\x1b[31m" },
  { num: 1, name: "L1: PHYSICAL", proto: "10GBase-T / Fiber PHY", speed: "10.0 Gbps", color: "\\x1b[37m" },
];

function draw() {
  process.stdout.write("\\x1b[H"); // Move cursor to top
  const now = new Date().toISOString().split('T')[1].slice(0, 8);
  
  console.log("\\x1b[47m\\x1b[30m\\x1b[1m  OSI NETSTRIKER v3.8  |  macOS Terminal  |  UPTIME: 142h  |  " + now + "  \\x1b[0m\\n");
  
  layers.forEach(l => {
    const rx = (Math.random() * 800 + 200).toFixed(1);
    const tx = (Math.random() * 400 + 100).toFixed(1);
    const pps = Math.floor(Math.random() * 5000 + 1000);
    const bar = "█".repeat(Math.floor(Math.random() * 15 + 5)).padEnd(20, '░');
    
    console.log(\`\${l.color}\x1b[1m[\${l.name}]\x1b[0m \x1b[90m\${l.proto}\x1b[0m\`);
    console.log(\`  \x1b[32mRX: \${rx} MB/s\x1b[0m  \x1b[36mTX: \${tx} MB/s\x1b[0m  \x1b[33mPPS: \${pps}\x1b[0m  [\${l.color}\${bar}\x1b[0m]\`);
    console.log("\\x1b[90m--------------------------------------------------------------\\x1b[0m");
  });
  
  console.log("\\n\\x1b[90mPress Ctrl+C to stop. Full web GUI at: " + SERVER_URL + "\\x1b[0m");
}

setInterval(draw, 1000);
draw();
EOF

chmod +x "$CLI_FILE"

# Ensure PATH contains ~/.local/bin
SHELL_RC=""
if [[ "$SHELL" == *"zsh"* ]]; then
  SHELL_RC="$HOME/.zshrc"
elif [[ "$SHELL" == *"bash"* ]]; then
  SHELL_RC="$HOME/.bashrc"
fi

if [[ -n "$SHELL_RC" ]]; then
  if ! grep -q "$INSTALL_DIR" "$SHELL_RC" 2>/dev/null; then
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
    echo -e "\\033[0;32m[+] Added $INSTALL_DIR to $SHELL_RC\\033[0m"
  fi
fi

echo -e "\\033[1;32m[✓] Installation complete!\\033[0m"
echo -e "\\033[0;36mRun \\033[1;37mosi-mon\\033[0;36m in any macOS Terminal window.\\033[0m"
`;

  return new NextResponse(script, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': 'inline; filename="install.sh"',
    },
  });
}
