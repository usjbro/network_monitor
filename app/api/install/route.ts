import { NextRequest, NextResponse } from 'next/server';
import { osiMonClientSource } from '@/lib/osi-mon-client';

// The Host header's hostname, without its port: `[::1]:3000` -> `::1`,
// `127.0.0.1:3000` -> `127.0.0.1`.
function hostname(host: string): string {
  if (host.startsWith('[')) return host.slice(1, host.indexOf(']') === -1 ? undefined : host.indexOf(']'));
  return host.split(':')[0];
}

// Loopback is served over plain http (the app binds 127.0.0.1; LAN access
// goes through Caddy's https/mTLS front door). Since JAM-185 osi-mon
// actually connects to this origin, so 127.0.0.1 and ::1 must count too,
// and a name that merely contains "localhost" must not.
function isLoopbackHost(host: string): boolean {
  const name = hostname(host).toLowerCase();
  return name === 'localhost' || name === '::1' || /^127(\.\d{1,3}){3}$/.test(name);
}

export async function GET(req: NextRequest) {
  const host = req.headers.get('host') || 'localhost:3000';
  const protocol = isLoopbackHost(host) ? 'http' : 'https';
  const origin = `${protocol}://${host}`;
  // `host` is client-controlled (JAM-177). It reaches the generated script
  // only via JSON.stringify in osiMonClientSource, so it can never be more
  // than one JS string literal inside the single-quoted (non-expanding)
  // heredoc. osi-mon itself shows only what /api/stream reports (JAM-185).

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
${osiMonClientSource(origin)}
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
