export interface Env {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  CONTEXT_DO: DurableObjectNamespace;
}

export interface OAuthEnv {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
}

// Durable Object for storing markdown documents
export class ContextDO {
  private state: DurableObjectState;
  private env: Env;
  private sessions: Set<WebSocket>;
  private content: string;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.sessions = new Set();
    this.content = "";
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Initialize content from storage
    if (!this.content) {
      this.content =
        (await this.state.storage.get("content")) ||
        "# New Document\n\nStart editing...";
    }

    if (request.headers.get("Upgrade") === "websocket") {
      return this.handleWebSocket(request);
    }

    if (request.method === "GET") {
      return new Response(JSON.stringify({ content: this.content }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    if (request.method === "POST") {
      const { content, user } = (await request.json()) as {
        content: string;
        user: any;
      };

      // Validate user can write to this path
      const docPath = url.pathname;
      if (!this.canUserWrite(user, docPath)) {
        return new Response("Unauthorized", { status: 403 });
      }

      this.content = content;
      await this.state.storage.put("content", content);

      // Broadcast to all connected clients
      this.broadcast({ type: "update", content, user: user.login });

      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("Method not allowed", { status: 405 });
  }

  private canUserWrite(user: any, docPath: string): boolean {
    if (!user) return false;

    // Remove leading slash and split path
    const pathParts = docPath.substring(1).split("/");
    const username = pathParts[0];

    // User can write to /<username> or /<username>/*
    return username === user.login;
  }

  private async handleWebSocket(request: Request): Promise<Response> {
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    server.accept();
    this.sessions.add(server);

    // Send current content immediately
    server.send(JSON.stringify({ type: "init", content: this.content }));

    server.addEventListener("close", () => {
      this.sessions.delete(server);
    });

    server.addEventListener("error", () => {
      this.sessions.delete(server);
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  private broadcast(message: any) {
    const messageStr = JSON.stringify(message);
    for (const session of this.sessions) {
      try {
        session.send(messageStr);
      } catch (error) {
        // Remove broken connections
        this.sessions.delete(session);
      }
    }
  }
}

// OAuth middleware (embedded)

interface OAuthState {
  redirectTo?: string;
  codeVerifier: string;
}

export async function handleOAuth(
  request: Request,
  env: OAuthEnv,
  scope = "user:email",
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/login") {
    return handleLogin(request, env, scope);
  }

  if (path === "/callback") {
    return handleCallback(request, env);
  }

  if (path === "/logout") {
    return handleLogout(request);
  }

  return null;
}

async function handleLogin(
  request: Request,
  env: OAuthEnv,
  scope: string,
): Promise<Response> {
  const url = new URL(request.url);
  const redirectTo = url.searchParams.get("redirect_to") || "/";

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  const state: OAuthState = { redirectTo, codeVerifier };
  const stateString = btoa(JSON.stringify(state));

  const githubUrl = new URL("https://github.com/login/oauth/authorize");
  githubUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  githubUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  githubUrl.searchParams.set("scope", scope);
  githubUrl.searchParams.set("state", stateString);
  githubUrl.searchParams.set("code_challenge", codeChallenge);
  githubUrl.searchParams.set("code_challenge_method", "S256");

  return new Response(null, {
    status: 302,
    headers: {
      Location: githubUrl.toString(),
      "Set-Cookie": `oauth_state=${encodeURIComponent(
        stateString,
      )}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
    },
  });
}

async function handleCallback(
  request: Request,
  env: OAuthEnv,
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");

  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const stateCookie = cookies.oauth_state;

  if (!stateCookie || stateCookie !== stateParam) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  let state: OAuthState;
  try {
    state = JSON.parse(atob(stateParam));
  } catch {
    return new Response("Invalid state format", { status: 400 });
  }

  const tokenResponse = await fetch(
    "https://github.com/login/oauth/access_token",
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${url.origin}/callback`,
        code_verifier: state.codeVerifier,
      }),
    },
  );

  const tokenData = (await tokenResponse.json()) as any;

  if (!tokenData.access_token) {
    return new Response("Failed to get access token", { status: 400 });
  }

  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "WordDO-Worker",
    },
  });

  if (!userResponse.ok) {
    return new Response("Failed to get user info", { status: 400 });
  }

  const userData = (await userResponse.json()) as any;

  const sessionData = {
    user: userData,
    accessToken: tokenData.access_token,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };

  const sessionToken = btoa(JSON.stringify(sessionData));
  const headers = new Headers({ Location: state.redirectTo || "/" });

  headers.append(
    "Set-Cookie",
    "oauth_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
  );
  headers.append(
    "Set-Cookie",
    `session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Max-Age=${
      7 * 24 * 60 * 60
    }; Path=/`,
  );

  return new Response(null, { status: 302, headers });
}

async function handleLogout(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const redirectTo = url.searchParams.get("redirect_to") || "/";
  return new Response(null, {
    status: 302,
    headers: {
      Location: redirectTo,
      "Set-Cookie":
        "session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
    },
  });
}

export function getCurrentUser(request: Request): any | null {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const sessionToken = cookies.session;

  if (!sessionToken) return null;

  try {
    const sessionData = JSON.parse(atob(sessionToken));
    if (Date.now() > sessionData.exp) return null;
    return sessionData.user;
  } catch {
    return null;
  }
}

export function getAccessToken(request: Request): string | null {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const sessionToken = cookies.session;

  if (!sessionToken) return null;

  try {
    const sessionData = JSON.parse(atob(sessionToken));
    if (Date.now() > sessionData.exp) return null;
    return sessionData.accessToken;
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  cookieHeader.split(";").forEach((cookie) => {
    const [name, value] = cookie.trim().split("=");
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });
  return cookies;
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, Array.from(array)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return btoa(
    String.fromCharCode.apply(null, Array.from(new Uint8Array(digest))),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Main worker handler
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Handle OAuth routes
    const oauthResponse = await handleOAuth(request, env, "user:email");
    if (oauthResponse) {
      return oauthResponse;
    }

    // Handle API routes
    if (url.pathname.startsWith("/api/")) {
      const docPath = url.pathname.replace("/api", "");
      const docId = env.CONTEXT_DO.idFromName(docPath);
      const docStub = env.CONTEXT_DO.get(docId);

      if (request.method === "POST") {
        const user = getCurrentUser(request);
        const body = (await request.json()) as { content: string };

        return docStub.fetch(
          new Request(request.url, {
            method: "POST",
            body: JSON.stringify({ content: body.content, user }),
            headers: { "Content-Type": "application/json" },
          }),
        );
      }

      return docStub.fetch(request);
    }

    // Handle WebSocket connections
    if (request.headers.get("Upgrade") === "websocket") {
      const docId = env.CONTEXT_DO.idFromName(url.pathname);
      const docStub = env.CONTEXT_DO.get(docId);
      return docStub.fetch(request);
    }

    // Serve the HTML interface
    if (url.pathname === "/" || url.pathname.match(/^\/[^\/]*$/)) {
      return new Response(getHTML(), {
        headers: { "Content-Type": "text/html" },
      });
    }

    // Handle document paths
    if (url.pathname.match(/^\/[^\/]+(\/.*)?$/)) {
      return new Response(getHTML(), {
        headers: { "Content-Type": "text/html" },
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};

function getHTML(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WordDO - Collaborative Markdown</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
        .container { display: flex; height: 100vh; }
        .editor-panel, .preview-panel { flex: 1; display: flex; flex-direction: column; }
        .toolbar { background: #f5f5f5; padding: 10px; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; }
        .auth-info { font-size: 14px; color: #666; }
        .login-btn, .logout-btn { background: #0366d6; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; text-decoration: none; }
        .logout-btn { background: #d73a49; }
        .editor { flex: 1; font-family: 'Monaco', 'Menlo', monospace; border: none; outline: none; padding: 20px; resize: none; }
        .preview { flex: 1; padding: 20px; overflow-y: auto; border-left: 1px solid #ddd; }
        .status { background: #f8f9fa; padding: 5px 10px; font-size: 12px; color: #666; border-top: 1px solid #ddd; }
        .readonly { background: #f8f9fa; }
        h1, h2, h3, h4, h5, h6 { margin: 20px 0 10px 0; }
        p { margin: 10px 0; line-height: 1.6; }
        pre { background: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto; }
        code { background: #f6f8fa; padding: 2px 4px; border-radius: 3px; }
        blockquote { border-left: 4px solid #dfe2e5; padding-left: 16px; margin: 16px 0; color: #6a737d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="editor-panel">
            <div class="toolbar">
                <div>
                    <strong>Path:</strong> <span id="current-path"></span>
                </div>
                <div class="auth-info" id="auth-info">
                    <a href="/login" class="login-btn">Login with GitHub</a>
                </div>
            </div>
            <textarea class="editor" id="editor" placeholder="Start typing your markdown..."></textarea>
            <div class="status" id="status">Connecting...</div>
        </div>
        <div class="preview-panel">
            <div class="toolbar">
                <strong>Preview</strong>
            </div>
            <div class="preview" id="preview"></div>
        </div>
    </div>

    <script>
        class WordDOClient {
            constructor() {
                this.editor = document.getElementById('editor');
                this.preview = document.getElementById('preview');
                this.status = document.getElementById('status');
                this.authInfo = document.getElementById('auth-info');
                this.currentPath = window.location.pathname;
                this.user = null;
                this.canWrite = false;
                this.ws = null;
                this.debounceTimer = null;
                
                this.init();
            }
            
            async init() {
                await this.checkAuth();
                await this.loadDocument();
                this.connectWebSocket();
                this.setupEventListeners();
            }
            
            async checkAuth() {
                try {
                    const response = await fetch('/api' + this.currentPath);
                    const data = await response.json();
                    
                    // Try to get user info from a protected endpoint
                    const authResponse = await fetch('/api/user-info', { credentials: 'include' });
                    if (authResponse.ok) {
                        this.user = await authResponse.json();
                        this.updateAuthUI();
                        this.checkWritePermission();
                    }
                } catch (e) {
                    // Not authenticated
                }
            }
            
            updateAuthUI() {
                if (this.user) {
                    this.authInfo.innerHTML = \`
                        <span>Logged in as \${this.user.login}</span>
                        <a href="/logout" class="logout-btn">Logout</a>
                    \`;
                } else {
                    this.authInfo.innerHTML = '<a href="/login" class="login-btn">Login with GitHub</a>';
                }
            }
            
            checkWritePermission() {
                if (!this.user) {
                    this.canWrite = false;
                } else {
                    const pathParts = this.currentPath.substring(1).split('/');
                    const username = pathParts[0];
                    this.canWrite = username === this.user.login;
                }
                
                if (!this.canWrite) {
                    this.editor.classList.add('readonly');
                    this.editor.readOnly = true;
                    this.editor.placeholder = this.user ? 
                        'You can only edit documents in your own namespace (/' + this.user.login + '/*)' :
                        'Login to edit documents';
                }
            }
            
            async loadDocument() {
                try {
                    const response = await fetch('/api' + this.currentPath);
                    const data = await response.json();
                    this.editor.value = data.content;
                    this.updatePreview();
                } catch (e) {
                    this.status.textContent = 'Error loading document';
                }
            }
            
            connectWebSocket() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                this.ws = new WebSocket(\`\${protocol}//\${window.location.host}\${this.currentPath}\`);
                
                this.ws.onopen = () => {
                    this.status.textContent = 'Connected';
                };
                
                this.ws.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    
                    if (data.type === 'init') {
                        this.editor.value = data.content;
                        this.updatePreview();
                    } else if (data.type === 'update') {
                        this.editor.value = data.content;
                        this.updatePreview();
                        this.status.textContent = \`Updated by \${data.user}\`;
                        setTimeout(() => {
                            this.status.textContent = 'Connected';
                        }, 2000);
                    }
                };
                
                this.ws.onclose = () => {
                    this.status.textContent = 'Disconnected';
                    setTimeout(() => this.connectWebSocket(), 3000);
                };
                
                this.ws.onerror = () => {
                    this.status.textContent = 'Connection error';
                };
            }
            
            setupEventListeners() {
                this.editor.addEventListener('input', () => {
                    this.updatePreview();
                    if (this.canWrite) {
                        this.debounceSave();
                    }
                });
            }
            
            updatePreview() {
                this.preview.innerHTML = marked.parse(this.editor.value);
            }
            
            debounceSave() {
                clearTimeout(this.debounceTimer);
                this.debounceTimer = setTimeout(() => {
                    this.saveDocument();
                }, 1000);
            }
            
            async saveDocument() {
                if (!this.canWrite) return;
                
                try {
                    await fetch('/api' + this.currentPath, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ content: this.editor.value }),
                        credentials: 'include'
                    });
                } catch (e) {
                    this.status.textContent = 'Save failed';
                    setTimeout(() => {
                        this.status.textContent = 'Connected';
                    }, 2000);
                }
            }
        }
        
        new WordDOClient();
    </script>
</body>
</html>`;
}
