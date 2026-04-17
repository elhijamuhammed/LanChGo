// ==================== ELEMENTS ====================
const messages = document.getElementById("messages");
const emptyState = document.getElementById("emptyState");
const input = document.getElementById("messageInput");
const sendBtn = document.getElementById("sendBtn");
const fileTransferPanelBtn = document.getElementById("FileTransferPanelButton");
const filePanelBody = document.getElementById("filePanelBody");

// ==================== WEBSOCKET ====================
const ws = new WebSocket(`ws://${location.host}/ws`);

ws.onopen = () => {
    console.log("✅ Connected to server");
    setInputEnabled(true, "Type a message...");
    addMessage("Connected to session", "system");
};

ws.onmessage = (e) => {
    console.log("📩 Raw received:", e.data);

    let msg;
    try {
        msg = JSON.parse(e.data);
    } catch {
        console.warn("Invalid JSON message:", e.data);
        return;
    }

    if (msg.type === "chat") {
        addMessage(msg.text, msg.sender === "web" ? "me" : "other");
    } 
    else if (msg.type === "system") {
        handleSystemMessage(msg);
    }
    else if (msg.type === "file_offer") {
        addFileTransferOffer(msg);
    }
};

ws.onclose = () => {
    console.log("❌ Disconnected from server");
    addMessage("Disconnected from session", "system");
    setInputEnabled(false, "Disconnected");
};

ws.onerror = (err) => {
    console.error("⚠️ WebSocket error:", err);
};

// ==================== BADGE ====================
let unreadFileOffers = 0;

function updateFileBadge() {
    const badge = document.getElementById("fileTransferBadge");
    if (!badge) return;
    if (unreadFileOffers > 0) {
        badge.textContent = unreadFileOffers;
        badge.style.display = "flex";
    } else {
        badge.style.display = "none";
    }
}

// ==================== UI ====================
function addMessage(text, type = "me") {
    if (!text) return;

    if (emptyState) emptyState.style.display = "none";

    const row = document.createElement("div");
    row.className = `msg-row ${type}`;

    const msg = document.createElement("div");
    msg.className = `msg ${type}`;
    msg.textContent = text;

    row.appendChild(msg);
    messages.appendChild(row);
    messages.scrollTop = messages.scrollHeight;
}

function addFileTransferOffer(msg) {
    if (!filePanelBody) return;

    const existing = filePanelBody.querySelector(`[data-offer-id="${CSS.escape(msg.offer_id)}"]`);
    if (existing) return;

    if (!filePanelOverlay.classList.contains("open")) {
        unreadFileOffers++;
        updateFileBadge();
    }

    const card = document.createElement("div");
    card.className = "file-transfer-card";
    card.dataset.offerId = msg.offer_id || "";

    const icon = document.createElement("div");
    icon.className = "file-transfer-icon";
    icon.textContent = "📄";

    const content = document.createElement("div");
    content.className = "file-transfer-content";

    const nameEl = document.createElement("div");
    nameEl.className = "file-transfer-name";
    const name = msg.name || "Unknown file";
    nameEl.textContent = name.length > 20 ? name.slice(0, 10) + "..." : name;

    const sizeEl = document.createElement("div");
    sizeEl.className = "file-transfer-size";
    sizeEl.textContent = formatBytes(msg.size || 0);

    const actions = document.createElement("div");
    actions.className = "file-transfer-actions";

    const btn = document.createElement("button");
    btn.className = "FileTransferPanelButton";
    btn.textContent = "Download";

    btn.addEventListener("click", () => {
        requestDownload(msg.offer_id);
        btn.textContent = "Downloading...";
        btn.disabled = true;
    });

    actions.appendChild(btn);
    content.appendChild(nameEl);
    content.appendChild(sizeEl);
    content.appendChild(actions);
    card.appendChild(icon);
    card.appendChild(content);
    filePanelBody.appendChild(card);
}

function clearChat() {
    messages.innerHTML = "";
    if (emptyState) emptyState.style.display = "block";
}

function setInputEnabled(enabled, placeholderText = "Type a message...") {
    input.disabled = !enabled;
    sendBtn.disabled = !enabled;
    input.placeholder = placeholderText;
}

function handleSystemMessage(msg) {
    if (msg.action === "session_end") {
        addMessage(msg.text || "Session has ended", "system");
        setInputEnabled(false, "Session ended");
        if (ws.readyState === WebSocket.OPEN) ws.close();
    }
    else if (msg.action === "clear_chat") {
        clearChat();
        addMessage(msg.text || "Chat cleared", "system");
    }
    else {
        addMessage(msg.text || "System message", "system");
    }
}

// ==================== SEND ====================
function sendMessage() {
    const text = input.value.trim();
    if (!text) return;

    if (text.startsWith("/")) {
        handleCommand(text);
        input.value = "";
        return;
    }

    if (ws.readyState !== WebSocket.OPEN) {
        addMessage("Cannot send: not connected", "system");
        return;
    }

    ws.send(JSON.stringify({ type: "chat", sender: "web", text }));
    input.value = "";
}

function requestDownload(offerId) {
    if (!offerId) return;
    const a = document.createElement("a");
    a.href = `/download/${offerId}`;
    a.download = "";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// ==================== COMMANDS ====================
function handleCommand(text) {
    const cmd = text.trim().toLowerCase();

    if (cmd === "/clear") {
        clearChat();
        addMessage("Chat cleared", "system");
    }
    else if (cmd === "/help") {
        addMessage("Available commands: /help, /clear, /info, /disconnect, /close", "system");
    }
    else if (cmd === "/info") {
        addMessage("LanChGo Web Companion\nUse this page to send and receive chat messages from the active session.", "system");
    }
    else if (cmd === "/disconnect") {
        addMessage("Disconnecting from session...", "system");
        setInputEnabled(false, "Disconnected");
        if (ws.readyState === WebSocket.OPEN) ws.close();
    }
    else if (cmd === "/close") {
        addMessage("Closing session view...", "system");
        setInputEnabled(false, "Closed");
        if (ws.readyState === WebSocket.OPEN) ws.close();
        setTimeout(() => window.close(), 150);
    }
    else {
        addMessage(`Unknown command: ${text}`, "system");
    }
}

// ==================== HELPERS ====================
function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0, num = bytes;
    while (num >= 1024 && i < units.length - 1) { num /= 1024; i++; }
    return `${num.toFixed(num >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

// ==================== EVENTS ====================
sendBtn.addEventListener("click", sendMessage);

input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
});

const filePanelClose = document.getElementById("filePanelClose");
const filePanelOverlay = document.getElementById("filePanelOverlay");
const clearFileTransfer = document.getElementById("clearFileTransfer");

if (fileTransferPanelBtn) {
    fileTransferPanelBtn.addEventListener("click", () => {
        filePanelOverlay.classList.add("open");
        unreadFileOffers = 0;
        updateFileBadge();
    });
}

if (filePanelClose) {
    filePanelClose.addEventListener("click", () => {
        filePanelOverlay.classList.remove("open");
    });
}

if (clearFileTransfer) {
    clearFileTransfer.addEventListener("click", () => {
        if (filePanelBody) filePanelBody.innerHTML = "";
    });
}
