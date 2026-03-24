// ==================== ELEMENTS ====================
const messages = document.getElementById("messages");
const emptyState = document.getElementById("emptyState");
const input = document.getElementById("messageInput");
const sendBtn = document.getElementById("sendBtn");

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
        addMessage(
            msg.text,
            msg.sender === "web" ? "me" : "other"
        );
    } 
    else if (msg.type === "system") {
        handleSystemMessage(msg);
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

// ==================== UI ====================
function addMessage(text, type = "me") {
    if (!text) return;

    if (emptyState) {
        emptyState.style.display = "none";
    }

    const row = document.createElement("div");
    row.className = `msg-row ${type}`;

    const msg = document.createElement("div");
    msg.className = `msg ${type}`;
    msg.textContent = text;

    row.appendChild(msg);
    messages.appendChild(row);

    messages.scrollTop = messages.scrollHeight;
}

function clearChat() {
    messages.innerHTML = "";

    if (emptyState) {
        emptyState.style.display = "block";
    }
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

        if (ws.readyState === WebSocket.OPEN) {
            ws.close();
        }
    }
    else if (msg.action === "clear_chat") {
        clearChat();
        addMessage(msg.text || "Chat cleared", "system");
    }
    else { addMessage(msg.text || "System message", "system"); }
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

    const payload = {
        type: "chat",
        sender: "web",
        text: text
    };

    ws.send(JSON.stringify(payload));
    input.value = "";
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

        if (ws.readyState === WebSocket.OPEN) {
            ws.close();
        }
    }
    else if (cmd === "/close") {
        addMessage("Closing session view...", "system");
        setInputEnabled(false, "Closed");
        if (ws.readyState === WebSocket.OPEN) {
            ws.close();
        }
        setTimeout(() => {
            window.close();
        }, 150);
    } else { addMessage(`Unknown command: ${text}`, "system"); }
}

// ==================== EVENTS ====================
sendBtn.addEventListener("click", sendMessage);

input.addEventListener("keydown", (e) => { if (e.key === "Enter") { sendMessage(); }});
