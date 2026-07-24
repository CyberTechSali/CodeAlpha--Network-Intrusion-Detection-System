let refreshIntervalMs = 5000;
let refreshTimer = null;

function updateClock() {
    const now = new Date();
    const el = document.getElementById("current-time");
    if (el) el.innerText = now.toLocaleString();
}

function setLastUpdate() {
    const el = document.getElementById("last-update");
    if (el) el.innerText = new Date().toLocaleTimeString();
}

function setRefreshInterval(ms) {
    refreshIntervalMs = parseInt(ms);
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(runRefreshCallbacks, refreshIntervalMs);
}

let refreshCallbacks = [];
function registerRefresh(fn) {
    refreshCallbacks.push(fn);
}
function runRefreshCallbacks() {
    refreshCallbacks.forEach(fn => fn());
    setLastUpdate();
}

async function loadSystemStatus() {
    try {
        const res = await fetch("/api/system/status");
        const data = await res.json();

        const map = {
            "status-suricata": data.suricata,
            "status-parser": data.parser,
            "status-sqlite": data.sqlite,
            "status-flask": data.flask,
            "status-response": data.response_engine
        };

        for (const [id, value] of Object.entries(map)) {
            const el = document.getElementById(id);
            if (!el) continue;
            const isOk = (value === "Running" || value === "OK");
            el.innerHTML = `<span class="dot ${isOk ? 'green' : 'red'}"></span> ${value}`;
        }

        const iface = document.getElementById("status-interface");
        if (iface) iface.innerText = data.interface;

        const uptime = document.getElementById("status-uptime");
        if (uptime) uptime.innerText = data.uptime;

        const dbsize = document.getElementById("status-dbsize");
        if (dbsize) dbsize.innerText = data.db_size_kb + " KB";

    } catch (e) {
        console.error("Error loading system status:", e);
    }
}

setInterval(updateClock, 1000);
updateClock();
loadSystemStatus();
setInterval(loadSystemStatus, 10000);
registerRefresh(loadSystemStatus);
setRefreshInterval(5000);
