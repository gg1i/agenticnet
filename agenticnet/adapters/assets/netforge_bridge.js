// NetForge Clean-Room Companion Script Module for Cisco Packet Tracer 8.2.2 (MIT License)
// Module ID: com.netforge.bridge
// Typed-opcode RPC dispatcher over lazy headless WebView -> 127.0.0.1 HTTP + token auth.
var MODULE_ID = "com.netforge.bridge";
var SESSION_FILE = "__NETFORGE_SESSION_FILE__";
var BRIDGE_WEBVIEW_TITLE = "NetForge Bridge";
var IDLE_POLL_INTERVAL_MS = 5000;
var SESSION_FRESH_TTL_MS = 60000;
var MAX_FAILED_POLLS = 3;

var wv = null;
var wvReady = false;
var activeConfigKey = "";
var activeCfg = null;
var sessionTimer = null;
var isStarted = false;
var isStopping = false;
var blacklistedSessions = {};
var failedPollCount = 0;
var missedDescriptorCount = 0;

function normalizeSlashPath(p) {
    try {
        if (!p) { return ""; }
        var s = String(p).replace(/\\/g, "/");
        while (s.length > 1 && s.charAt(s.length - 1) === "/") {
            s = s.slice(0, -1);
        }
        return s;
    } catch (e) {
        return "";
    }
}

function appendUniquePath(list, seen, candidate) {
    try {
        var norm = normalizeSlashPath(candidate);
        if (!norm || seen[norm]) { return; }
        seen[norm] = true;
        list.push(norm);
    } catch (e) {}
}

function resolveSessionCandidates() {
    try {
        var candidates = [];
        var seen = {};
        if (SESSION_FILE && SESSION_FILE.indexOf("__") !== 0) {
            appendUniquePath(candidates, seen, SESSION_FILE);
        }
        var aw = ipc.appWindow();
        if (aw && typeof aw.getTempFileLocation === "function") {
            var tempDir = normalizeSlashPath(aw.getTempFileLocation());
            if (tempDir) {
                var tParts = tempDir.split("/");
                for (var ti = tParts.length - 1; ti >= 1; ti--) {
                    if (
                        String(tParts[ti - 1]).toLowerCase() === "appdata" &&
                        String(tParts[ti]).toLowerCase() === "local"
                    ) {
                        appendUniquePath(
                            candidates,
                            seen,
                            tParts.slice(0, ti + 1).join("/") + "/netforge/bridge_session.json"
                        );
                    }
                }
                if (tParts.length > 1) {
                    appendUniquePath(
                        candidates,
                        seen,
                        tParts.slice(0, tParts.length - 1).join("/") + "/netforge/bridge_session.json"
                    );
                }
            }
        }
        if (aw && typeof aw.getUserFolder === "function") {
            var userDir = normalizeSlashPath(aw.getUserFolder());
            if (userDir) {
                var bases = [userDir];
                var lastSlash = userDir.lastIndexOf("/");
                if (lastSlash > 2) {
                    bases.push(userDir.slice(0, lastSlash));
                }
                for (var bi = 0; bi < bases.length; bi++) {
                    var b = bases[bi];
                    appendUniquePath(candidates, seen, b + "/AppData/Local/netforge/bridge_session.json");
                    appendUniquePath(candidates, seen, b + "/.local/share/netforge/bridge_session.json");
                    appendUniquePath(
                        candidates,
                        seen,
                        b + "/Library/Application Support/netforge/bridge_session.json"
                    );
                    appendUniquePath(candidates, seen, b + "/.netforge/bridge_session.json");
                }
            }
        }
        return candidates;
    } catch (e) {
        return [];
    }
}

function getSessionIdFromPayload(parsed) {
    try {
        if (!parsed || typeof parsed !== "object") { return ""; }
        if (parsed.session_id) { return String(parsed.session_id); }
        return String(parsed.url || "") + "|" + String(parsed.server_pid || "") + "|" + String(parsed.created_at || "");
    } catch (e) {
        return "";
    }
}

function isSessionDescriptorFresh(parsed, nowMs) {
    try {
        if (!parsed || typeof parsed !== "object") { return false; }
        if (typeof parsed.url !== "string" || !parsed.url) { return false; }
        if (typeof parsed.token !== "string" || !parsed.token) { return false; }
        var serverPid = Number(parsed.server_pid);
        var createdAt = Number(parsed.created_at);
        var heartbeatAt = Number(parsed.heartbeat_at || parsed.created_at);
        if (!serverPid || isNaN(serverPid) || serverPid <= 0) { return false; }
        if (!createdAt || isNaN(createdAt) || createdAt <= 0) { return false; }
        if (!heartbeatAt || isNaN(heartbeatAt) || heartbeatAt <= 0) { return false; }
        var refNow = (typeof nowMs === "number" && !isNaN(nowMs)) ? nowMs : Date.now();
        var ttlMs = SESSION_FRESH_TTL_MS;
        if (typeof parsed.ttl_ms === "number" && !isNaN(parsed.ttl_ms) && parsed.ttl_ms > 0) {
            ttlMs = Math.min(Number(parsed.ttl_ms), SESSION_FRESH_TTL_MS);
        }
        var ageMs = refNow - heartbeatAt;
        if (ageMs > ttlMs || ageMs < -15000) { return false; }
        var sid = getSessionIdFromPayload(parsed);
        if (!sid || blacklistedSessions[sid]) { return false; }
        return true;
    } catch (e) {
        return false;
    }
}

function readSessionConfig() {
    try {
        var fm = ipc.systemFileManager();
        var candidates = resolveSessionCandidates();
        var nowMs = Date.now();
        for (var i = 0; i < candidates.length; i++) {
            var path = candidates[i];
            if (!fm.fileExists(path)) {
                continue;
            }
            var raw = fm.getFileContents(path);
            if (!raw) {
                continue;
            }
            var parsed = JSON.parse(raw);
            if (isSessionDescriptorFresh(parsed, nowMs)) {
                return {
                    session_id: getSessionIdFromPayload(parsed),
                    url: parsed.url,
                    token: parsed.token,
                    server_pid: Number(parsed.server_pid),
                    created_at: Number(parsed.created_at),
                    heartbeat_at: Number(parsed.heartbeat_at || parsed.created_at)
                };
            }
        }
        return null;
    } catch (e) {
        return null;
    }
}

function destroyWebView() {
    try {
        if (wv) {
            var oldWv = wv;
            wv = null;
            wvReady = false;
            try {
                if (typeof oldWv.close === "function") {
                    oldWv.close();
                }
            } catch (eClose) {}
        }
        wvReady = false;
    } catch (e) {}
}

function blacklistSession(sessionId, reason) {
    try {
        var sid = String(sessionId || (activeCfg && activeCfg.session_id) || "");
        if (sid) {
            blacklistedSessions[sid] = true;
        }
        activeConfigKey = "";
        activeCfg = null;
        failedPollCount = 0;
        missedDescriptorCount = 0;
        destroyWebView();
    } catch (e) {}
}

function netforgeOnPollSuccess(sessionId) {
    try {
        failedPollCount = 0;
        missedDescriptorCount = 0;
    } catch (e) {}
}

function netforgeOnPollFailure(sessionId, failCount, errText) {
    try {
        var sid = String(sessionId || (activeCfg && activeCfg.session_id) || "");
        if (!activeCfg || (sid && activeCfg.session_id && sid !== activeCfg.session_id)) {
            return;
        }
        var reportedCount = Number(failCount);
        if (!isNaN(reportedCount) && reportedCount > 0) {
            failedPollCount = Math.max(failedPollCount + 1, reportedCount);
        } else {
            failedPollCount += 1;
        }
        if (failedPollCount >= MAX_FAILED_POLLS) {
            blacklistSession(sid, errText);
        }
    } catch (e) {}
}

function sendBridgeResult(requestId, ok, data, error) {
    try {
        if (!wv) { return; }
        var payload = {
            request_id: requestId,
            ok: Boolean(ok),
            data: data || {},
            error: error ? String(error) : null
        };
        wv.evaluateJavaScriptAsync("window.netforgePostResult(" + JSON.stringify(payload) + ");");
    } catch (e) {}
}

function applyConfigToWebView() {
    try {
        if (!isStarted || isStopping || !wv || !wvReady || !activeCfg) { return; }
        wv.evaluateJavaScriptAsync("window.netforgeStart(" + JSON.stringify(activeCfg) + ");");
    } catch (e) {}
}

function netforgeOnWebViewReady() {
    try {
        if (!isStarted || isStopping) { return; }
        wvReady = true;
        applyConfigToWebView();
    } catch (e) {}
}

function ensureWebView() {
    try {
        if (!isStarted || isStopping || wv) { return; }
        if (!activeCfg || !activeCfg.url || !activeCfg.token) { return; }
        wvReady = false;
        wv = webViewManager.createWebView(BRIDGE_WEBVIEW_TITLE, "this-sm:bridge.html", 240, 100);
        wv.addAllowedExternalFilter("http://127.0.0.1*");
    } catch (e) {}
}

function pollSessionDescriptor() {
    try {
        if (!isStarted || isStopping) { return; }
        var next = readSessionConfig();
        if (!next) {
            if (wv || activeCfg) {
                missedDescriptorCount += 1;
                if (missedDescriptorCount >= MAX_FAILED_POLLS) {
                    blacklistSession(activeCfg ? activeCfg.session_id : "", "session_descriptor_missing_or_stale");
                }
            }
            return;
        }
        missedDescriptorCount = 0;
        var key = String(next.session_id || "") + "|" + next.url + "|" + next.token;
        if (key !== activeConfigKey) {
            activeConfigKey = key;
            activeCfg = next;
            failedPollCount = 0;
            ensureWebView();
            applyConfigToWebView();
        }
    } catch (e) {}
}

function walkTreeLeaves(node, prefix, leaves) {
    try {
        if (!node) { return; }
        var name = "";
        try { name = String(node.getNodeName()); } catch (e0) {}
        var path = prefix ? (prefix + " > " + name) : name;
        var cc = 0;
        try { cc = node.getChildCount(); } catch (e1) {}
        if (cc === 0) {
            leaves.push({
                path: path,
                name: name,
                value: String(node.getNodeValue() || ""),
                leafCount: node.getLeafCount(),
                checkLeafCount: node.getCheckLeafCount(),
                totalLeafPoints: node.getTotalLeafPoints(),
                checkLeafPoints: node.getCheckLeafPoints(),
                incorrectFeedback: String(node.getIncorrectFeedback() || "")
            });
        } else {
            for (var i = 0; i < cc; i++) {
                walkTreeLeaves(node.getChildNodeAt(i), path, leaves);
            }
        }
    } catch (e) {}
}

function handleCliExec(requestId, params) {
    try {
    var devName = String(params.device_name || "");
    var rawCmdList = params.commands || [];
    var execCommands = [];
    var cIdx = 0;
    for (cIdx = 0; cIdx < rawCmdList.length; cIdx += 1) {
        execCommands.push(String(rawCmdList[cIdx]));
    }
    var requestedTimeoutMs = Number(params.timeout_ms || 25000);
    var timeoutMs = isNaN(requestedTimeoutMs) || requestedTimeoutMs <= 0 ? 25000 : requestedTimeoutMs;
    var waitForPrompt = params.wait_for_prompt !== false;
    var dev = ipc.network().getDevice(devName);
    if (!dev) {
        sendBridgeResult(requestId, false, {}, "Device not found: " + devName);
        return;
    }
    var term = dev.getCommandLine();
    if (!term) {
        sendBridgeResult(requestId, false, {}, "Device has no TerminalLine: " + devName);
        return;
    }

    var chunks = [];
    var statuses = [];
    var nonFatalCommands = [];
    var moreCount = 0;
    var lastMoreChunkLen = -1;
    var sent = false;
    var nextIdx = 0;
    var stage = "check_boot";
    var yesNoHandled = false;
    var pressReturnSentAt = 0;
    var lastCmdSentAt = 0;
    var finished = false;
    var iv = null;

    var onOut = function (_src, args) { chunks.push(String(args.newOutput || "")); };
    var onEnd = function (_src, args) {
        if (!sent) {
            return;
        }
        var cmdStr = String(args.inputCommand || "");
        var st = Number(args.status);
        var trimmed = cmdStr.replace(/^\s+|\s+$/g, "").toLowerCase();
        var isTermLenZero = trimmed.indexOf("terminal length 0") === 0;
        var isNonFatal = isTermLenZero && st !== 0;
        if (isNonFatal) {
            nonFatalCommands.push(cmdStr);
        }
        statuses.push({ command: cmdStr, status: st, non_fatal: isNonFatal });
    };
    var onMore = function () {
        moreCount += 1;
        lastMoreChunkLen = chunks.join("").length;
        try { term.enterChar(32, 0); } catch (e) {}
    };

    term.registerEvent("outputWritten", null, onOut);
    term.registerEvent("commandEnded", null, onEnd);
    try { term.registerEvent("moreDisplayed", null, onMore); } catch (eRegMore) {}

    var cleanupListeners = function () {
        try { term.unregisterEvent("outputWritten", null, onOut); } catch (e1) {}
        try { term.unregisterEvent("commandEnded", null, onEnd); } catch (e2) {}
        try { term.unregisterEvent("moreDisplayed", null, onMore); } catch (e3) {}
    };

    var finishCli = function (ok, data, errMsg) {
        if (finished) {
            return;
        }
        finished = true;
        if (iv !== null) {
            clearInterval(iv);
            iv = null;
        }
        cleanupListeners();
        sendBridgeResult(requestId, ok, data, errMsg);
    };

    var startedAt = Date.now();
    var stepCli = function () {
        try {
            if (finished) {
                if (iv !== null) { clearInterval(iv); iv = null; }
                return;
            }
            var elapsed = Date.now() - startedAt;
            var rawNow = chunks.join("");
            var promptNow = String(term.getPrompt() || "");
            var trimmedPrompt = promptNow.replace(/^\s+|\s+$/g, "");
            var hasCliPrompt = /([>#])$/.test(trimmedPrompt);
            var effectiveTimeoutMs = (!hasCliPrompt && !sent && !params.strict_timeout)
                ? Math.max(timeoutMs, 20000)
                : timeoutMs;

            if (stage === "check_boot") {
                if (hasCliPrompt) {
                    stage = "send";
                } else if (!yesNoHandled && rawNow.indexOf("[yes/no]") !== -1) {
                    yesNoHandled = true;
                    term.enterCommand("no");
                    stage = "wait_prompt";
                } else if (rawNow.indexOf("Press RETURN") !== -1 && (Date.now() - pressReturnSentAt > 600)) {
                    pressReturnSentAt = Date.now();
                    term.enterCommand("");
                    stage = "wait_prompt";
                } else if (elapsed > 1500 && rawNow.length === 0 && !pressReturnSentAt) {
                    pressReturnSentAt = Date.now();
                    term.enterCommand("");
                } else if (elapsed > Math.min(effectiveTimeoutMs * 0.75, 16000)) {
                    stage = "send";
                }
            } else if (stage === "wait_prompt") {
                if (hasCliPrompt) {
                    stage = "send";
                } else if (rawNow.indexOf("Press RETURN") !== -1 && (Date.now() - pressReturnSentAt > 600)) {
                    pressReturnSentAt = Date.now();
                    term.enterCommand("");
                } else if (elapsed > Math.min(effectiveTimeoutMs * 0.8, 17000)) {
                    stage = "send";
                }
            }

            if (stage === "send" && !sent) {
                var isPromptProbeOnly = (
                    execCommands.length === 0
                    || (execCommands.length === 1 && execCommands[0].replace(/^\s+|\s+$/g, "") === "")
                );
                if (isPromptProbeOnly && hasCliPrompt) {
                    finishCli(true, {
                        device_name: devName,
                        prompt: promptNow,
                        mode: String(term.getMode() || ""),
                        raw_output: rawNow || promptNow,
                        command_statuses: statuses,
                        non_fatal_commands: nonFatalCommands,
                        more_pages_advanced: moreCount,
                        timed_out: false
                    }, null);
                    return;
                }
                if (execCommands.length > 0) {
                    var firstTrim = execCommands[0].replace(/^\s+|\s+$/g, "").toLowerCase();
                    if ((firstTrim === "configure terminal" || firstTrim === "conf t")
                        && trimmedPrompt.slice(-1) === ">") {
                        execCommands.unshift("enable");
                    } else if ((firstTrim === "enable" || firstTrim === "en")
                        && /\(config[^)]*\)#$/.test(trimmedPrompt)) {
                        execCommands[0] = "end";
                    }
                }
                sent = true;
                nextIdx = 1;
                lastCmdSentAt = Date.now();
                term.enterCommand(execCommands.length > 0 ? String(execCommands[0]) : "");
                stage = "wait_done";
            } else if (stage === "wait_done") {
                var tail = rawNow.slice(-32);
                var atMore = tail.indexOf("--More--") !== -1;
                if (atMore && rawNow.length !== lastMoreChunkLen) {
                    lastMoreChunkLen = rawNow.length;
                    moreCount += 1;
                    try { term.enterChar(32, 0); } catch (eMore) {}
                }
                // Recover if PT drops a `commandEnded` event while an async syslog line
                // interleaves and the CLI prompt is already back (skip slow ping/traceroute).
                if (statuses.length < nextIdx && hasCliPrompt && !atMore
                    && lastCmdSentAt > 0 && (Date.now() - lastCmdSentAt > 250)) {
                    var pendingCmd = String(execCommands[statuses.length] || "");
                    var pendingLow = pendingCmd.replace(/^\s+|\s+$/g, "").toLowerCase();
                    var isSlowNetCmd = (
                        pendingLow.indexOf("ping") === 0
                        || pendingLow.indexOf("traceroute") === 0
                    );
                    if (!isSlowNetCmd) {
                        statuses.push({ command: pendingCmd, status: 0, non_fatal: true });
                        lastCmdSentAt = Date.now();
                    }
                }
                // Send commands one at a time: queued keystrokes typed while a
                // --More-- pager is active get swallowed (observed: "ping" -> "ing").
                if (nextIdx < execCommands.length && statuses.length >= nextIdx && !atMore) {
                    lastCmdSentAt = Date.now();
                    term.enterCommand(String(execCommands[nextIdx]));
                    nextIdx += 1;
                }
                var doneByCount = statuses.length >= execCommands.length && !atMore;
                if (!waitForPrompt || doneByCount || elapsed >= effectiveTimeoutMs) {
                    finishCli(true, {
                        device_name: devName,
                        prompt: String(term.getPrompt() || ""),
                        mode: String(term.getMode() || ""),
                        raw_output: chunks.join(""),
                        command_statuses: statuses,
                        non_fatal_commands: nonFatalCommands,
                        more_pages_advanced: moreCount,
                        timed_out: !doneByCount && waitForPrompt
                    }, null);
                }
            } else if (elapsed >= effectiveTimeoutMs) {
                finishCli(false, { raw_output: rawNow }, "CLI execution timed out.");
            }
        } catch (err) {
            finishCli(false, {}, String(err));
        }
    };
    iv = setInterval(stepCli, 20);
    stepCli();
    } catch (eOuterCli) {
        try { sendBridgeResult(requestId, false, {}, String(eOuterCli)); } catch (eSend) {}
    }
}

function attachIpPhonePowerOnDevice(dev) {
    try {
    if (!dev) {
        return { ok: false, powered: false, error: "Null device handle" };
    }
    var beforePower = false;
    try { beforePower = Boolean(dev.getPower && dev.getPower()); } catch (e0) {}

    var suppList = [];
    try {
        if (typeof dev.getSupportedModule === "function") {
            var rawSupp = dev.getSupportedModule();
            if (rawSupp && typeof rawSupp.length === "number") {
                for (var si = 0; si < rawSupp.length; si++) {
                    suppList.push(String(rawSupp[si]));
                }
            }
        }
    } catch (eSupp) {}

    var adapterNames = ["IP_PHONE_POWER_ADAPTER", "IP-Phone-Power-Adapter"];
    for (var sj = 0; sj < suppList.length; sj++) {
        var sEntry = suppList[sj];
        if (sEntry.toLowerCase().indexOf("power") !== -1 || sEntry.toLowerCase().indexOf("adapter") !== -1) {
            var token = sEntry.split(",")[0].split(":")[0].split(" ")[0].replace(/^\s+|\s+$/g, "");
            if (token && adapterNames.indexOf(token) === -1) {
                adapterNames.unshift(token);
            }
        }
    }

    var rootMod = null;
    try { rootMod = dev.getRootModule ? dev.getRootModule() : null; } catch (eRm) {}
    var rootSlotPath = "";
    var slotCount = 0;
    if (rootMod) {
        try { if (typeof rootMod.getSlotPath === "function") { rootSlotPath = String(rootMod.getSlotPath() || ""); } } catch (eSp) {}
        try { if (typeof rootMod.getSlotCount === "function") { slotCount = Number(rootMod.getSlotCount()) || 0; } } catch (eSc) {}
    }

    var added = false;
    var methodUsed = "";
    for (var ai = 0; ai < adapterNames.length && !added; ai++) {
        var mName = adapterNames[ai];
        if (rootMod && typeof rootMod.addModuleAt === "function") {
            var maxIdx = Math.max(slotCount, 2);
            for (var idx = 0; idx <= maxIdx; idx++) {
                try {
                    if (rootMod.addModuleAt(mName, idx)) {
                        added = true;
                        methodUsed = "rootModule.addModuleAt(" + mName + "," + idx + ")";
                        break;
                    }
                } catch (eAma) {}
            }
        }
        if (!added && typeof dev.addModule === "function") {
            var slotCandidates = [];
            if (rootSlotPath) { slotCandidates.push(rootSlotPath); }
            slotCandidates.push("0", "0/0", "1/0", "0/1", "1", "");
            for (var ci = 0; ci < slotCandidates.length; ci++) {
                try {
                    if (dev.addModule(slotCandidates[ci], 11, mName)) {
                        added = true;
                        methodUsed = "device.addModule(" + slotCandidates[ci] + ",11," + mName + ")";
                        break;
                    }
                } catch (eAm) {}
            }
        }
    }

    try {
        if (typeof dev.setPower === "function") {
            dev.setPower(true);
        }
    } catch (ePwr) {}

    var afterPower = false;
    var afterModCount = 0;
    try { afterPower = Boolean(dev.getPower && dev.getPower()); } catch (eAp) {}
    try {
        if (rootMod && typeof rootMod.getModuleCount === "function") {
            afterModCount = Number(rootMod.getModuleCount()) || 0;
        }
    } catch (eMc) {}

    return {
        ok: true,
        powered: afterPower,
        before_power: beforePower,
        module_added: added,
        method_used: methodUsed,
        module_count: afterModCount,
        supported_modules: suppList
    };
    } catch (eOuterPhone) {
        return { ok: false, powered: false, error: String(eOuterPhone) };
    }
}

function attachRouterSerialModulesOnDevice(dev) {
    try {
    if (!dev) {
        return { ok: false, hwics_added: 0, serial_ports: [] };
    }
    var serialPorts = [];
    var pc = 0;
    try { pc = Number(dev.getPortCount()); } catch (ePc) {}
    for (var pi = 0; pi < pc; pi++) {
        try {
            var p = dev.getPortAt(pi);
            if (p) {
                var pName = String(p.getName() || "");
                if (pName.indexOf("Serial") === 0) {
                    serialPorts.push(pName);
                }
            }
        } catch (eGp) {}
    }
    if (serialPorts.length > 0) {
        return { ok: true, already_has_serial: true, hwics_added: 0, serial_ports: serialPorts };
    }

    var suppList = [];
    var hwicSupported = false;
    try {
        if (typeof dev.getSupportedModule === "function") {
            var rawSupp = dev.getSupportedModule();
            if (rawSupp && typeof rawSupp.length === "number") {
                for (var si = 0; si < rawSupp.length; si++) {
                    var entry = String(rawSupp[si]);
                    suppList.push(entry);
                    if (entry.indexOf("HWIC-2T") === 0) {
                        hwicSupported = true;
                    }
                }
            }
        }
    } catch (eSupp) {}

    if (!hwicSupported) {
        return { ok: true, hwics_added: 0, serial_ports: [], reason: "HWIC-2T not supported" };
    }

    var rootMod = null;
    try { rootMod = dev.getRootModule ? dev.getRootModule() : null; } catch (eRm) {}
    try { if (typeof dev.setPower === "function") { dev.setPower(false); } } catch (eOff) {}

    var hwicsAdded = 0;
    var methods = [];
    var targetSlots = [0, 1];
    var devSlotsByIdx = {
        0: ["0/0", "0"],
        1: ["0/1", "1"]
    };

    for (var ti = 0; ti < targetSlots.length; ti++) {
        var slotIdx = targetSlots[ti];
        var slotOk = false;
        if (rootMod && typeof rootMod.addModuleAt === "function") {
            try {
                if (rootMod.addModuleAt("HWIC-2T", slotIdx)) {
                    slotOk = true;
                    hwicsAdded += 1;
                    methods.push("rootModule.addModuleAt(HWIC-2T," + slotIdx + ")");
                }
            } catch (eAma) {}
        }
        if (!slotOk && typeof dev.addModule === "function") {
            var cands = devSlotsByIdx[slotIdx] || [String(slotIdx)];
            for (var ci = 0; ci < cands.length; ci++) {
                try {
                    if (dev.addModule(cands[ci], 2, "HWIC-2T")) {
                        slotOk = true;
                        hwicsAdded += 1;
                        methods.push("device.addModule(" + cands[ci] + ",2,HWIC-2T)");
                        break;
                    }
                } catch (eAm) {}
            }
        }
    }

    try { if (typeof dev.setPower === "function") { dev.setPower(true); } } catch (eOn) {}

    var afterSerial = [];
    var afterPc = 0;
    try { afterPc = Number(dev.getPortCount()); } catch (eApc) {}
    for (var api = 0; api < afterPc; api++) {
        try {
            var ap = dev.getPortAt(api);
            if (ap) {
                var apName = String(ap.getName() || "");
                if (apName.indexOf("Serial") === 0) {
                    afterSerial.push(apName);
                }
            }
        } catch (eAgp) {}
    }
    return {
        ok: true,
        hwics_added: hwicsAdded,
        methods_used: methods,
        serial_ports: afterSerial
    };
    } catch (eOuterSer) {
        return { ok: false, hwics_added: 0, serial_ports: [], error: String(eOuterSer) };
    }
}

function addDeviceSync(params) {
    try {
        var lw = ipc.appWindow().getActiveWorkspace().getLogicalWorkspace();
        var dTypeNum = Number(params.device_type || 0);
        var dModelStr = String(params.model || "");
        var px = Number(params.x || 100);
        var py = Number(params.y || 100);

        var candidates = [dModelStr];
        var fallbacksByType = {
            1: ["2960-24TT", "2950-24", "Switch-PT", ""],
            8: ["PC-PT", "PC", ""],
            9: ["Server-PT", "Server", ""],
            10: ["Printer-PT", "Printer", ""],
            17: ["Laptop-PT", "Laptop", ""],
            12: ["7960", "IP Phone", ""]
        };
        var extraCands = fallbacksByType[dTypeNum] || [];
        for (var ei = 0; ei < extraCands.length; ei++) {
            if (candidates.indexOf(extraCands[ei]) === -1) {
                candidates.push(extraCands[ei]);
            }
        }

        var name = "";
        var matchedModel = dModelStr;
        for (var ci = 0; ci < candidates.length; ci++) {
            try {
                var attemptName = lw.addDevice(dTypeNum, candidates[ci], px, py);
                if (attemptName) {
                    name = String(attemptName);
                    matchedModel = candidates[ci] || dModelStr;
                    break;
                }
            } catch (eAddCand) {}
        }
        if (!name) {
            return {
                ok: false,
                data: {},
                error: "addDevice returned empty name for model '" + dModelStr + "' (type=" + dTypeNum + ")"
            };
        }

        var addOut = {
            device_name: name,
            model: dModelStr,
            resolved_model: matchedModel,
            device_type: dTypeNum
        };
        var createdDev = null;
        try { createdDev = ipc.network().getDevice(name); } catch (eCd) {}
        if (params.auto_power !== false && (dTypeNum === 12 || dModelStr === "7960")) {
            try {
                var pwrInfo = attachIpPhonePowerOnDevice(createdDev);
                addOut.auto_powered = Boolean(pwrInfo.powered);
                addOut.power_details = pwrInfo;
            } catch (ePwrAdd) {
                addOut.auto_powered = false;
            }
        }
        if (params.auto_serial_modules !== false && dTypeNum === 0) {
            try {
                addOut.serial_modules = attachRouterSerialModulesOnDevice(createdDev);
            } catch (eSerAdd) {}
        }
        if (createdDev && params.display_name) {
            try {
                createdDev.setName(String(params.display_name));
                addOut.device_name = String(createdDev.getName() || name);
            } catch (eSetName) {}
        }
        return { ok: true, data: addOut, error: null };
    } catch (err) {
        return { ok: false, data: {}, error: "addDeviceSync exception: " + String(err) };
    }
}

function configureHostSync(params, aliasMap) {
    try {
        var rawName = String(params.device_name || "");
        var hDevName = (aliasMap && aliasMap[rawName]) ? aliasMap[rawName] : rawName;
        var hDev = ipc.network().getDevice(hDevName);
        if (!hDev) {
            return { ok: false, data: {}, error: "Device not found: " + hDevName };
        }
        var hPortName = String(params.port || "FastEthernet0");
        var hPort = null;
        try { hPort = hDev.getPort(hPortName); } catch (eGpH) {}
        if (!hPort) {
            try {
                if (hDev.getPortCount() > 0) {
                    hPort = hDev.getPortAt(0);
                }
            } catch (eGpH0) {}
        }
        if (!hPort) {
            return { ok: false, data: {}, error: "Host port not found: " + hPortName };
        }
        var useDhcp = Boolean(params.dhcp);
        try {
            if (typeof hPort.setDhcpClientFlag === "function") {
                hPort.setDhcpClientFlag(useDhcp);
            }
        } catch (eDhcp) {}
        var hIp = params.ip ? String(params.ip) : "";
        var hMask = params.subnet_mask ? String(params.subnet_mask) : "";
        if (!useDhcp && hIp && hMask && typeof hPort.setIpSubnetMask === "function") {
            hPort.setIpSubnetMask(hIp, hMask);
        }
        var hGw = params.default_gateway ? String(params.default_gateway) : "";
        if (hGw) {
            try {
                if (typeof hPort.setDefaultGateway === "function") {
                    hPort.setDefaultGateway(hGw);
                }
            } catch (eGw1) {}
            try {
                if (typeof hDev.setDefaultGateway === "function") {
                    hDev.setDefaultGateway(hGw);
                }
            } catch (eGw2) {}
        }
        if (params.display_name) {
            try { hDev.setName(String(params.display_name)); } catch (eDn) {}
        }
        return {
            ok: true,
            data: {
                device_name: String(hDev.getName() || hDevName),
                port: hPortName,
                dhcp: useDhcp,
                ip: hIp,
                subnet_mask: hMask,
                default_gateway: hGw
            },
            error: null
        };
    } catch (err) {
        return { ok: false, data: {}, error: "configureHostSync exception: " + String(err) };
    }
}

function createLinkSync(params, aliasMap) {
    try {
        var rawD1 = String(params.device1 || "");
        var rawD2 = String(params.device2 || "");
        var d1 = (aliasMap && aliasMap[rawD1]) ? aliasMap[rawD1] : rawD1;
        var d2 = (aliasMap && aliasMap[rawD2]) ? aliasMap[rawD2] : rawD2;
        var p1 = String(params.port1 || "");
        var p2 = String(params.port2 || "");
        var ctype = Number(params.conn_type || 8107);
        var lwl = ipc.appWindow().getActiveWorkspace().getLogicalWorkspace();
        var linked = Boolean(lwl.createLink(d1, p1, d2, p2, ctype));
        return {
            ok: linked,
            data: { linked: linked, device1: d1, port1: p1, device2: d2, port2: p2, conn_type: ctype },
            error: linked ? null : "createLink returned false"
        };
    } catch (err) {
        return { ok: false, data: {}, error: "createLinkSync exception: " + String(err) };
    }
}

function netforgeOnCommand(requestId, opcode, paramsJson) {
    try {
        var params = {};
        try { params = paramsJson ? JSON.parse(paramsJson) : {}; } catch (e) {}
        switch (opcode) {
            case "ping":
                sendBridgeResult(
                    requestId,
                    true,
                    {
                        pong: true,
                        bridge: "netforge_pts",
                        module_id: MODULE_ID,
                        ts: Date.now(),
                        dynamic_session_discovery: true,
                        has_hardcoded_session_file: Boolean(
                            SESSION_FILE && SESSION_FILE.indexOf("__") !== 0
                        )
                    },
                    null
                );
                return;
            case "add_device": {
                var addRes = addDeviceSync(params);
                sendBridgeResult(requestId, addRes.ok, addRes.data, addRes.error);
                return;
            }
            case "configure_host": {
                var hostRes = configureHostSync(params, null);
                sendBridgeResult(requestId, hostRes.ok, hostRes.data, hostRes.error);
                return;
            }
            case "create_link": {
                var linkRes = createLinkSync(params, null);
                sendBridgeResult(requestId, linkRes.ok, linkRes.data, linkRes.error);
                return;
            }
            case "batch_ops": {
                var ops = params.ops || [];
                var aliasMap = {};
                var results = [];
                for (var oi = 0; oi < ops.length; oi++) {
                    var item = ops[oi] || {};
                    var opName = String(item.op || "");
                    var opParams = item.params || {};
                    var itemRes = { ok: false, data: {}, error: "Unsupported batch op: " + opName };
                    if (opName === "add_device") {
                        itemRes = addDeviceSync(opParams);
                        if (itemRes.ok && item.alias && itemRes.data.device_name) {
                            aliasMap[String(item.alias)] = String(itemRes.data.device_name);
                        }
                    } else if (opName === "create_link") {
                        itemRes = createLinkSync(opParams, aliasMap);
                    } else if (opName === "configure_host") {
                        itemRes = configureHostSync(opParams, aliasMap);
                    } else if (opName === "attach_ip_phone_power") {
                        var pRaw = String(opParams.device_name || "");
                        var pTarget = aliasMap[pRaw] || pRaw;
                        var pDevObj = ipc.network().getDevice(pTarget);
                        if (!pDevObj) {
                            itemRes = { ok: false, data: {}, error: "Device not found: " + pTarget };
                        } else {
                            var pwrOut = attachIpPhonePowerOnDevice(pDevObj);
                            pwrOut.device_name = pTarget;
                            itemRes = { ok: true, data: pwrOut, error: null };
                        }
                    }
                    results.push({
                        index: oi,
                        op: opName,
                        alias: item.alias || null,
                        ok: Boolean(itemRes.ok),
                        data: itemRes.data || {},
                        error: itemRes.error || null
                    });
                }
                sendBridgeResult(requestId, true, { results: results, aliases: aliasMap }, null);
                return;
            }
            case "cli_exec":
                handleCliExec(requestId, params);
                return;
            case "get_activity_status": {
                var af = ipc.appWindow().getActiveFile();
                var isAct = typeof af.isActivityFile === "function" ? Boolean(af.isActivityFile()) : false;
                if (!isAct) {
                    sendBridgeResult(requestId, true, {
                        is_activity_file: false,
                        state: "not_activity",
                        readable: false,
                        fallback: "cli_verification",
                        leaves: []
                    }, null);
                    return;
                }
                try {
                    var pct = Number(af.getPercentageComplete());
                    if (isNaN(pct) || pct < 0) {
                        sendBridgeResult(requestId, true, {
                            is_activity_file: true,
                            state: "unavailable",
                            readable: false,
                            fallback: "cli_verification",
                            reason: "Activity completion score is unreadable or locked.",
                            leaves: []
                        }, null);
                        return;
                    }
                    var out = {
                        is_activity_file: true,
                        state: "available",
                        readable: true,
                        percentage_complete: pct,
                        percentage_complete_score: Number(af.getPercentageCompleteScore()),
                        items_count: Number(af.getAssessmentItemsCount()),
                        correct_items_count: Number(af.getCorrectAssessmentItemsCount()),
                        score_count: Number(af.getAssessmentScoreCount()),
                        correct_score_count: Number(af.getCorrectAssessmentScoreCount()),
                        leaves: []
                    };
                    var tree = af.getAssessedComparatorTree();
                    if (tree) {
                        walkTreeLeaves(tree, "", out.leaves);
                    }
                    sendBridgeResult(requestId, true, out, null);
                } catch (actErr) {
                    sendBridgeResult(requestId, true, {
                        is_activity_file: true,
                        state: "unavailable",
                        readable: false,
                        fallback: "cli_verification",
                        reason: String(actErr),
                        leaves: []
                    }, null);
                }
                return;
            }
            case "open_file": {
                var openPath = String(params.path || "");
                if (!openPath) {
                    sendBridgeResult(requestId, false, {}, "Missing path parameter.");
                    return;
                }
                ipc.appWindow().fileOpen(openPath);
                var openedFile = ipc.appWindow().getActiveFile();
                var savedFilename = "";
                try {
                    if (openedFile && typeof openedFile.getSavedFilename === "function") {
                        savedFilename = String(openedFile.getSavedFilename() || "");
                    }
                } catch (fnErr) {}
                sendBridgeResult(requestId, true, {
                    path: openPath,
                    saved_filename: savedFilename,
                    is_activity_file: Boolean(
                        openedFile && typeof openedFile.isActivityFile === "function" && openedFile.isActivityFile()
                    )
                }, null);
                return;
            }
            case "save_file": {
                var savePath = params.path ? String(params.path) : "";
                var overwrite = (params.overwrite !== false);
                var appWin = ipc.appWindow();
                if (savePath) {
                    try {
                        if (typeof appWin.fileSaveAsNoPrompt === "function") {
                            appWin.fileSaveAsNoPrompt(savePath, overwrite);
                        } else if (typeof appWin.fileSaveAs === "function") {
                            appWin.fileSaveAs(savePath);
                        } else {
                            appWin.fileSave();
                        }
                    } catch (saveErr) {
                        sendBridgeResult(requestId, false, {}, "fileSaveAs failed: " + String(saveErr));
                        return;
                    }
                } else {
                    try {
                        appWin.fileSave();
                    } catch (saveErr2) {
                        sendBridgeResult(requestId, false, {}, "fileSave failed: " + String(saveErr2));
                        return;
                    }
                }
                var curFile = appWin.getActiveFile();
                var curSavedFilename = "";
                try {
                    if (curFile && typeof curFile.getSavedFilename === "function") {
                        curSavedFilename = String(curFile.getSavedFilename() || "");
                    }
                } catch (fnErr2) {}
                sendBridgeResult(requestId, true, {
                    path: savePath || curSavedFilename,
                    saved_filename: curSavedFilename,
                    overwrite: overwrite
                }, null);
                return;
            }
            case "list_devices": {
                var net = ipc.network();
                var devCount = 0;
                try { devCount = Number(net.getDeviceCount()); } catch (eDc) {}
                var devices = [];
                var portMap = [];
                var links = [];
                var seenLinks = {};
                var typeNames = {
                    0: "router",
                    1: "switch",
                    2: "cloud",
                    3: "bridge",
                    4: "hub",
                    5: "repeater",
                    6: "coaxial_splitter",
                    7: "access_point",
                    8: "pc",
                    9: "server",
                    10: "printer",
                    11: "wireless_router",
                    12: "ip_phone",
                    13: "dsl_modem",
                    14: "cable_modem",
                    15: "remote_network",
                    16: "multilayer_switch",
                    17: "laptop",
                    18: "tablet",
                    19: "pda",
                    20: "wireless_end_device",
                    21: "wired_end_device",
                    22: "tv",
                    23: "home_voip",
                    24: "analog_phone",
                    26: "asa",
                    27: "ioe",
                    28: "home_gateway",
                    31: "access_point",
                    39: "wlc"
                };

                for (var i = 0; i < devCount; i++) {
                    var dev = null;
                    try { dev = net.getDeviceAt(i); } catch (eDa) {}
                    if (!dev) { continue; }
                    var dName = "";
                    var dModel = "";
                    var dType = -1;
                    try { dName = String(dev.getName() || ""); } catch (eDn) {}
                    try { dModel = String(dev.getModel() || ""); } catch (eDm) {}
                    try { dType = Number(dev.getType()); } catch (eDt) {}

                    var hostname = "";
                    var isIosCliDevice = (dType === 0 || dType === 1 || dType === 16 || dType === 26);
                    if (isIosCliDevice) {
                        try {
                            if (typeof dev.getHostName === "function") {
                                var directHn = String(dev.getHostName() || "").replace(/^\s+|\s+$/g, "");
                                if (directHn) {
                                    hostname = directHn;
                                }
                            }
                        } catch (eDhn) {}
                        if (!hostname) {
                            try {
                                var cmdLine = dev.getCommandLine();
                                if (cmdLine && typeof cmdLine.getPrompt === "function") {
                                    var pr = String(cmdLine.getPrompt() || "");
                                    if (pr && pr.indexOf("\\") === -1 && pr.indexOf("/") === -1) {
                                        hostname = pr.replace(/\([^)]*\)/g, "").replace(/[>#:]/g, "").replace(/^\s+|\s+$/g, "");
                                    }
                                }
                            } catch (eHn) {}
                        }
                    }

                    var portCount = 0;
                    try { portCount = Number(dev.getPortCount()); } catch (ePc) {}
                    var ports = [];
                    for (var j = 0; j < portCount; j++) {
                        var p = null;
                        try { p = dev.getPortAt(j); } catch (ePa) {}
                        if (!p) { continue; }
                        var pName = "";
                        var isUp = false;
                        var protoUp = false;
                        var mac = "";
                        var ipAddr = "";
                        var subMask = "";
                        var hasLink = false;
                        var remPort = "";
                        var remDev = "";

                        try { pName = String(p.getName() || ""); } catch (ePn) {}
                        try { isUp = Boolean(p.isPortUp && p.isPortUp()); } catch (ePu) {}
                        try { protoUp = Boolean(p.isProtocolUp && p.isProtocolUp()); } catch (ePru) {}
                        try { if (p.getMacAddress) { mac = String(p.getMacAddress() || ""); } } catch (eMac) {}
                        try {
                            if (typeof p.getIpAddress === "function") {
                                ipAddr = String(p.getIpAddress() || "");
                            }
                            if (typeof p.getSubnetMask === "function") {
                                subMask = String(p.getSubnetMask() || "");
                            }
                        } catch (eIp) {}
                        try {
                            var linkObj = p.getLink ? p.getLink() : null;
                            hasLink = Boolean(linkObj);
                            if (typeof p.getRemotePortName === "function") {
                                remPort = String(p.getRemotePortName() || "");
                            }
                            if (linkObj) {
                                var otherP = null;
                                if (typeof linkObj.getOtherPort === "function") {
                                    try { otherP = linkObj.getOtherPort(dName, pName); } catch (eOp1) {}
                                }
                                if (!otherP && typeof linkObj.getPort1 === "function" && typeof linkObj.getPort2 === "function") {
                                    var lp1 = linkObj.getPort1();
                                    var lp2 = linkObj.getPort2();
                                    var lp1Dev = (lp1 && typeof lp1.getOwnerDevice === "function" && lp1.getOwnerDevice())
                                        ? String(lp1.getOwnerDevice().getName() || "") : "";
                                    var lp1Name = lp1 ? String(lp1.getName() || "") : "";
                                    otherP = (lp1Dev === dName && lp1Name === pName) ? lp2 : lp1;
                                }
                                if (otherP) {
                                    if (!remPort && typeof otherP.getName === "function") {
                                        remPort = String(otherP.getName() || "");
                                    }
                                    if (typeof otherP.getOwnerDevice === "function" && otherP.getOwnerDevice()) {
                                        remDev = String(otherP.getOwnerDevice().getName() || "");
                                    }
                                }
                            }
                        } catch (eLnk) {}

                        var pInfo = {
                            name: pName,
                            ip_address: ipAddr,
                            subnet_mask: subMask,
                            port_up: isUp,
                            protocol_up: protoUp,
                            mac_address: mac,
                            has_link: hasLink,
                            remote_port_name: remPort,
                            remote_device_name: remDev
                        };
                        ports.push(pInfo);
                        if (hasLink && remDev && remPort) {
                            var pairKey = [dName + ":" + pName, remDev + ":" + remPort].sort().join("<->");
                            if (!seenLinks[pairKey]) {
                                seenLinks[pairKey] = true;
                                links.push({
                                    device1: dName,
                                    port1: pName,
                                    device2: remDev,
                                    port2: remPort
                                });
                            }
                        } else if (hasLink && remPort) {
                            portMap.push({
                                dev: dName,
                                port: pName,
                                rem_port: remPort,
                                portRef: pInfo
                            });
                        }
                    }

                    devices.push({
                        name: dName,
                        model: dModel,
                        type_code: dType,
                        type: typeNames[dType] || "other",
                        hostname: hostname || dName,
                        port_count: ports.length,
                        ports: ports
                    });
                }

                // Fallback cross-link peer resolution via rem_port match if needed
                for (var li = 0; li < portMap.length; li++) {
                    var src = portMap[li];
                    if (src.portRef.remote_device_name) { continue; }
                    for (var lj = li + 1; lj < portMap.length; lj++) {
                        var dst = portMap[lj];
                        if (src.dev !== dst.dev && src.rem_port === dst.port && dst.rem_port === src.port) {
                            src.portRef.remote_device_name = dst.dev;
                            dst.portRef.remote_device_name = src.dev;
                            var linkKey = [src.dev + ":" + src.port, dst.dev + ":" + dst.port].sort().join("<->");
                            if (!seenLinks[linkKey]) {
                                seenLinks[linkKey] = true;
                                links.push({
                                    device1: src.dev,
                                    port1: src.port,
                                    device2: dst.dev,
                                    port2: dst.port
                                });
                            }
                            break;
                        }
                    }
                }

                sendBridgeResult(requestId, true, {
                    device_count: devices.length,
                    link_count: links.length,
                    devices: devices,
                    links: links
                }, null);
                return;
            }
            case "attach_ip_phone_power": {
                var pwrDevName = String(params.device_name || "");
                var pwrDev = ipc.network().getDevice(pwrDevName);
                if (!pwrDev) {
                    sendBridgeResult(requestId, false, {}, "Device not found: " + pwrDevName);
                    return;
                }
                var pwrRes = attachIpPhonePowerOnDevice(pwrDev);
                pwrRes.device_name = pwrDevName;
                sendBridgeResult(requestId, true, pwrRes, null);
                return;
            }
            default:
                sendBridgeResult(requestId, false, {}, "Unsupported opcode: " + String(opcode));
                return;
        }
    } catch (err) {
        sendBridgeResult(requestId, false, {}, String(err));
    }
}

function main() {
    try {
        if (isStarted) {
            pollSessionDescriptor();
            return;
        }
        isStarted = true;
        isStopping = false;
        pollSessionDescriptor();
        if (sessionTimer === null) {
            sessionTimer = setInterval(pollSessionDescriptor, IDLE_POLL_INTERVAL_MS);
        }
    } catch (e) {}
}

function cleanUp() {
    try {
        if (isStopping) {
            return;
        }
        isStopping = true;
        isStarted = false;
        try {
            if (sessionTimer !== null) {
                clearInterval(sessionTimer);
                sessionTimer = null;
            }
        } catch (e1) {}
        destroyWebView();
        wvReady = false;
        activeConfigKey = "";
        activeCfg = null;
        failedPollCount = 0;
        missedDescriptorCount = 0;
        isStopping = false;
    } catch (e) {
        isStopping = false;
    }
}
