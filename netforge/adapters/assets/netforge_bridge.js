// NetForge Clean-Room Companion Script Module for Cisco Packet Tracer 8.2.2 (MIT License)
// Typed-opcode RPC dispatcher over headless WebView -> 127.0.0.1 HTTP + token auth.
var SESSION_FILE = "__NETFORGE_SESSION_FILE__";
var BRIDGE_WEBVIEW_TITLE = "NetForge Bridge";
var wv = null;
var wvReady = false;
var activeConfigKey = "";
var activeCfg = null;
var sessionTimer = null;
var isStarted = false;
var isStopping = false;

function normalizeSlashPath(p) {
    if (!p) { return ""; }
    var s = String(p).replace(/\\/g, "/");
    while (s.length > 1 && s.charAt(s.length - 1) === "/") {
        s = s.slice(0, -1);
    }
    return s;
}

function appendUniquePath(list, seen, candidate) {
    var norm = normalizeSlashPath(candidate);
    if (!norm || seen[norm]) { return; }
    seen[norm] = true;
    list.push(norm);
}

function resolveSessionCandidates() {
    var candidates = [];
    var seen = {};
    if (SESSION_FILE && SESSION_FILE.indexOf("__") !== 0) {
        appendUniquePath(candidates, seen, SESSION_FILE);
    }
    try {
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
    } catch (e) {}
    return candidates;
}

function readSessionConfig() {
    try {
        var fm = ipc.systemFileManager();
        var candidates = resolveSessionCandidates();
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
            if (parsed && typeof parsed.url === "string" && typeof parsed.token === "string") {
                return { url: parsed.url, token: parsed.token };
            }
        }
    } catch (e) {}
    return null;
}

function sendBridgeResult(requestId, ok, data, error) {
    if (!wv) { return; }
    var payload = {
        request_id: requestId,
        ok: Boolean(ok),
        data: data || {},
        error: error ? String(error) : null
    };
    try {
        wv.evaluateJavaScriptAsync("window.netforgePostResult(" + JSON.stringify(payload) + ");");
    } catch (e) {}
}

function applyConfigToWebView() {
    if (!isStarted || isStopping || !wv || !wvReady || !activeCfg) { return; }
    try {
        wv.evaluateJavaScriptAsync("window.netforgeStart(" + JSON.stringify(activeCfg) + ");");
    } catch (e) {}
}

function netforgeOnWebViewReady() {
    if (!isStarted || isStopping) { return; }
    wvReady = true;
    applyConfigToWebView();
}

function ensureWebView() {
    if (!isStarted || isStopping || wv) { return; }
    wvReady = false;
    wv = webViewManager.createWebView(BRIDGE_WEBVIEW_TITLE, "this-sm:bridge.html", 240, 100);
    wv.addAllowedExternalFilter("http://127.0.0.1*");
}

function pollSessionDescriptor() {
    if (!isStarted || isStopping) { return; }
    var next = readSessionConfig();
    if (!next) {
        return;
    }
    var key = next.url + "|" + next.token;
    if (key !== activeConfigKey) {
        activeConfigKey = key;
        activeCfg = next;
        ensureWebView();
        applyConfigToWebView();
    }
}

function walkTreeLeaves(node, prefix, leaves) {
    if (!node) { return; }
    var name = "";
    try { name = String(node.getNodeName()); } catch (e) {}
    var path = prefix ? (prefix + " > " + name) : name;
    var cc = 0;
    try { cc = node.getChildCount(); } catch (e) {}
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
}

function handleCliExec(requestId, params) {
    var devName = String(params.device_name || "");
    var commands = params.commands || [];
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

    var startedAt = Date.now();
    var iv = setInterval(function () {
        try {
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
                sent = true;
                nextIdx = 1;
                term.enterCommand(String(commands[0]));
                stage = "wait_done";
            } else if (stage === "wait_done") {
                // Send commands one at a time: queued keystrokes typed while a
                // --More-- pager is active get swallowed (observed: "ping" -> "ing").
                if (nextIdx < commands.length && statuses.length >= nextIdx
                    && !(rawNow.slice(-32).indexOf("--More--") !== -1)) {
                    term.enterCommand(String(commands[nextIdx]));
                    nextIdx += 1;
                }
                var tail = rawNow.slice(-32);
                var atMore = tail.indexOf("--More--") !== -1;
                if (atMore && rawNow.length !== lastMoreChunkLen) {
                    lastMoreChunkLen = rawNow.length;
                    moreCount += 1;
                    try { term.enterChar(32, 0); } catch (eMore) {}
                }
                var doneByCount = statuses.length >= commands.length && !atMore;
                if (!waitForPrompt || doneByCount || elapsed >= effectiveTimeoutMs) {
                    clearInterval(iv);
                    cleanupListeners();
                    sendBridgeResult(requestId, true, {
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
                clearInterval(iv);
                cleanupListeners();
                sendBridgeResult(requestId, false, { raw_output: rawNow }, "CLI execution timed out.");
            }
        } catch (err) {
            clearInterval(iv);
            cleanupListeners();
            sendBridgeResult(requestId, false, {}, String(err));
        }
    }, 100);
}

function netforgeOnCommand(requestId, opcode, paramsJson) {
    var params = {};
    try { params = paramsJson ? JSON.parse(paramsJson) : {}; } catch (e) {}

    try {
        switch (opcode) {
            case "ping":
                sendBridgeResult(
                    requestId,
                    true,
                    {
                        pong: true,
                        bridge: "netforge_pts",
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
                var lw = ipc.appWindow().getActiveWorkspace().getLogicalWorkspace();
                var name = lw.addDevice(
                    Number(params.device_type || 0),
                    String(params.model || ""),
                    Number(params.x || 100),
                    Number(params.y || 100)
                );
                if (!name) {
                    sendBridgeResult(requestId, false, {}, "addDevice returned empty name");
                    return;
                }
                sendBridgeResult(requestId, true, {
                    device_name: String(name),
                    model: String(params.model || ""),
                    device_type: Number(params.device_type || 0)
                }, null);
                return;
            }
            case "create_link": {
                var lwl = ipc.appWindow().getActiveWorkspace().getLogicalWorkspace();
                var linked = Boolean(lwl.createLink(
                    String(params.device1 || ""),
                    String(params.port1 || ""),
                    String(params.device2 || ""),
                    String(params.port2 || ""),
                    Number(params.conn_type || 8107)
                ));
                sendBridgeResult(requestId, linked, {
                    linked: linked,
                    device1: String(params.device1 || ""),
                    port1: String(params.port1 || ""),
                    device2: String(params.device2 || ""),
                    port2: String(params.port2 || ""),
                    conn_type: Number(params.conn_type || 8107)
                }, linked ? null : "createLink returned false");
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
            default:
                sendBridgeResult(requestId, false, {}, "Unsupported opcode: " + String(opcode));
                return;
        }
    } catch (err) {
        sendBridgeResult(requestId, false, {}, String(err));
    }
}

function main() {
    if (isStarted) {
        pollSessionDescriptor();
        return;
    }
    isStarted = true;
    isStopping = false;
    pollSessionDescriptor();
    if (sessionTimer === null) {
        sessionTimer = setInterval(pollSessionDescriptor, 1500);
    }
}

function cleanUp() {
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
    if (wv) {
        var oldWv = wv;
        wv = null;
        wvReady = false;
        try {
            if (typeof oldWv.close === "function") {
                oldWv.close();
            }
        } catch (e2) {}
    }
    wvReady = false;
    activeConfigKey = "";
    activeCfg = null;
    isStopping = false;
}
