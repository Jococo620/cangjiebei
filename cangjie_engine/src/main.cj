package cangjie_engine

import std.net.*
import std.collection.*

func atoi(s: String): Int64 {
    var n: Int64 = 0
    for (b in s) {
        if (b >= 48 && b <= 57) {
            n = n * 10 + (Int64(b) - 48)
        }
    }
    return n
}

func nodeCost(toolId: String): Int64 {
    let t = toolId.toAsciiLower()
    if (t.contains("scan") || t.contains("recon") || t.contains("discover")) { return 20 }
    if (t.contains("analysis") || t.contains("triage") || t.contains("classify") || t.contains("audit")) { return 15 }
    if (t.contains("query") || t.contains("lookup") || t.contains("retrieve") || t.contains("search")) { return 5 }
    if (t.contains("action") || t.contains("contain") || t.contains("block") || t.contains("isolate")) { return 10 }
    return 10
}

func toolOf(ids: ArrayList<String>, tools: ArrayList<String>, id: String): String {
    for (i in 0..ids.size) {
        if (ids[i] == id) { return tools[i] }
    }
    return ""
}

func planDag(body: String): String {
    let ids = ArrayList<String>()
    let tools = ArrayList<String>()
    let adj = HashMap<String, ArrayList<String>>()
    let indeg = HashMap<String, Int64>()

    for (raw in body.split("\n")) {
        let line = raw.trimAscii()
        if (line.size < 3) { continue }
        let parts = line.split("|")
        if (parts.size < 2) { continue }
        let kind = parts[0].trimAscii()
        if (kind == "NODE" && parts.size >= 3) {
            let id = parts[1].trimAscii()
            let tool = parts[2].trimAscii()
            ids.add(id)
            tools.add(tool)
            adj[id] = ArrayList<String>()
            indeg[id] = 0
        } else if (kind == "EDGE" && parts.size >= 3) {
            let a = parts[1].trimAscii()
            let b = parts[2].trimAscii()
            if (adj.contains(a) && adj.contains(b)) {
                match (adj.get(a)) {
                    case Some(lst) => lst.add(b)
                    case None => ()
                }
                match (indeg.get(b)) {
                    case Some(v) => indeg[b] = v + 1
                    case None => ()
                }
            }
        }
    }

    if (ids.size == 0) { return "ERR|no nodes" }

    let remaining = HashMap<String, Bool>()
    for (id in ids) { remaining[id] = true }

    var out = "OK"
    var guard = 0
    while (remaining.size > 0 && guard < ids.size + 5) {
        guard = guard + 1
        let level = ArrayList<String>()
        for (id in ids) {
            if (remaining.contains(id)) {
                match (indeg.get(id)) {
                    case Some(v) => if (v == 0) { level.add(id) }
                    case None => ()
                }
            }
        }
        if (level.size == 0) { return "ERR|cycle detected" }

        for (i in 0..level.size) {
            for (j in i + 1..level.size) {
                let a = level[i]
                let b = level[j]
                let ca = nodeCost(toolOf(ids, tools, a))
                let cb = nodeCost(toolOf(ids, tools, b))
                if (cb < ca) {
                    level[i] = b
                    level[j] = a
                }
            }
        }

        var row = "LEVEL"
        for (id in level) { row = row + "|" + id }
        out = out + "\n" + row

        for (id in level) {
            remaining.remove(id)
            match (adj.get(id)) {
                case Some(lst) =>
                    for (nx in lst) {
                        match (indeg.get(nx)) {
                            case Some(v) => indeg[nx] = v - 1
                            case None => ()
                        }
                    }
                case None => ()
            }
        }
    }

    for (i in 0..ids.size) {
        let id = ids[i]
        out = out + "\nCOST|${id}|${nodeCost(tools[i])}"
    }
    return out
}

// 安全策略决策核：由仓颉承担处置放行/风险分级决策。
// 返回三态 Verdict：
//   ALLOW                 —— 放行（低危/中危，或已审批的高危）
//   DENY|<reason>         —— 拒绝（预算耗尽 / 越界 / 未知工具）
//   NEED_APPROVAL|<reason> —— 需要人工审批（致命动作 / 未审批的高危）

func isCriticalTool(tool: String): Bool {
    return tool == "safe_firewall_ban" || tool == "edr_client.micro_isolate"
}

func isHighRiskTool(tool: String): Bool {
    return tool == "agentic_repair" || tool == "plan_case_reproduce"
        || tool == "edr_isolation" || tool == "firewall_block"
}

func isMediumRiskTool(tool: String): Bool {
    return tool == "sympas_dynamic_slice" || tool == "generate_mr"
        || tool == "eval_patch_taint" || tool == "reproduce_fault"
        || tool == "plan_quality_gate" || tool == "patch_safety_verifier"
        || tool == "skill_doc_generator" || tool == "four_layer_demo"
}

func isLowRiskTool(tool: String): Bool {
    return tool == "code_scan" || tool == "sympas_slice" || tool == "sympas_slice_table"
        || tool == "cwe_classifier" || tool == "taint_path_explainer"
        || tool == "sbfl_rank" || tool == "reachability_query"
        || tool == "vkb_retrieve" || tool == "ast_symbol_extractor"
        || tool == "sympas-hv" || tool == "sca_cve_scanner"
        || tool == "dep_cluster" || tool == "sympas_dep_graph"
        || tool == "uafr_report" || tool == "start_scan"
        || tool == "sarif_textual_export" || tool == "slice_diff"
        || tool == "repair_prompt_bundle" || tool == "agent_context"
        || tool == "traffic_hunt.pcap_analyze" || tool == "ticket_im.notify_dispatch"
}

func decide(tool: String, scopeAllowed: Bool, approvalValid: Bool, remainingMs: Int64): String {
    if (remainingMs <= 0) {
        return "DENY|BUDGET_EXHAUSTED"
    }
    if (!scopeAllowed) {
        return "DENY|OUT_OF_SCOPE"
    }
    if (isCriticalTool(tool)) {
        return "NEED_APPROVAL|CRITICAL_ACTION"
    }
    if (isHighRiskTool(tool)) {
        if (approvalValid) {
            return "ALLOW"
        } else {
            return "NEED_APPROVAL|HIGH_RISK_REVIEW"
        }
    }
    if (isMediumRiskTool(tool) || isLowRiskTool(tool)) {
        return "ALLOW"
    }
    return "DENY|UNKNOWN_TOOL"
}

// 解析 /policy/decide 的请求体：tool|scopeAllowed|approvalValid|remainingMs
func decideFromBody(body: String): String {
    let parts = body.split("|")
    if (parts.size < 4) {
        return "DENY|MALFORMED_REQUEST"
    }
    let tool = parts[0].trimAscii()
    let scopeAllowed = parts[1].trimAscii() == "true"
    let approvalValid = parts[2].trimAscii() == "true"
    let remainingMs = atoi(parts[3].trimAscii())
    return decide(tool, scopeAllowed, approvalValid, remainingMs)
}

func handle(path: String, body: String): (Int64, String, String) {
    if (path == "/health") {
        return (200, "application/json", "{\"status\":\"ok\",\"engine\":\"cangjie\",\"version\":\"1.3.0\"}")
    }
    if (path == "/dag/plan") {
        return (200, "text/plain", planDag(body))
    }
    if (path == "/policy/decide") {
        return (200, "text/plain", decideFromBody(body))
    }
    return (404, "text/plain", "not found")
}

func respond(client: TcpSocket, status: Int64, ctype: String, payload: String): Unit {
    let reason = if (status == 200) { "OK" } else { "Not Found" }
    let pb = unsafe { payload.rawData() }
    let text = "HTTP/1.1 ${status} ${reason}\r\nContent-Type: ${ctype};charset=UTF-8\r\nContent-Length: ${pb.size}\r\nConnection: close\r\n\r\n"
    let hb = unsafe { text.rawData() }
    client.write(hb)
    client.write(pb)
}

main(): Int64 {
    let port: UInt16 = 2270
    let server = TcpServerSocket(bindAt: port)
    server.bind()
    println("CangSight cangjie engine listening on 127.0.0.1:${port}")

    while (true) {
        try {
            let client = server.accept()
            try {
                let acc = ArrayList<Byte>()
                let tmp = Array<Byte>(4096, { item => UInt8(0) })
                var headerEnd = -1
                var contentLength = 0
                var body = ""
                var finished = false
                while (!finished) {
                    let n = client.read(tmp)
                    if (n <= 0) { break }
                    for (k in 0..n) { acc.add(tmp[k]) }
                    let cur = String.fromUtf8(acc.toArray())
                    let segs = cur.split("\r\n\r\n")
                    if (segs.size >= 2) {
                        let head = segs[0]
                        headerEnd = head.size
                        for (h in head.split("\r\n")) {
                            let hl = h.trimAscii().toAsciiLower()
                            if (hl.startsWith("content-length:")) {
                                contentLength = atoi(hl.replace("content-length:", "").trimAscii())
                            }
                        }
                        if (segs.size > 1) { body = segs[1] }
                        let have = cur.size - (headerEnd + 4)
                        if (have >= contentLength) { finished = true }
                    }
                }

                let all = String.fromUtf8(acc.toArray())
                var path = "/"
                let firstLine = all.split("\r\n")[0]
                let rq = firstLine.split(" ")
                if (rq.size >= 2) { path = rq[1] }
                let (st, ct, pl) = handle(path, body)
                respond(client, st, ct, pl)
            } catch (e: Exception) {
                println("handler error: ${e.message}")
            }
            client.close()
        } catch (e: Exception) {
            println("accept error: ${e.message}")
        }
    }
    return 0
}
