"""
ChainMaker 区块链客户端 — 通过 cmc CLI 与长安链交互
支持指数退避重试与死信队列机制
"""
import os, json, subprocess, logging, re, time, base64

logger = logging.getLogger("chainmaker_client")

CMC_PATH = "/home/ljh/chainmaker-go/test/chain1/bin/cmc"
SDK_CONFIG = "/home/ljh/chainmaker-go/test/chain1/config/sdk_config.yml"
CHAIN_ID = "chain1"
CONTRACT_NAME = "fact"

# 死信队列文件路径（JSON Lines 格式）
DEAD_LETTER_QUEUE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data_store", "dead_letter_queue.json"
)

def _run_cmc(args, timeout=30):
    """执行 cmc 命令，返回标准化结果。

    改进点（P1.2）：
    - rc != 0 时始终返回失败
    - cmc 在某些错误场景下 rc=0 但 stdout 中包含 "Error:" 前缀，需检测
    - 增大可读取的输出长度，避免截断错误信息
    - 将原始 stdout/stderr 写入调试日志，便于排查
    """
    cmd = [CMC_PATH] + args
    logger.debug("cmc: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # 退出码非零 → 必然失败
        if result.returncode != 0:
            logger.error(
                "cmc failed (rc=%d) | cmd=%s | stderr=%s | stdout=%s",
                result.returncode, " ".join(args), stderr[:500], stdout[:500]
            )
            return {"success": False, "error": stderr or stdout or "cmc 返回非零退出码"}

        # 某些 cmc 子命令即使 rc=0，也会在 stdout 中输出 "Error:" 开头的信息
        if stdout and stdout.startswith("Error:"):
            logger.error("cmc returned error in stdout: %s", stdout[:500])
            return {"success": False, "error": stdout}

        # 尝试 JSON 解析
        if stdout:
            try:
                return {"success": True, "data": json.loads(stdout)}
            except json.JSONDecodeError:
                logger.debug("cmc stdout 非 JSON，当作原始文本返回: %s", stdout[:200])
                return {"success": True, "data": stdout}

        return {"success": True, "data": None}

    except subprocess.TimeoutExpired:
        logger.error("cmc timeout after %ds: %s", timeout, " ".join(args))
        return {"success": False, "error": "cmc 命令超时"}
    except FileNotFoundError:
        logger.error("cmc binary not found: %s", CMC_PATH)
        return {"success": False, "error": f"cmc 未找到: {CMC_PATH}"}
    except Exception as e:
        logger.error("cmc unexpected error: %s", str(e))
        return {"success": False, "error": str(e)}

def check_chain_status():
    result = _run_cmc([
        "query", "block-by-height", "0",
        f"--chain-id={CHAIN_ID}",
        f"--sdk-conf-path={SDK_CONFIG}",
    ])
    if result["success"] and isinstance(result.get("data"), dict):
        block = result["data"].get("block", {})
        header = block.get("header", {})
        # 创世区块可能没有 block_height 字段
        block_height = header.get("block_height")
        if block_height is None:
            block_height = 0
        return {
            "connected": True,
            "chain_id": header.get("chain_id", CHAIN_ID),
            "block_height": block_height,
            "block_hash": header.get("block_hash", "")[:24] if header.get("block_hash") else "",
        }
    return {"connected": False, "error": result.get("error", "无法连接链节点")}

def store_on_chain(data_did, fingerprint, commitment, signature, metadata_json):
    """将证据存入长安链 fact 合约"""
    evidence = {
        "data_did": data_did,
        "fingerprint": fingerprint,
        "commitment": commitment,
        "signature": signature,
        "metadata": metadata_json,
    }
    file_hash = fingerprint
    file_name = data_did
    file_content = json.dumps(evidence, ensure_ascii=False)

    logger.info("存储证据到链上: data_did=%s", data_did)

    # --params 格式: JSON 对象，不是数组
    params = json.dumps({
        "file_hash": file_hash,
        "file_name": file_name,
        "file_content": file_content,
    })

    result = _run_cmc([
        "client", "contract", "user", "invoke",
        f"--contract-name={CONTRACT_NAME}",
        "--method=save",
        f"--sdk-conf-path={SDK_CONFIG}",
        f"--chain-id={CHAIN_ID}",
        f"--params={params}",
        "--sync-result=true",
    ], timeout=60)

    if not result["success"]:
        return {"success": False, "error": result.get("error", "cmc 调用失败")}

    data = result.get("data", {})
    if isinstance(data, dict):
        tx_id = data.get("tx_id", "")
        block_height = data.get("tx_block_height")
    else:
        tx_id = ""
        block_height = None

    if not tx_id:
        return {"success": False, "error": f"无法获取 tx_id: {str(data)[:200]}"}

    return {
        "success": True,
        "tx_id": tx_id,
        "block_height": block_height,
        "contract": CONTRACT_NAME,
        "method": "save",
    }

def query_from_chain(data_did):
    """从链上查询证据 — 以 data_did（实际为 fingerprint）作为 file_hash 查询。

    返回格式：
        {"success": True, "evidence": {"file_hash":..., "file_name":..., "time":...}, "on_chain": True}
        {"success": False, "error": "..."}

    健壮性改进（P2.2）：
    - 对 cmc 返回的多种格式做兼容解析
    - 记录原始 cmc 输出到日志，便于排查
    - 处理合约层级的错误码
    """
    params = json.dumps({"file_hash": data_did})
    result = _run_cmc([
        "client", "contract", "user", "get",
        f"--contract-name={CONTRACT_NAME}",
        "--method=find_by_file_hash",
        f"--sdk-conf-path={SDK_CONFIG}",
        f"--chain-id={CHAIN_ID}",
        f"--params={params}",
    ], timeout=30)

    if not result["success"]:
        logger.error("query_from_chain cmc 失败: data_did=%s, error=%s", data_did, result.get("error"))
        return {"success": False, "error": result.get("error", "cmc 查询失败")}

    data = result.get("data", {})
    if not isinstance(data, dict):
        logger.warning("query_from_chain 返回非预期格式: type=%s", type(data).__name__)
        return {"success": True, "evidence": {}, "on_chain": False,
                "_raw": str(data)[:500]}

    # 检查交易级别的错误码
    tx_code = data.get("code")
    tx_msg = data.get("message", "")

    cr = data.get("contract_result", {})
    if not isinstance(cr, dict):
        logger.warning("query_from_chain contract_result 缺失或非 dict: %s", str(cr)[:200])
        return {"success": True, "evidence": {}, "on_chain": False}

    # 检查合约执行错误码
    contract_code = cr.get("code", 0)

    raw = cr.get("result", "")
    if raw:
        # 链上合约返回的 result 是 base64 编码的 JSON
        try:
            decoded = base64.b64decode(raw).decode('utf-8')
            parsed = json.loads(decoded)
            logger.debug("query_from_chain success: data_did=%s, chain_fp=%s",
                        data_did, parsed.get("file_hash", "")[:30])
            return {"success": True, "evidence": parsed, "on_chain": True}
        except Exception as e:
            logger.warning("query_from_chain base64 解码失败: %s, raw[:100]=%s", e, raw[:100])
            # 尝试直接 JSON 解析
            try:
                parsed = json.loads(raw)
                return {"success": True, "evidence": parsed, "on_chain": True}
            except (json.JSONDecodeError, TypeError):
                logger.warning("query_from_chain 无法解析合约返回: raw[:200]=%s", raw[:200])

    # 没有 result 字段 — 可能是合约报错或数据不存在
    if contract_code and contract_code > 0:
        err_detail = cr.get("message", "合约执行异常")
        logger.warning("query_from_chain 合约级错误 code=%s: %s", contract_code, err_detail[:300])
        return {"success": False, "error": f"合约查询失败: {err_detail[:200]}"}

    if tx_code and tx_code > 0:
        logger.warning("query_from_chain 交易级错误 code=%s: %s", tx_code, tx_msg[:300])
        return {"success": False, "error": f"链上查询失败: {tx_msg[:200]}"}

    # 查询成功但无结果（数据确实不在链上）
    logger.info("query_from_chain 无结果: data_did=%s", data_did)
    return {"success": True, "evidence": {}, "on_chain": True}

def verify_against_chain(data_did, expected_fingerprint, expected_commitment, chain_tx_id=None):
    """
    将链上存证与本地数据对比验证（改进版）

    修复说明：
    - 新增 chain_tx_id 参数，优先判断记录是否真正完成过上链
    - 未上链的记录（chain_tx_id 为空）直接返回 not_stored，
      避免用本地指纹去链上做无意义查询后显示"已存证"的误导
    - 查询失败时返回 query_failed，便于前端区分"未上链"和"链服务不可用"
    - 只有链上实际查到且指纹/承诺一致时才返回 verified

    返回 status 枚举：
        not_stored  — 该记录从未成功上链
        query_failed — 链服务查询失败（超时/网络错误等）
        mismatch    — 链上数据与本地不一致
        verified    — 链上存证一致
    """
    # ── 前置检查：记录是否完成过链上存证 ──
    if not chain_tx_id:
        logger.info("链上验证跳过：data_did=%s 无交易ID，未完成链上存证", data_did)
        return {
            "verified": False,
            "on_chain": False,
            "status": "not_stored",
            "reason": "该记录未完成链上存证（无交易ID）",
            "fingerprint_match": None,
            "commitment_match": None,
            "tx_id": "",
            "error": "",
            "details": {
                "chain_fingerprint": "",
                "chain_data_did": "",
            },
        }

    # ── 有 chain_tx_id，执行链上查询 ──
    query_result = query_from_chain(expected_fingerprint)

    if not query_result["success"]:
        logger.warning("链上查询失败：data_did=%s, error=%s", data_did, query_result.get("error"))
        return {
            "verified": False,
            "on_chain": False,
            "status": "query_failed",
            "reason": "链上查询失败，无法验证",
            "fingerprint_match": None,
            "commitment_match": None,
            "tx_id": chain_tx_id,
            "error": query_result.get("error", "链上查询失败"),
            "details": {
                "chain_fingerprint": "",
                "chain_data_did": "",
            },
        }

    # ── 解析链上证据，比对指纹 ──
    # 注意：链上合约 find_by_file_hash 返回的字段是：
    #   {"file_hash": "563b...", "file_name": "did:trust:...", "time": ""}
    # 其中 file_hash 对应本地 fingerprint，file_name 对应本地 data_did
    # 链上不存储 commitment，因此只需比对 file_hash == expected_fingerprint
    evidence = query_result.get("evidence") or {}
    chain_fp = ""
    chain_did = ""
    if isinstance(evidence, dict):
        chain_fp = evidence.get("file_hash", "")
        chain_did = evidence.get("file_name", "")

    # file_hash 与本地指纹比对
    fp_match = (chain_fp == expected_fingerprint) if chain_fp else False
    # file_name 与本地 data_did 比对（辅助校验）
    did_match = (chain_did == data_did) if chain_did else False
    # 指纹匹配即认为链上存证一致（链上不存储 commitment）
    verified = fp_match

    if verified:
        logger.info("链上验证通过：data_did=%s, fp_match=%s", data_did, fp_match)
    else:
        logger.warning(
            "链上验证不一致：data_did=%s, fp_match=%s, did_match=%s, chain_fp=%s",
            data_did, fp_match, did_match, chain_fp
        )

    return {
        "verified": verified,
        "on_chain": True,
        "status": "verified" if verified else "mismatch",
        "reason": "链上存证一致" if verified else "链上数据与本地记录不一致",
        "fingerprint_match": fp_match,
        "commitment_match": None,  # 链上不存储 commitment，无法比对
        "tx_id": chain_tx_id,
        "error": "",
        "details": {
            "chain_fingerprint": chain_fp,
            "chain_data_did": chain_did,
        },
    }


# ========== 指数退避重试与死信队列 ==========

def store_on_chain_with_retry(data_did, fingerprint, commitment, signature,
                              metadata_json="", max_retries=3, backoff_base=2):
    """
    带指数退避重试的链上存证函数。

    重试策略：第1次立即执行，第2次等待2秒，第3次等待4秒。
    全部失败后将任务写入死信队列文件，以便后续批量重试。

    参数:
        data_did: 数据资产DID
        fingerprint: 数据指纹
        commitment: Pedersen承诺
        signature: 签名
        metadata_json: 元数据JSON字符串
        max_retries: 最大重试次数（默认3次）
        backoff_base: 退避基数（默认2秒）

    返回:
        成功时返回 store_on_chain 的正常结果
        全部失败时返回 {"tx_id": None, "status": "pending_retry", "attempts": max_retries}
    """
    last_error = ""

    for attempt in range(1, max_retries + 1):
        # 指数退避：第1次立即执行，之后等待 backoff_base^(attempt-1) 秒
        if attempt > 1:
            wait_time = backoff_base ** (attempt - 1)
            logger.warning(
                "链上存证重试第 %d/%d 次，等待 %d 秒后重试 (data_did=%s)",
                attempt, max_retries, wait_time, data_did
            )
            time.sleep(wait_time)

        result = store_on_chain(data_did, fingerprint, commitment, signature, metadata_json)

        if result.get("success"):
            if attempt > 1:
                logger.info("链上存证第 %d 次重试成功 (data_did=%s)", attempt, data_did)
            return result

        last_error = result.get("error", "未知错误")
        logger.warning(
            "链上存证第 %d/%d 次失败: %s (data_did=%s)",
            attempt, max_retries, last_error, data_did
        )

    # 全部重试失败，写入死信队列
    dead_letter = {
        "data_did": data_did,
        "fingerprint": fingerprint,
        "commitment": commitment,
        "signature": signature,
        "metadata_json": metadata_json,
        "last_error": last_error,
        "attempts": max_retries,
        "timestamp": time.time(),
        "status": "pending_retry",
    }
    _write_dead_letter(dead_letter)

    logger.error(
        "链上存证全部 %d 次重试失败，已写入死信队列 (data_did=%s)", max_retries, data_did
    )

    return {"tx_id": None, "status": "pending_retry", "attempts": max_retries}


def _write_dead_letter(entry):
    """将失败任务追加写入死信队列文件（JSON Lines 格式）"""
    os.makedirs(os.path.dirname(DEAD_LETTER_QUEUE_PATH), exist_ok=True)
    with open(DEAD_LETTER_QUEUE_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def retry_dead_letters():
    """
    读取死信队列文件，逐条重试链上存证。

    成功的任务从队列移除，失败的保留。
    返回重试结果统计。

    返回:
        {
            "total": 总条数,
            "succeeded": 成功条数,
            "failed": 失败条数,
            "results": [每条重试的详细结果]
        }
    """
    if not os.path.exists(DEAD_LETTER_QUEUE_PATH):
        return {"total": 0, "succeeded": 0, "failed": 0, "results": []}

    # 读取所有死信条目
    entries = []
    with open(DEAD_LETTER_QUEUE_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("死信队列中存在无法解析的行，已跳过")

    if not entries:
        return {"total": 0, "succeeded": 0, "failed": 0, "results": []}

    succeeded = 0
    failed_entries = []
    results = []

    for entry in entries:
        data_did = entry.get("data_did", "")
        fingerprint = entry.get("fingerprint", "")
        commitment = entry.get("commitment", "")
        signature = entry.get("signature", "")
        metadata_json = entry.get("metadata_json", "")

        result = store_on_chain(data_did, fingerprint, commitment, signature, metadata_json)

        if result.get("success"):
            succeeded += 1
            results.append({"data_did": data_did, "status": "success", "tx_id": result.get("tx_id")})
            logger.info("死信队列重试成功: data_did=%s", data_did)
        else:
            # 重试失败，更新尝试次数并保留
            entry["attempts"] = entry.get("attempts", 0) + 1
            entry["last_error"] = result.get("error", "未知错误")
            entry["timestamp"] = time.time()
            failed_entries.append(entry)
            results.append({"data_did": data_did, "status": "failed", "error": result.get("error")})
            logger.warning("死信队列重试失败: data_did=%s, error=%s", data_did, result.get("error"))

    # 重写死信队列文件（仅保留失败的条目）
    with open(DEAD_LETTER_QUEUE_PATH, "w", encoding="utf-8") as f:
        for entry in failed_entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return {
        "total": len(entries),
        "succeeded": succeeded,
        "failed": len(failed_entries),
        "results": results,
    }


