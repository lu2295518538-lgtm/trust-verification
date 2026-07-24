"""
app.py 的链上存证补丁 — 在 submit 和 verify 中插入长安链调用
将此文件中的代码块合并到 app.py 中即可
"""

# ===== 在 app.py 顶部 import 区域添加 =====
# from core.chainmaker_client import store_on_chain, query_from_chain, verify_against_chain

# ===== submit_data() 函数末尾，db commit 之后，return 之前插入 =====
#     # ── 长安链存证 ──
#     chain_result = store_on_chain(
#         data_did=data_did,
#         commitment=commitment_result["commitment"],
#         fingerprint=fp_result["fingerprint"],
#         owner_did=OWNER_DID,
#         timestamp=ts,
#     )
#     # 链上存证结果附加到返回中
#     result["chain_tx"] = chain_result

# ===== verify_data() 函数中，在获取 rec 之后插入 =====
#     # ── 长安链验证 ──
#     chain_check = verify_against_chain(data_did, rec["commitment"])
#     
#     # 在返回的 results 中增加
#     results["chain_verified"] = chain_check.get("match", False)
