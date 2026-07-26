# 更新日志 (CHANGELOG)

## 2026-07-26 — 清理多余测试与临时文件

本次提交移除了仓库中的测试脚本与临时演示页面，**仅保留项目核心运作模块**，
使仓库结构更聚焦于生产级代码。

### 删除的文件

#### 测试脚本（9 个）
| 文件 | 类型 | 说明 |
|------|------|------|
| `smoke_test.py` | 冒烟测试 | 端到端冒烟测试，验收阶段使用 |
| `test_did_namespace.py` | 单元测试 | DID 命名空间一致性测试 |
| `test_external_ca.py` | 单元测试 | 外部 CA 联邦接入测试 |
| `test_mobile_issue.py` | 单元测试 | 移动端现场出证测试 |
| `test_party_binding.py` | 单元测试 | 主体双向绑定测试 |
| `test_trace_risk.py` | 单元测试 | 状态机风险追溯测试 |
| `test_trace_viz.py` | 单元测试 | 业务时间轴/地理流向可视化测试 |
| `test_vc_vp_zkp.py` | 单元测试 | VC/VP + Pedersen ZKP 构造法测试 |
| `test_zkp_minimal.py` | 单元测试 | ZKP 最小可运行样例测试 |

#### 临时演示页面（2 个）
| 文件 | 说明 |
|------|------|
| `templates/jstest.html` | JS 运行检测测试页（非业务页面） |
| `templates/fresh.html` | 早期方案展示页（与核心运作无关，核心前端为 `index.html` 与 `mobile/index.html`） |

### 保留的核心运作模块

- **后端**：`app.py`（主 Flask 服务）、`app_chainmaker.py`（长安链接入）、`config.py`
- **核心库** `core/`：`did_manager.py`、`vc_manager.py`、`pedersen_zkp.py`、
  `pedersen.py`、`sm2_sign.py`、`fingerprint.py`、`ecc_hamming.py`、
  `watermark_dft.py`、`phfrfm_core.py`、`issuer_ca.py`、`metadata_extractor.py`、
  `chainmaker_client.py`
- **前端**：`templates/index.html`（主页面）、`templates/mobile/index.html`（移动端）
- **工具/文档**：`query_records.py`（记录查询工具）、`docs/`、`README.md`、
  `README_DEPLOY.md`、`.env.example`、`requirements.txt`、`.gitignore`

### 备注
测试脚本此前用于验收与回归验证，已确认核心功能稳定后移出仓库。
如后续需要恢复测试能力，可从历史提交中检出对应文件。
