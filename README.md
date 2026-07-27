# Trust Verification System (畜牧检疫数据可信验证平台)

基于长安链 (ChainMaker) 的畜牧检疫数据全生命周期可信验证系统，集成 SM2 签名、Pedersen 承诺、可验证凭证 (VC)、以及 PHFRFM 零水印 / DFT 隐水印技术。

## 功能模块

### 1. 数据上链与存证
- 原始检疫数据 (GBT 39915-2021 格式) 提交
- SM3 指纹生成 → Pedersen 承诺 → SM2 签名 → 长安链上链
- 返回 data_did、chain_tx_id、block_height

### 2. 四重验证
- SM3 指纹校验
- Pedersen 承诺校验 (零知识证明)
- SM2 签名校验 (国密算法)
- 长安链链上一致性校验（无 tx_id 时正确返回 `not_stored`，不误报）

### 3. 隐水印 (版权保护 + 溯源)
- **PHFRFM 零水印** (极谐波分数傅里叶矩)
  - 完全无损 (PSNR=100dB)
  - 抗 JPEG 压缩、裁剪、旋转、缩放、噪声、**微信转发二次截图**
  - 真实照片流转、含重度缩放场景默认用此模式
- **DFT 频域水印** + Hamming(7,4) ECC
  - 径向归一化（`_radial_baseline`）抵消真实照片非平坦频谱
  - 反向旋转 + 反向缩放几何补偿（提取前）
  - 嵌入强度 / 系数数随图尺寸自适应（保持能量恒定）
  - 自定义攻击强度（裁剪 / 旋转 / JPEG / 缩放 / 噪声，独立开关）
  - 抗旋转 / 裁剪 / JPEG / 噪声 / ≤70% 缩放；50% 重缩放为信息论极限（此时用 PHFRFM）
- **双副本同步攻击**：攻击同时施加于灰度数组（提取用）与彩色副本（展示用）
- **上传验证**：支持用户上传自处理图片 + 期望 DID 验证（微信转发真实场景）

### 4. 可验证凭证 (VC / VP) + 签发者目录 / CA 联邦
- VC 颁发（DID-based，三元组哈希 + P-256 Pedersen + Schnorr ZKP）
- VP 构造与选择性披露验证
- 本地 PKI 信任锚（`issuer_ca.py`）+ 外部 CA 联邦
- 主体 DID 强绑定（`resolve_party_ca_link`）+ 吊销 / 恢复
- `verify_issuer` 公钥一致性校验（防 VC 内嵌公钥与注册表不符）

### 5. 存证记录 / 业务追溯 / 运输管理
- 记录分页与批量查询（`/api/records`）
- 状态机时间轴 + SLA 超时 + 中国地理流向可视化（`/api/records/trace`）
- 运输登记与台账（复用同一组 API 的前端视图）

### 6. 移动端（现场端）
- 路由 `/m`，模板 `templates/mobile/index.html`
- 双 Tab：**现场出证**（扫码关联 → GPS 取证 → 检疫信息 → 出证）、**现场核验**（扫码 / 粘贴 JSON / 批次全链路状态机 + 风险预警）
- 复用同一可信后端（`securePost` 自动带 API Key + CSRF）
- 依赖第三方 JS：`/static/js/jsQR.js`、`/static/js/qrcode.js`（见 `static/js/README.md`）

### 7. VM 终端查询工具
```bash
python3 query_records.py --stats    # 统计
python3 query_records.py --latest   # 最新
python3 query_records.py --id 42    # 按 ID
python3 query_records.py --all      # 全部
python3 query_records.py --limit 20 # 最近 N 条
```

## 部署

### 环境要求
- Python 3.10+
- 长安链 ChainMaker（当前为测试网 `chain1`；生产需替换为多组织联盟链）
- Pillow, NumPy, SciPy, gmssl, pycryptodome, ecdsa, Flask

### 安装
```bash
cd trust_verification
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 配置（环境变量，生产必填）
- `CMC_PATH` / `SDK_CONFIG_PATH` / `CHAIN_ID`：指向实际链节点 SDK 配置
- `FLASK_SECRET_KEY` / `TRUST_API_KEY`：生产环境强制设置
- `DB_PATH`：本地索引库路径（默认 `data_store/chain.db`）

### 启动
```bash
# 开发模式
python3 app.py
# 默认监听 0.0.0.0:5000（可被外部访问，注意防火墙）
```

## 技术栈

| 层 | 技术 |
|---|------|
| 区块链 | 长安链 ChainMaker (chain1) |
| 签名 | SM2 (国密) |
| 哈希 | SM3 (国密) |
| 承诺 | Pedersen Commitments |
| 身份 | W3C DID + Schnorr ZKP |
| 水印 | PHFRFM 零水印 / DFT 隐水印 |
| ECC | Hamming(7,4) |
| 后台 | Flask + Jinja2 |
| 前端 | Vanilla JS（桌面 `templates/index.html` / 移动 `templates/mobile/index.html`） |
| 数据库 | SQLite (本地索引) + 长安链 (链上锚点) |

## 生产就绪状态（重要）

当前代码**密码学正确、链交互真实**，但部署拓扑为**单机测试链 + 本地 SQLite**，并非生产级。详见 **[docs/生产就绪差距分析.md](docs/生产就绪差距分析.md)** —— 投产前需：换多组织联盟链、CA 私钥进 HSM、本地库做高可用或明确链为唯一真相源、提交改 fail-closed。

## 最近修复（#117–#131，含 DFT 鲁棒性）
- DFT 旋转 / 缩放几何补偿缺失 → 反向旋转 + 反向上采样
- 提取返回缺 `match/char_similarity/ber` → 字段补全
- 小图 PSNR 崩 → 嵌入强度 / 系数数随尺寸自适应
- 真实照片频谱不平淹没信号 → 径向归一化 `_radial_baseline`
- 双重复编码致干净提取 BER≈50% → 去外层投票、传唯一比特
- 链上验证无 tx_id 误报 → `not_stored` 前置判定
- VC 内嵌公钥与注册表不符 → `verify_issuer` 一致性校验
