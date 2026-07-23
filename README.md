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
- 长安链链上一致性校验

### 3. 隐水印 (版权保护)
- **PHFRFM 零水印** (论文: 极谐波分数傅里叶矩及其零水印算法应用)
  - 完全无损 (PSNR=100dB)
  - 抗 JPEG 压缩、裁剪、旋转、缩放、噪声
  - 分数阶次 p 参数可调 (0.1-1.0)
- **DFT 频域水印** + **Hamming(7,4) ECC 纠错码**
  - 5x 重复编码 (多数投票纠错)
  - 自定义攻击强度 (裁剪/旋转/JPEG/缩放/噪声，每个独立开关)
  - 频谱对比 (嵌入前/后 DFT 幅度谱)
- **上传验证**: 支持用户上传自行处理过的图片 + 期望DID 验证

### 4. 可验证凭证 (VC/VP)
- VC 颁发 (DID-based)
- VP 构造与验证

### 5. VM 终端查询工具
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
- ChainMaker 长安链 (测试环境 chain1)
- Pillow, NumPy, gmssl, pycryptodome

### 安装
```bash
cd trust_verification
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 配置文件
- `app.py` 顶部: `OWNER_DID`, `OWNER_KEYPAIR`, `API_KEYS`
- 长安链 SDK 配置: `core/chainmaker_client.py`

### 启动
```bash
# 开发模式
python3 app.py

# 生产模式 (systemd)
sudo systemctl start trust-verification.service
```

## 技术栈

| 层 | 技术 |
|---|------|
| 区块链 | 长安链 ChainMaker (chain1) |
| 签名 | SM2 (国密) |
| 哈希 | SM3 (国密) |
| 承诺 | Pedersen Commitments |
| 身份 | W3C DID |
| 水印 | PHFRFM 零水印 / DFT 隐水印 |
| ECC | Hamming(7,4) |
| 后台 | Flask + Jinja2 |
| 前端 | Vanilla JS (无框架) |
| 数据库 | SQLite (本地缓存) + 长安链 (链上) |
