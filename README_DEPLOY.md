# 可信溯源验证系统 - 部署指南

## 环境要求

- Python 3.10+
- 长安链节点已部署并运行
- CMC 命令行工具可用

## 安装步骤

```bash
# 1. 创建并激活虚拟环境
python3 -m venv venv
source venv/bin/activate

# 2. 安装依赖
pip install -r requirements.txt
```

## 环境变量配置

复制示例文件并修改：

```bash
cp .env.example .env
```

编辑 `.env` 文件，填入实际的配置值。关键配置项：

| 变量名 | 说明 | 必填 |
|--------|------|------|
| FLASK_ENV | 运行环境（development/production/testing） | 否 |
| FLASK_SECRET_KEY | Flask 密钥（生产环境必填） | 生产必填 |
| TRUST_API_KEY | API 认证密钥 | 是 |
| DB_PATH | SQLite 数据库路径 | 否 |
| CMC_PATH | 长安链 CMC 工具路径 | 是 |
| SDK_CONFIG_PATH | SDK 配置文件路径 | 是 |
| CHAIN_ID | 链 ID | 否 |
| CONTRACT_NAME | 合约名称 | 否 |

## 启动方式

### 开发模式

```bash
export FLASK_ENV=development
python app.py
```

### 生产模式

```bash
export FLASK_ENV=production
export FLASK_SECRET_KEY="your-strong-secret-key"
export TRUST_API_KEY="your-production-api-key"
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## 注意事项

1. **首次部署必须修改 `SECRET_KEY` 和 `API_KEY`**，不要使用默认开发值
2. 生产环境未设置 `FLASK_SECRET_KEY` 将导致启动失败
3. 确保 `data_store/` 目录存在且有写入权限
4. 确保长安链 CMC 路径和 SDK 配置路径正确指向实际文件
