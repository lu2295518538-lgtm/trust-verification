# -*- coding: utf-8 -*-
"""
集中配置管理模块
从环境变量读取敏感配置，提供开发/生产/测试三套配置类
"""

import os


class BaseConfig:
    """基础配置类 - 通用配置项"""

    # Flask 密钥
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')

    # API 认证密钥
    API_KEY = os.environ.get('TRUST_API_KEY', 'dev-api-key-2026')

    # 数据库路径
    DATABASE_PATH = os.environ.get('DB_PATH', 'data_store/chain.db')

    # 长安链 CMC 工具路径
    CMC_PATH = os.environ.get('CMC_PATH', '/home/ljh/chainmaker-go/bin/cmc')

    # SDK 配置文件路径
    SDK_CONFIG_PATH = os.environ.get(
        'SDK_CONFIG_PATH',
        '/home/ljh/chainmaker-go/test/chain1/config/sdk_config.yml'
    )

    # 链 ID
    CHAIN_ID = os.environ.get('CHAIN_ID', 'chain1')

    # 合约名称
    CONTRACT_NAME = os.environ.get('CONTRACT_NAME', 'fact')

    # 原始数据最大长度
    MAX_RAW_DATA_LENGTH = 10000

    # 有效数据类型集合
    VALID_DATA_TYPES = {'quarantine', 'transaction', 'transport', 'slaughter'}

    # 速率限制：每分钟最大请求数
    RATE_LIMIT_PER_MINUTE = 10

    # VC 有效期（天）
    VC_VALIDITY_DAYS = 365

    # 链上操作最大重试次数
    CHAIN_MAX_RETRIES = 3

    # 链上操作重试退避因子（秒）
    CHAIN_RETRY_BACKOFF = 2


class DevelopmentConfig(BaseConfig):
    """开发环境配置"""

    DEBUG = True
    TESTING = False


class ProductionConfig(BaseConfig):
    """生产环境配置 - 强制要求设置环境变量"""

    DEBUG = False
    TESTING = False

    # 生产环境必须通过环境变量设置 SECRET_KEY（不提供默认值）
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')


class TestingConfig(BaseConfig):
    """测试环境配置 - 使用内存数据库"""

    DEBUG = True
    TESTING = True
    DATABASE_PATH = ':memory:'


# 配置映射字典
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
}

# 获取当前配置（根据 FLASK_ENV 环境变量选择）
current_config = config_map[os.environ.get('FLASK_ENV', 'development')]

# 生产环境启动时校验：SECRET_KEY 必须通过环境变量设置
if os.environ.get('FLASK_ENV') == 'production' and current_config.SECRET_KEY is None:
    raise ValueError("生产环境必须设置 FLASK_SECRET_KEY 环境变量")
