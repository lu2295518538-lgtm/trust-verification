#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证主体双向绑定 + 未登记预警（依赖运行中的 Flask）。"""
import json, urllib.request, urllib.error, urllib.parse

B = 'http://127.0.0.1:5000'
K = 'lk-2026-trust-verification-key'

def get(url):
    req = urllib.request.Request(url)
    return json.loads(urllib.request.urlopen(req, timeout=15).read().decode('utf-8'))

def auth_headers():
    t = get(B + '/api/csrf-token')['csrf_token']
    return {'X-API-Key': K, 'X-CSRF-Token': t, 'Content-Type': 'application/json'}

def post(url, data):
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'),
                                 headers=auth_headers(), method='POST')
    return json.loads(urllib.request.urlopen(req, timeout=15).read().decode('utf-8'))

print('--- 1) lookup 已登记主体(养殖场代码) ---')
print(get(B + '/api/party/lookup?code=91110000MA01XXXXX2'))

print('--- 2) lookup 未登记主体(随意名称) ---')
print(get(B + '/api/party/lookup?name=' + urllib.parse.quote('野鸡散养户')))

print('--- 3) submit 检疫记录(含已登记养殖场代码) ---')
raw = ('检疫编号: JC2026-BIND01\n检疫日期: 2026-03-10\n检疫机构: XX市畜牧兽医检疫站\n'
       '检疫结果: 合格\n动物种类: 肉牛\n数量: 50\n养殖场名称: XX生态养殖场\n'
       '养殖场代码: 91110000MA01XXXXX2')
d = post(B + '/api/submit', {'raw_data': raw, 'data_type': 'quarantine', 'is_structured': True})
print('success=', d.get('success'), 'binding=', d.get('metadata', {}).get('_party_binding'))

print('--- 4) trace JC2026-BIND01 应带 party_binding ---')
td = get(B + '/api/records/trace?q=JC2026-BIND01')
print('found=', td['summary']['found'], 'unregistered=', td['summary'].get('unregistered_parties'))
for l in td['linked']:
    print('  ', l['data_type'], 'binding=', l.get('party_binding'))
print('ALL DONE')
