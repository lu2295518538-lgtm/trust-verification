#!/usr/bin/env python3
"""
链上存证记录查询工具 - 在 VM 终端中运行
用法:
  python3 query_records.py              # 列出最近 20 条
  python3 query_records.py --all       # 列出所有
  python3 query_records.py --id 42     # 按 ID 查询
  python3 query_records.py --did did:trust:livestock:data:xxx  # 按 DID 查询
  python3 query_records.py --tx 18c4xxx  # 按链上 TX 查询
  python3 query_records.py --latest    # 最新一条
  python3 query_records.py --empty     # 查找空时间戳
"""
import sqlite3
import sys
import argparse
from datetime import datetime

DB = '/home/ljh/trust_verification/data_store/chain.db'


def format_row(row):
    rid, did, dtype, algo, fp, cmt, tx, bh, ts = row
    did_short = (did[:30] + '...') if did and len(did) > 30 else (did or '-')
    fp_short = (fp[:20] + '...') if fp and len(fp) > 20 else (fp or '-')
    cmt_short = (cmt[:20] + '...') if cmt and len(cmt) > 20 else (cmt or '-')
    tx_short = (tx[:20] + '...') if tx and len(tx) > 20 else (tx or '-')
    ts_short = (ts[:19] if ts else '-')

    s = '\nID:         ' + str(rid)
    s += '\nDID:        ' + did_short
    s += '\nType:       ' + str(dtype or '-')
    s += '\nAlgorithm:  ' + str(algo or '-')
    s += '\nFingerprint:' + fp_short
    s += '\nCommitment: ' + cmt_short
    s += '\nChain TX:   ' + tx_short
    s += '\nBlock:      ' + str(bh or '-')
    s += '\nTimestamp:  ' + ts_short
    s += '\n'
    return s


def main():
    parser = argparse.ArgumentParser(description='链上存证记录查询')
    parser.add_argument('--all', action='store_true', help='列出所有记录')
    parser.add_argument('--id', type=int, help='按 ID 查询')
    parser.add_argument('--did', type=str, help='按 DID 查询')
    parser.add_argument('--tx', type=str, help='按链上 TX 查询')
    parser.add_argument('--latest', action='store_true', help='最新一条')
    parser.add_argument('--empty', action='store_true', help='查找空时间戳')
    parser.add_argument('--limit', type=int, default=20, help='列出条数')
    parser.add_argument('--stats', action='store_true', help='显示统计')
    args = parser.parse_args()

    c = sqlite3.connect(DB)
    cur = c.cursor()

    if args.stats:
        total = cur.execute("SELECT COUNT(*) FROM commitments").fetchone()[0]
        with_ts = cur.execute("SELECT COUNT(*) FROM commitments WHERE timestamp IS NOT NULL AND timestamp != ''").fetchone()[0]
        types = cur.execute("SELECT data_type, COUNT(*) FROM commitments GROUP BY data_type").fetchall()
        print('\n=== 统计 ===')
        print('总记录数: ' + str(total))
        print('有时间戳: ' + str(with_ts))
        print('空时间戳: ' + str(total - with_ts))
        print('\n按类型分组:')
        for t, cnt in types:
            print('  ' + str(t) + ': ' + str(cnt))

    elif args.id is not None:
        row = cur.execute("SELECT * FROM commitments WHERE id=?", (args.id,)).fetchone()
        cols = [d[0] for d in cur.description]
        if row:
            print('\n=== 记录 ID=' + str(args.id) + ' ===')
            for c_name, val in zip(cols, row):
                print('  ' + str(c_name) + ': ' + str(val))
        else:
            print('未找到 ID=' + str(args.id))

    elif args.did:
        row = cur.execute("SELECT * FROM commitments WHERE data_did=?", (args.did,)).fetchone()
        cols = [d[0] for d in cur.description]
        if row:
            print('\n=== 记录 DID=' + args.did[:50] + ' ===')
            for c_name, val in zip(cols, row):
                print('  ' + str(c_name) + ': ' + str(val))
        else:
            print('未找到 DID=' + args.did)

    elif args.tx:
        row = cur.execute("SELECT * FROM commitments WHERE chain_tx_id=?", (args.tx,)).fetchone()
        if row:
            print(format_row(row))
        else:
            print('未找到 TX=' + args.tx)

    elif args.latest:
        row = cur.execute("SELECT * FROM commitments ORDER BY id DESC LIMIT 1").fetchone()
        cols = [d[0] for d in cur.description]
        if row:
            print('\n=== 最新记录 (ID=' + str(row[0]) + ') ===')
            for c_name, val in zip(cols, row):
                print('  ' + str(c_name) + ': ' + str(val))

    elif args.empty:
        rows = cur.execute("SELECT id, data_did, chain_tx_id FROM commitments WHERE timestamp IS NULL OR timestamp = ''").fetchall()
        print('\n=== 空时间戳记录: ' + str(len(rows)) + ' 条 ===')
        for rid, did, tx in rows:
            print('  id=' + str(rid) + ' did=' + str(did[:40] if did else None) + ' tx=' + str(tx[:20] if tx else None))

    else:
        limit = 1000 if args.all else args.limit
        rows = cur.execute("SELECT id, data_did, data_type, algorithm, fingerprint, commitment, chain_tx_id, block_height, timestamp FROM commitments ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        print('\n=== 链上存证记录 (最近 ' + str(len(rows)) + ' 条) ===')
        for r in rows:
            print(format_row(r))

    c.close()


if __name__ == '__main__':
    main()
