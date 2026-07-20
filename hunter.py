#!/usr/bin/env python3
"""
鹰图 (Hunter) API 数据获取脚本
https://hunter.qianxin.com/

默认每次仅搜索 10 条数据（硬要求）。
总数据上限 500 条（受每日免费积分限制）。
"""

import argparse
import base64
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta

import requests

# ─── 常量 ──────────────────────────────────────────────────────────────
BASE_URL = "https://hunter.qianxin.com/openApi/search"
DEFAULT_PAGE_SIZE = 10          # 每次固定 10 条（除非用户明确要求更改）
DEFAULT_MAX_PAGES = 1           # 默认只取 1 页（10 条）
ABSOLUTE_MAX_PAGES = 50         # 50 页 × 10 条 = 500 条（积分上限）
DEFAULT_TIMEOUT = 30            # 请求超时秒数
START_TIME = "2020-01-01"
END_TIME = "2030-12-31"


class HunterAPI:
    """鹰图 API 封装"""

    def __init__(self, api_key: str):
        self.api_key = api_key

    # ── 工具方法 ──────────────────────────────────────────────────────

    @staticmethod
    def encode_search(query: str) -> str:
        """将搜索语法做 base64url 编码（RFC 4648）。"""
        return base64.urlsafe_b64encode(
            query.encode("utf-8")
        ).decode("ascii")

    @staticmethod
    def decode_search(encoded: str) -> str:
        """解码 base64url 编码的搜索语法。"""
        return base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8")

    # ── 核心请求 ──────────────────────────────────────────────────────

    def search_page(
        self,
        search: str,
        page: int,
        page_size: int = DEFAULT_PAGE_SIZE,
        is_web: str = "3",
        status_code: str = "",
        port_filter: str = "false",
        start_time: str = START_TIME,
        end_time: str = END_TIME,
    ) -> dict:
        """
        请求单页数据。

        参数
        ----
        search : str
            原始搜索语法（函数内部自动做 base64url 编码）。
        page : int
            页码，从 1 开始。
        page_size : int
            每页条数，默认为 10（硬要求）。
        is_web : str
            资产类型：1=Web, 2=非Web, 3=全部。
        status_code : str
            状态码过滤，逗号分隔，如 "200,401"。
        port_filter : str
            是否开启端口过滤："true" 或 "false"。
        start_time / end_time : str
            时间范围，格式 "YYYY-MM-DD"。

        返回
        ----
        dict
            接口返回的 JSON 响应（已解析为字典）。
            结构示例：
            {
                "code": 200,
                "data": {
                    "total": <int>,
                    "time": <int>,
                    "account_type": <str>,
                    "arr": [ <资产条目> ]
                },
                "message": "success"
            }
        """
        encoded = self.encode_search(search)

        params = {
            "api-key": self.api_key,
            "search": encoded,
            "page": page,
            "page_size": page_size,
            "is_web": is_web,
            "port_filter": port_filter,
            "start_time": start_time,
            "end_time": end_time,
        }
        if status_code:
            params["status_code"] = status_code

        resp = requests.get(BASE_URL, params=params, timeout=DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def search(
        self,
        search: str,
        max_pages: int = DEFAULT_MAX_PAGES,
        page_size: int = DEFAULT_PAGE_SIZE,
        is_web: str = "3",
        status_code: str = "",
        port_filter: str = "false",
        start_time: str = START_TIME,
        end_time: str = END_TIME,
        delay: float = 0.5,
    ) -> dict:
        """
        分页获取搜索结果，最终整合为一个结果字典。

        max_pages 控制最多取多少页，每页固定 page_size 条。
        总数据量 = max_pages × page_size，上限 500 条。
        """
        if page_size != DEFAULT_PAGE_SIZE:
            print(
                f"[提醒] page_size 已被改为 {page_size}（原默认值 {DEFAULT_PAGE_SIZE}）",
                file=sys.stderr,
            )
        if page_size < 1:
            raise ValueError("page_size 必须 >= 1")
        max_allowed = ABSOLUTE_MAX_PAGES * DEFAULT_PAGE_SIZE
        if max_pages * page_size > max_allowed:
            print(
                f"[警告] 总请求条数超过每日上限 {max_allowed}，已自动限制为 {max_allowed}",
                file=sys.stderr,
            )
            max_pages = max_allowed // page_size

        all_arr = []
        total = None
        rest_total = None
        account_type = None
        query_time = None
        consume_credit = 0
        failed_pages = []

        for p in range(1, max_pages + 1):
            print(
                f"  [分页] 正在请求第 {p}/{max_pages} 页（page_size={page_size}）...",
                file=sys.stderr,
            )
            try:
                result = self.search_page(
                    search=search,
                    page=p,
                    page_size=page_size,
                    is_web=is_web,
                    status_code=status_code,
                    port_filter=port_filter,
                    start_time=start_time,
                    end_time=end_time,
                )
            except requests.RequestException as e:
                print(f"  [错误] 第 {p} 页请求失败: {e}", file=sys.stderr)
                failed_pages.append(p)
                if p < max_pages:
                    time.sleep(delay)
                continue

            code = result.get("code")
            if code != 200:
                msg = result.get("message", "未知错误")
                print(f"  [错误] 第 {p} 页返回 code={code}: {msg}", file=sys.stderr)
                failed_pages.append(p)
                if p < max_pages:
                    time.sleep(delay)
                continue

            data = result.get("data", {})
            arr = data.get("arr", [])

            # 只在第一页时记录总量等信息
            if p == 1:
                total = data.get("total", 0)
                rest_total = data.get("rest_total")
                account_type = data.get("account_type")
                query_time = data.get("time")
                consume_credit = data.get("consume_credit", 0)

            all_arr.extend(arr)

            # 如果这一页返回的数据少于 page_size，说明后面没数据了
            if len(arr) < page_size:
                break

            # 页间等待，避免触发限流
            if p < max_pages:
                time.sleep(delay)

        return {
            "code": 200,
            "message": "success",
            "data": {
                "total": total,
                "rest_total": rest_total,
                "account_type": account_type,
                "time": query_time,
                "consume_credit": consume_credit,
                "arr": all_arr,
                "page_size": page_size,
                "pages_requested": min(p, max_pages),
                "pages_failed": failed_pages,
                "total_fetched": len(all_arr),
            },
        }

    # ── 便捷方法 ──────────────────────────────────────────────────────

    def search_all(
        self,
        search: str,
        page_size: int = DEFAULT_PAGE_SIZE,
        **kwargs,
    ) -> dict:
        """
        自动获取所有可用数据（每日上限 500 条）。
        等价于 search(..., max_pages=50)。
        """
        return self.search(
            search=search,
            max_pages=ABSOLUTE_MAX_PAGES,
            page_size=page_size,
            **kwargs,
        )

    def search_by_page(
        self,
        search: str,
        page: int,
        page_size: int = DEFAULT_PAGE_SIZE,
        **kwargs,
    ) -> dict:
        """只获取指定页码的数据（不进行分页聚合）。"""
        return self.search_page(
            search=search,
            page=page,
            page_size=page_size,
            **kwargs,
        )


# ── CLI ─────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunter.py",
        description="鹰图 (Hunter) API 数据获取工具  https://hunter.qianxin.com/",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 设置 API Key（推荐写入环境变量）
  export HUNTER_API_KEY="你的API_KEY"

  # 基本搜索（默认取 1 页，共 10 条）
  python3 hunter.py -q 'ip="1.1.1.1"'

  # 搜索并输出全部可用数据（最多 500 条）
  python3 hunter.py -q 'title="北京"' --max-pages 50

  # 搜索 Web 资产
  python3 hunter.py -q 'body="php"' --is-web 1

  # 修改每页条数（需使用者明确声明同意）
  python3 hunter.py -q 'port="443"' --page-size 50

  # 指定页码
  python3 hunter.py -q 'domain="example.com"' --page 3 --single-page

  # 保存为 JSON 文件
  python3 hunter.py -q 'icp="京ICP备"' -o result.json

  # 从文件读取搜索语法
  python3 hunter.py -f query.txt --max-pages 10
        """.strip(),
    )

    # ── 搜索参数 ──
    query_group = parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument(
        "-q", "--query",
        help="搜索语法原文（如 ip=\"1.1.1.1\"），脚本自动做 base64url 编码",
    )
    query_group.add_argument(
        "-f", "--query-file",
        help="从文件读取搜索语法",
    )

    # ── 分页参数 ──
    parser.add_argument(
        "--page-size", type=int, default=DEFAULT_PAGE_SIZE,
        help=(
            f"每页条数（默认 {DEFAULT_PAGE_SIZE}，硬要求！"
            f"除非你明确知道自己在做什么且同意更改，否则不要改）"
        ),
    )
    parser.add_argument(
        "--max-pages", type=int, default=DEFAULT_MAX_PAGES,
        help=f"最大拉取页数（默认 {DEFAULT_PAGE_SIZE} 条 / {DEFAULT_MAX_PAGES} 页。"
             f"积分类账号上限 500 条即 {ABSOLUTE_MAX_PAGES} 页。"
             f"配合 --page-size 使用时确保总数不超过 500）",
    )
    parser.add_argument(
        "--single-page", action="store_true",
        help="只获取单页数据（需配合 --page 指定页码）",
    )
    parser.add_argument(
        "--page", type=int, default=1,
        help="指定页码（默认 1，与 --single-page 配合使用）",
    )

    # ── 过滤参数 ──
    parser.add_argument(
        "--is-web", type=str, default="3", choices=["1", "2", "3"],
        help='资产类型：1=Web, 2=非Web, 3=全部（默认 3）',
    )
    parser.add_argument(
        "--status-code", type=str, default="",
        help='状态码过滤，逗号分隔，如 "200,401"',
    )
    parser.add_argument(
        "--port-filter", type=str, default="false", choices=["true", "false"],
        help='端口过滤（默认 false）',
    )
    parser.add_argument(
        "--start-time", type=str, default=START_TIME,
        help=f'开始时间（默认 {START_TIME}）',
    )
    parser.add_argument(
        "--end-time", type=str, default=END_TIME,
        help=f'结束时间（默认 {END_TIME}）',
    )

    # ── 输出参数 ──
    parser.add_argument(
        "-o", "--output",
        help="输出结果到 JSON 文件（默认打印到终端）",
    )
    parser.add_argument(
        "--pretty", action="store_true",
        help="JSON 输出时格式化缩进（默认压缩输出）",
    )
    parser.add_argument(
        "--delay", type=float, default=0.5,
        help="页间请求延迟秒数（默认 0.5，避免触发限流）",
    )

    # ── API Key ──
    parser.add_argument(
        "--api-key",
        help=(
            f"API Key。优先使用此参数，"
            f"其次读取环境变量 HUNTER_API_KEY"
        ),
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # ── 获取 API Key ──
    api_key = args.api_key or os.environ.get("HUNTER_API_KEY")
    if not api_key:
        print(
            "错误：未提供 API Key。\n"
            "请通过 --api-key 参数设置，或设置环境变量 HUNTER_API_KEY。\n"
            "获取方式：https://hunter.qianxin.com/ → 个人中心 → API Key",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── 读取搜索语法 ──
    query = args.query
    if args.query_file:
        try:
            with open(args.query_file, "r", encoding="utf-8") as f:
                query = f.read().strip()
        except OSError as e:
            print(f"错误：无法读取文件 {args.query_file}: {e}", file=sys.stderr)
            sys.exit(1)

    if not query:
        print("错误：搜索语法不能为空", file=sys.stderr)
        sys.exit(1)

    # ── page_size 校验（硬要求：默认 10） ──
    page_size = args.page_size
    if page_size != DEFAULT_PAGE_SIZE:
        print(
            "\n"
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  [注意] page_size 已从默认 10 更改为其他值！           ║\n"
            "║  除非你（使用者）明确同意，请不要随意更改。            ║\n"
            "╠══════════════════════════════════════════════════════════╣\n"
            f"║  当前 page_size = {page_size}                               ║\n"
            f"║  总条数上限   = {ABSOLUTE_MAX_PAGES * DEFAULT_PAGE_SIZE} 条"
            f"{' ' * (13 - len(str(ABSOLUTE_MAX_PAGES * DEFAULT_PAGE_SIZE)))}║\n"
            "╚══════════════════════════════════════════════════════════╝\n",
            file=sys.stderr,
        )

    # ── 发起请求 ──
    hunter = HunterAPI(api_key)
    start = time.time()

    print(
        f"搜索语法: {query}",
        file=sys.stderr,
    )
    print(f"API endpoint: {BASE_URL}", file=sys.stderr)

    try:
        if args.single_page:
            # 单页模式
            result = hunter.search_by_page(
                search=query,
                page=args.page,
                page_size=page_size,
                is_web=args.is_web,
                status_code=args.status_code,
                port_filter=args.port_filter,
                start_time=args.start_time,
                end_time=args.end_time,
            )
            # 包装为统一格式
            data = result.get("data", {})
            arr = data.get("arr", [])
            output = {
                "code": result.get("code"),
                "message": result.get("message"),
                "data": {
                    "total": data.get("total"),
                    "rest_total": data.get("rest_total"),
                    "account_type": data.get("account_type"),
                    "time": data.get("time"),
                    "consume_credit": data.get("consume_credit", 0),
                    "arr": arr,
                    "page_size": page_size,
                    "pages_requested": 1,
                    "pages_failed": [],
                    "total_fetched": len(arr),
                },
            }
        else:
            # 分页模式
            output = hunter.search(
                search=query,
                max_pages=args.max_pages,
                page_size=page_size,
                is_web=args.is_web,
                status_code=args.status_code,
                port_filter=args.port_filter,
                start_time=args.start_time,
                end_time=args.end_time,
                delay=args.delay,
            )
    except requests.RequestException as e:
        print(f"\n错误：API 请求失败: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n错误：{e}", file=sys.stderr)
        sys.exit(1)

    elapsed = time.time() - start
    d = output.get("data", {})

    # ── 输出汇总 ──
    print(file=sys.stderr)
    print("─" * 50, file=sys.stderr)
    print(f"  请求耗时    : {elapsed:.2f} s", file=sys.stderr)
    print(f"  远程总量    : {d.get('total', 'N/A')}", file=sys.stderr)
    print(f"  剩余总量    : {d.get('rest_total', 'N/A')}", file=sys.stderr)
    print(f"  账户类型    : {d.get('account_type', 'N/A')}", file=sys.stderr)
    print(f"  消耗积分    : {d.get('consume_credit', 'N/A')}", file=sys.stderr)
    print(f"  请求页数    : {d.get('pages_requested', 'N/A')}", file=sys.stderr)
    print(f"  失败页数    : {d.get('pages_failed', [])}", file=sys.stderr)
    print(f"  本次拉取    : {d.get('total_fetched', 0)} 条", file=sys.stderr)
    print("─" * 50, file=sys.stderr)

    # ── 输出结果 ──
    indent = 2 if args.pretty else None
    ensure_ascii = False
    output_str = json.dumps(output, indent=indent, ensure_ascii=ensure_ascii)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_str)
            print(f"\n结果已保存至: {args.output}", file=sys.stderr)
        except OSError as e:
            print(f"\n错误：写入文件失败: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output_str)


if __name__ == "__main__":
    main()
