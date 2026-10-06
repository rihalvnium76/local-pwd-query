'''往 data.toml 追加压测用的批量条目，供页面在大数据量下试用。

条目放在 --root 下，按 --dirs 与 --depth 铺成目录树，重跑脚本会整段替换上一次生成的内容。
'''

import argparse
import json

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

DEFAULT_COUNT = 3200
DEFAULT_ROOT = '/压测'
DEFAULT_GROUP = '家庭'
AUTHORS = ('alice', 'bob')
MARKER = '# 以下压测条目由 gen_bulk_data.py 生成'
MARKER_TAIL = '，重跑脚本会整段替换。'
DATA_TOML = Path('data.toml')


@dataclass(frozen=True, slots=True)
class Shape:
    root: str
    count: int
    group: str
    dirs: int
    depth: int


def positive(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError('须为正整数')
    return value


def non_negative(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError('须为非负整数')
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='gen_bulk_data.py',
        description='把压测用的批量条目写进 data.toml，上一次生成的整段会被替换',
    )
    parser.add_argument(
        '--count',
        type=positive,
        default=DEFAULT_COUNT,
        metavar='N',
        help=f'条目总数，默认 {DEFAULT_COUNT}',
    )
    parser.add_argument(
        '--root',
        default=DEFAULT_ROOT,
        metavar='PATH',
        help=f'条目的虚拟根目录，默认 {DEFAULT_ROOT}',
    )
    parser.add_argument(
        '--group',
        default=DEFAULT_GROUP,
        metavar='NAME',
        help=f'条目所属分组，默认 {DEFAULT_GROUP}',
    )
    parser.add_argument(
        '--dirs',
        type=positive,
        default=1,
        metavar='D',
        help='每层目录的个数，默认 1',
    )
    parser.add_argument(
        '--depth',
        type=non_negative,
        default=0,
        metavar='L',
        help='根目录下的目录层数，0 表示条目直接放在根目录下，默认 0',
    )
    return parser


def leaf_paths(shape: Shape) -> list[str]:
    paths = [shape.root]
    for _ in range(shape.depth):
        paths = [f'{path}/分组-{index:04d}' for path in paths for index in range(1, shape.dirs + 1)]
    return paths


def block_sizes(total: int, parts: int) -> list[int]:
    base, extra = divmod(total, parts)
    return [base + (1 if index < extra else 0) for index in range(parts)]


def entry(index: int, path: str, group: str) -> str:
    name = f'{index:04d}'
    desc = f'压测条目 {index}'
    if index % 10 == 0:
        desc += f'\n第二行：条目 {index} 的补充说明'
    return (
        f'\n[file."{path}/条目-{name}.txt"]\n'
        f"loc = 'https://bulk.example.org/{name}'\n"
        f"pwd = 'bulk-pwd-{name}'\n"
        f'desc = {json.dumps(desc, ensure_ascii=False)}\n'
        f"author = '{AUTHORS[index % len(AUTHORS)]}'\n"
        f'groups = ["{group}"]\n'
    )


def entries(shape: Shape, paths: Sequence[str]) -> Iterator[str]:
    index = 0
    for path, size in zip(paths, block_sizes(shape.count, len(paths)), strict=True):
        for _ in range(size):
            index += 1
            yield entry(index, path, shape.group)


def main(argv: Sequence[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    shape = Shape(
        root=args.root, count=args.count, group=args.group, dirs=args.dirs, depth=args.depth
    )
    paths = leaf_paths(shape)
    summary = (
        f'{MARKER}（count={shape.count}, dirs={shape.dirs}, depth={shape.depth},'
        f' root={shape.root}, group={shape.group}）{MARKER_TAIL}'
    )
    base = DATA_TOML.read_text(encoding='utf-8').split(MARKER, 1)[0].rstrip()
    block = ''.join(entries(shape, paths))
    DATA_TOML.write_text(f'{base}\n\n{summary}\n{block}', encoding='utf-8')
    print(f'{shape.count} 条压测条目写入 {DATA_TOML}，分布在 {len(paths)} 个目录')


if __name__ == '__main__':
    main()
