'''往数据文件追加压测用的批量条目，供页面在大数据量下试用。

条目放在 --root 下，按 --dirs 与 --depth 铺成目录树，重跑脚本会整段替换上一次生成的内容。
'''

import argparse
import json

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_COUNT = 3200
DEFAULT_ROOT = '/压测'
DEFAULT_GROUP = '家庭'
AUTHORS = ('alice', 'bob')
MARKER = '# 以下压测条目由 gen_bulk_data.py 生成'
MARKER_TAIL = '，重跑脚本会整段替换。'


@dataclass(frozen=True, slots=True)
class Shape:
    root: str
    count: int
    group: str
    dirs: int
    depth: int


@dataclass(slots=True)
class Dir:
    name: str
    dirs: dict[str, Dir] = field(default_factory=dict)
    entries: list[int] = field(default_factory=list)


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
        description='把压测用的批量条目写进源数据文件，上一次生成的整段会被替换',
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
    parser.add_argument(
        'orig_file',
        metavar='ORIG_FILE',
        help='要追加压测条目的源数据文件',
    )
    return parser


def leaf_segments(shape: Shape) -> list[list[str]]:
    paths = [[segment for segment in shape.root.split('/') if segment]]
    for _ in range(shape.depth):
        paths = [
            [*path, f'分组-{index:04d}'] for path in paths for index in range(1, shape.dirs + 1)
        ]
    return paths


def block_sizes(total: int, parts: int) -> list[int]:
    base, extra = divmod(total, parts)
    return [base + (1 if index < extra else 0) for index in range(parts)]


def build_tree(leaves: Sequence[Sequence[str]], sizes: Sequence[int]) -> Dir:
    root = Dir(name='')
    index = 0
    for segments, size in zip(leaves, sizes, strict=True):
        node = root
        for segment in segments:
            node = node.dirs.setdefault(segment, Dir(name=segment))
        node.entries.extend(range(index + 1, index + size + 1))
        index += size
    return root


def toml_string(value: str) -> str:
    '''按 TOML 基本字符串转义，JSON 的转义规则是它的真子集。'''
    return json.dumps(value, ensure_ascii=False)


def file_fields(index: int, group: str) -> Iterator[str]:
    name = f'{index:04d}'
    desc = f'压测条目 {index}'
    if index % 10 == 0:
        desc += f'\n第二行：条目 {index} 的补充说明'
    yield f'name = {toml_string(f"条目-{name}.txt")}'
    yield f"loc = 'https://bulk.example.org/{name}'"
    yield f"pwd = 'bulk-pwd-{name}'"
    yield f'desc = {toml_string(desc)}'
    yield f"author = '{AUTHORS[index % len(AUTHORS)]}'"
    yield f'groups = [{toml_string(group)}]'


def emit(node: Dir, table: str, group: str) -> Iterator[str]:
    for child in node.dirs.values():
        yield f'[[{table}.dirs]]'
        yield f'name = {toml_string(child.name)}'
        yield from emit(child, f'{table}.dirs', group)
    for index in node.entries:
        yield f'[[{table}.files]]'
        yield from file_fields(index, group)


def main(argv: Sequence[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    orig_file = Path(args.orig_file)
    shape = Shape(
        root=args.root, count=args.count, group=args.group, dirs=args.dirs, depth=args.depth
    )
    leaves = leaf_segments(shape)
    summary = (
        f'{MARKER}（count={shape.count}, dirs={shape.dirs}, depth={shape.depth},'
        f' root={shape.root}, group={shape.group}）{MARKER_TAIL}'
    )
    base = orig_file.read_text(encoding='utf-8').split(MARKER, 1)[0].rstrip()
    tree = build_tree(leaves, block_sizes(shape.count, len(leaves)))
    block = '\n'.join(['[[roots]]', *emit(tree, 'roots', shape.group)])
    orig_file.write_text(f'{base}\n\n{summary}\n{block}\n', encoding='utf-8')
    print(f'{shape.count} 条压测条目写入 {orig_file}，分布在 {len(leaves)} 个目录')


if __name__ == '__main__':
    main()
