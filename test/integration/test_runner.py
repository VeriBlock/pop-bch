import pathlib
import sys

from pypoptools.pypoptesting.framework.node import Node
from pypoptools.pypoptesting.test_runner import tests_running
from pypoptools.pypoptesting.altchain_node_adaptors.vbitcoind_node import VBitcoindNode


def create_node(number: int, path: pathlib.Path) -> Node:
    return VBitcoindNode(number=number, datadir=path)


if __name__ == '__main__':
    tests_running(test_names=sys.argv[1:], create_node=create_node)
