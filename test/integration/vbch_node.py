import os

from pathlib import Path

from pypoptools.pypoptesting.framework.bin_util import assert_dir_accessible, get_open_port
from pypoptools.pypoptesting.framework.entities import *
from pypoptools.pypoptesting.framework.json_rpc import JsonRpcApi, JsonRpcException
from pypoptools.pypoptesting.framework.managers import ProcessManager
from pypoptools.pypoptesting.altchain_node_adaptors.vbitcoind_node import VBitcoindNode

PORT_MIN = 15000
PORT_MAX = 25000
BIND_TO = '127.0.0.1'


def _write_vbitcoin_conf(datadir, p2p_port, rpc_port, rpc_user, rpc_password):
    bitcoin_conf_file = Path(datadir, "bitcoin.conf")
    with open(bitcoin_conf_file, 'w', encoding='utf8') as f:
        f.write("regtest=1\n")
        f.write("[{}]\n".format("regtest"))
        f.write("port={}\n".format(p2p_port))
        f.write("rpcport={}\n".format(rpc_port))
        f.write("rpcuser={}\n".format(rpc_user))
        f.write("rpcpassword={}\n".format(rpc_password))
        f.write("fallbackfee=0.0002\n")
        f.write("server=1\n")
        f.write("keypool=1\n")
        f.write("discover=0\n")
        f.write("dnsseed=0\n")
        f.write("listenonion=0\n")
        f.write("printtoconsole=0\n")
        f.write("upnp=0\n")
        f.write("shrinkdebugfile=0\n")
        f.write("poplogverbosity=info\n")


class VBchNode(VBitcoindNode):
    def __init__(self, number: int, datadir: Path):
        self.number = number

        p2p_port = get_open_port(PORT_MIN, PORT_MAX, BIND_TO)
        self.p2p_address = "{}:{}".format(BIND_TO, p2p_port)

        rpc_port = get_open_port(PORT_MIN, PORT_MAX, BIND_TO)
        rpc_url = "http://{}:{}/".format(BIND_TO, rpc_port)
        rpc_user = 'testuser'
        rpc_password = 'testpassword'
        self.rpc = JsonRpcApi(rpc_url, user=rpc_user, password=rpc_password)

        vbitcoind_path = os.environ.get('BITCOIND')
        if vbitcoind_path == None:
            raise Exception("BITCOIND env var is not set. Set up the path to the bitcoind binary to the BITCOIND env var")

        exe = Path(Path.cwd(), vbitcoind_path)
        if not exe:
            raise Exception("BitcoinNode: bitcoind is not found in PATH")

        assert_dir_accessible(datadir)
        args = [
            exe,
            "-datadir=" + str(datadir),
            "-logtimemicros",
            "-logthreadnames",
            "-debug",
            "-debugexclude=libevent",
            "-debugexclude=leveldb",
            "-txindex",
            "-uacomment=testnode{}".format(number)
        ]
        self.manager = ProcessManager(args, datadir)

        _write_vbitcoin_conf(datadir, p2p_port, rpc_port, rpc_user, rpc_password)

    def getblock(self, hash: Hexstr) -> BlockWithPopData:
        s = self.rpc.getblock(hash)
        return BlockWithPopData(
            hash=s['hash'],
            height=s['height'],
            prevhash=s.get('previousblockhash', ''),
            confirmations=s['confirmations'],
            endorsedBy=s['pop']['state']['endorsedBy'],
            blockOfProofEndorsements=[],
            containingATVs=s['pop']['state']['stored']['atvs'],
            containingVTBs=s['pop']['state']['stored']['vtbs'],
            containingVBKs=s['pop']['state']['stored']['vbkblocks']
        )