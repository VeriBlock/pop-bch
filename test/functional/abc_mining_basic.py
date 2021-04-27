#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Tests for Bitcoin ABC mining RPCs
"""

from test_framework.cdefs import (
    BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO,
    DEFAULT_MAX_BLOCK_SIZE,
)
from test_framework.messages import (
    COIN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
)

from decimal import Decimal

AXION_ACTIVATION_TIME = 2000000600
MINER_FUND_ADDR = 'bchreg:pqnqv9lt7e5vjyp0w88zf2af0l92l8rxdgd35g0pkl'


class AbcMiningRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [[
            '-enableminerfund',
            '-axionactivationtime={}'.format(AXION_ACTIVATION_TIME),
        ], []]

    def run_test(self):
        node = self.nodes[0]
        address = node.get_deterministic_priv_key().address

        # Assert the results of getblocktemplate have expected values. Keys not
        # in 'expected' are not checked.
        def assert_getblocktemplate(expected):
            # Always test these values in addition to those passed in
            expected = {**expected, **{
                'sigoplimit': DEFAULT_MAX_BLOCK_SIZE // BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO,
            }}

            blockTemplate = node.getblocktemplate()
            for key, value in expected.items():
                assert_equal(blockTemplate[key], value)

        # Move block time to just before axion activation
        node.setmocktime(AXION_ACTIVATION_TIME)
        node.generatetoaddress(5, address)

        # Before axion activation, the miner fund list is empty
        assert_getblocktemplate({
            'coinbasetxn': {
                'minerfund': {
                    'addresses': [],
                    'minimumvalue': 0,
                },
            },
        })

        # Move MTP forward to axion activation
        node.generatetoaddress(1, address)
        assert_equal(
            node.getblockchaininfo()['mediantime'],
            AXION_ACTIVATION_TIME)

        def get_best_coinbase():
            return node.getblock(node.getbestblockhash(), 2)['tx'][0]

        coinbase = get_best_coinbase()
        assert_equal(len(coinbase['vout']), 1)
        block_reward = coinbase['vout'][0]['value']

        # We don't need to test all fields in getblocktemplate since many of
        # them are covered in mining_basic.py
        assert_equal(node.getmempoolinfo()['size'], 0)
        assert_getblocktemplate({
            'coinbasetxn': {
                # We expect to start seeing the miner fund addresses since the
                # next block will start enforcing them.
                'minerfund': {
                    'addresses': [MINER_FUND_ADDR],
                    'minimumvalue': block_reward * 8 // 100 * COIN,
                },
            },
            # Although the coinbase value need not necessarily be the same as
            # the last block due to halvings and fees, we know this to be true
            # since we are not crossing a halving boundary and there are no
            # transactions in the mempool.
            'coinbasevalue': block_reward * COIN,
            'mintime': AXION_ACTIVATION_TIME + 1,
        })

        # First block with the new rules
        node.generatetoaddress(1, address)

        # We expect the coinbase to have multiple outputs now
        coinbase = get_best_coinbase()
        assert_greater_than_or_equal(len(coinbase['vout']), 2)
        total = Decimal()
        for o in coinbase['vout']:
            total += o['value']

        assert_equal(total, block_reward)
        assert_getblocktemplate({
            'coinbasetxn': {
                'minerfund': {
                    'addresses': [MINER_FUND_ADDR],
                    'minimumvalue': block_reward * 8 // 100 * COIN,
                },
            },
            # Again, we assume the coinbase value is the same as prior blocks.
            'coinbasevalue': block_reward * COIN,
            'mintime': AXION_ACTIVATION_TIME + 1,
        })

        # Move MTP forward
        node.setmocktime(AXION_ACTIVATION_TIME + 1)
        node.generatetoaddress(6, address)
        assert_getblocktemplate({
            'coinbasetxn': {
                'minerfund': {
                    'addresses': [MINER_FUND_ADDR],
                    'minimumvalue': block_reward * 8 // 100 * COIN,
                },
            },
            'coinbasevalue': block_reward * COIN,
            'mintime': AXION_ACTIVATION_TIME + 2,
        })


if __name__ == '__main__':
    AbcMiningRPCTest().main()
