// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

# source: https://github.com/ethereum/web3.py/blob/master/docs/web3.eth.account.rst
contract EcdsaSecp256k1 {
    address constant StakeHolder = 0xe0fDae262D5624B9317eD5fa4681C07e01c05078;

    function ecr (bytes32 msgh, uint8 v, bytes32 r, bytes32 s)
        public pure
        returns (bool)
    {
        return ecrecover(msgh, v, r, s) == StakeHolder;
    }
}