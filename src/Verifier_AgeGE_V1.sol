// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Verifier_AgeGE_V1 {
    function verifyProof(bytes calldata proof, uint256[] calldata pubInputs) external pure returns (bool) {
        // TODO: zk proof verification logic
        return true;
    }
}
