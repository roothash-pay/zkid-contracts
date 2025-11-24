// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IBLSApkRegistry.sol";
import "./IOracleKYCPod.sol";

interface IKYCManager {
    event KYCVerified(address indexed user, uint256 commitment, bytes32 signPodHash, uint256 totalStake);

    struct KYCVerifyParams {
        address user;
        uint256 commitment;
        bool isVerified;
        bytes32 msgHash;
        uint32 refBlock;
    }

    function verifyAndPodKYC(IOracleKYCPod oraclePod, KYCVerifyParams calldata params, IBLSApkRegistry.NonSignerAndSignature memory oracleSig) external;
}
