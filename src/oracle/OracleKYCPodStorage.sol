// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IOracleKYCPod.sol";

abstract contract OracleKYCPodStorage is IOracleKYCPod {
    mapping(address => Record) public kycRecords; // user => Record

    uint256[100] private __gap;
}
