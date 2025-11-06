// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracleKYCPod {
    struct Record {
        bytes32 commitment; // Poseidon(m, r, did, policy_id, version)
        bytes32 msgHash; // Oracle签名消息哈希
        bytes32 signRecordHash; // 聚合签名记录哈希
        uint32 refBlock; // 验签所基于的区块号
        bool verified; // 是否已验证成功
    }

    /// @notice 记录KYC验证结果（仅管理合约可调用）
    function recordVerification(
        address user,
        bytes32 commitment,
        bytes32 msgHash,
        bytes32 signRecordHash,
        uint32 refBlock
    ) external;

    /// @notice 查询某个DID是否已验证
    function isVerified(address user) external view returns (bool);

    /// @notice 查询完整记录
    function getRecord(address user) external view returns (Record memory);

    function getCommitment(address user) external view returns (bytes32);
}
