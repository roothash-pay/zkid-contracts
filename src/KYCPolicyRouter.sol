// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./libraries/OracleSigVerifier.sol";
import "./interfaces/IOracleKYCPod.sol";
import "./interfaces/IVerifier.sol";

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "./libraries/BN254.sol";
import "./KYCPolicyRouterStorage.sol";

/// @title KYCPolicyRouter
/// @notice Upper-layer design, Layer 3: zkID Policy Verifier & Oracle Router
///         - Route to the corresponding Oracle KYC Pod based on different policyId
///         - Call OracleSigVerifier.verify() to verify BLS signatures
///         - (Reserved) Call zk proof verifier to verify zero-knowledge proofs
contract KYCPolicyRouter is Initializable, OwnableUpgradeable, KYCPolicyRouterStorage {
    using OracleSigVerifier for *;

    // ============================ Functions ==============================

    /// @notice Initialize the contract
    function initialize(address _initialOwner) public initializer {
        __Ownable_init(_initialOwner);
    }

    /// @dev Set zkVerifier; different verifiers can be used for different policies,
    ///      such as checking age, nationality, etc.
    /// @dev Can also be set to address(0) to skip zk proof verification
    /// @param description Verifier description, e.g. "age_over_18"
    /// @param _verifier   Verifier contract address
    function setZkVerifier(string memory description, address _verifier) external onlyOwner {
        zkVerifiers[description] = IVerifier(_verifier);
    }

    /// @dev Bind an Oracle KYC Pod to a specific policy
    /// @dev Also acts as registration for the Oracle KYC Pod
    /// @param policyId Business policy ID
    /// @param kycPod   Oracle KYC Pod contract address
    function setPolicykycPod(uint256 policyId, address kycPod) external onlyOwner {
        policyToKycPod[policyId] = IOracleKYCPod(kycPod);
    }

    /// @dev Update the latest version number of a specific policy
    /// @param policyId Business policy ID
    /// @param version  Latest version
    function setLatestPolicyVersion(uint256 policyId, uint256 version) external onlyOwner {
        latestPolicyVersion[policyId] = version;
    }

    // =============== Verification Logic  ===============

    /// @notice Full pipeline for BLS + ZK verification
    /// @param policyId    Business policy ID
    /// @param version     Policy version
    /// @param proof       zk proof (placeholder)
    /// @param pubInputs   Public inputs of the zk proof (placeholder)
    function verifyAll(uint256 policyId, uint256 version, bytes calldata proof, uint256[] calldata pubInputs, string memory zkVerifierDescription) external returns (bool) {
        // 1. Find the corresponding Oracle KYC Pod by policyId
        require(version == latestPolicyVersion[policyId], "PolicyRouter: policy version mismatch"); // Must match the Oracle's latest version
        IOracleKYCPod kycPod = policyToKycPod[policyId];
        require(address(kycPod) != address(0), "PolicyRouter: kycPod not set");

        // 2. First perform Oracle KYC verification
        require(kycPod.isVerified(msg.sender), "PolicyRouter: user not verified");
        uint256 commitment = kycPod.getCommitment(msg.sender);

        // 3. (Reserved) Verify zk proof (currently requires zk proof to pass)
        IVerifier zkVerifier = zkVerifiers[zkVerifierDescription];
        require(address(zkVerifier) != address(0), "PolicyRouter: zk verifier not set");
        require(zkVerifier.verifyProof(proof, pubInputs), "PolicyRouter: zk proof invalid");

        emit Verified(policyId, version, zkVerifierDescription, address(zkVerifier), msg.sender);
        return true;
    }
}
