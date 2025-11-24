// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IBLSApkRegistryX.sol";
import "../libraries/BN254.sol";

/// @title OracleSigVerifier
/// @notice Layer 2 middle layer:
///         DApps can choose different BLS Registry contracts for verification.
///         Only verifies signature validity, without touching user plaintext or KYC data.
library OracleSigVerifier {
    using BN254 for *;

    /// @notice Privacy-preserving verification logic using snapshot + pairing
    /// @param registry   Oracle Registry address (maintains aggregated public key snapshots)
    /// @param refBlock   Reference block height bound to the signature at signing time
    /// @param apkHash    Hash of the aggregated G1 public key at that time (Registry snapshot)
    /// @param sigma      Aggregated signature (G1)
    /// @param P          Message point (G1) computed off-chain by the Oracle, i.e. hashToG1(msgHash)
    /// @param apkG2      Aggregated public key (G2), returned by the Oracle together with the signature
    function verify(IBLSApkRegistryX registry, uint32 refBlock, bytes24 apkHash, BN254.G1Point memory sigma, BN254.G1Point memory P, BN254.G2Point memory apkG2) internal view returns (bool ok) {
        // 1. Ensure consistency of the aggregated public key snapshot
        //    to prevent users from forging apkG2 paired with an old signature
        require(registry.isApkHashValidAt(apkHash, refBlock), "OracleSigVerifier: apk snapshot mismatch");
        // Fetch the historical G1 public key snapshot
        BN254.G1Point memory apkG1 = registry.apkHashAt(refBlock);

        // Check consistency between apkG1 and apkG2
        // e(apkG1, g2) == e(g1, apkG2)
        bool keyMatch = BN254.pairing(apkG1, BN254.generatorG2(), BN254.generatorG1(), apkG2);
        require(keyMatch, "OracleSigVerifier: apkG1/apkG2 mismatch");

        // 2. Pairing-based signature verification: e(σ, g2) == e(P, apkG2)
        //    - σ: aggregated signature (G1)
        //    - g2: fixed curve generator (G2)
        //    - P: hashToG1(msgHash) computed off-chain by the Oracle
        //    - apkG2: aggregated public key at that time (G2)
        bool pairingOk = BN254.pairing(sigma, BN254.generatorG2(), P, apkG2); // Not verified in the registry contract because the registry's aggregated public key is updated in real time, so consistency can't be guaranteed
        require(pairingOk, "OracleSigVerifier: pairing failed");

        // 3. Verification passed
        ok = true;
    }
}
