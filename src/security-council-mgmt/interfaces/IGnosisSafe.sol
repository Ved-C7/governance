// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.16;

/*
 * ============================================================
 * ANNOTATED IMPLEMENTATION WALKTHROUGH
 * Presentation: "The Governance Handbrake" - Security Councils
 * Slide 03
 * ============================================================
 *
 * This interface is the Solidity face of the actual Gnosis Safe that the Security Council
 * uses. Slide 03 names the mechanism as a Gnosis Safe multi-sig with a 9-of-12 threshold.
 * Every function in this interface maps directly to something the slideshow described.
 * getThreshold() returns the "9." getOwners() returns all 12 council members. The add and
 * remove functions are what SecurityCouncilMemberSyncAction calls when it syncs a new
 * election result into the Safe. And execTransactionFromModule is how the UpgradeExecutor
 * makes those changes without requiring the council to sign off on their own replacements.
 * ============================================================
 */

abstract contract OpEnum {
    enum Operation {
        Call,
        DelegateCall
    }
}

interface IGnosisSafe {
    // SLIDE 03: Returns all 12 current signer addresses. SecurityCouncilMemberSyncAction
    // calls this to compare the current owner list against the desired one after an election.
    function getOwners() external view returns (address[] memory);

    // SLIDE 03: Returns the current signing threshold, which is 9 in production. This is
    // the "9" in 9-of-12. Any transaction the council wants to execute needs at least this
    // many distinct private keys to sign off on it.
    function getThreshold() external view returns (uint256);

    function isOwner(address owner) external view returns (bool);

    // SLIDE 03: Returns whether a given address is an authorized module. The UpgradeExecutor
    // is listed as a module, which is what allows it to call execTransactionFromModule below.
    function isModuleEnabled(address module) external view returns (bool);

    // SLIDE 03: Adds a new signer to the Safe and updates the threshold at the same time.
    // Called by SecurityCouncilMemberSyncAction when it adds a newly elected member.
    function addOwnerWithThreshold(address owner, uint256 threshold) external;

    // SLIDE 03: Removes a signer from the Safe. The Safe stores its owner list as a linked
    // list, so removing someone requires knowing the address that points to them in the list.
    // SecurityCouncilMemberSyncAction.getPrevOwner() walks the list first to find that address.
    function removeOwner(address prevOwner, address owner, uint256 threshold) external;

    // SLIDE 03: This is the module entry point that lets the UpgradeExecutor modify the Safe
    // without collecting nine signatures from the current council. The council authorized this
    // during initial setup, and that authorization can only be revoked by the Safe owners
    // themselves, and removing it requires nine signatures. This is what makes the
    // election process work: governance can replace council members without the outgoing
    // members having to sign their own removal.
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        OpEnum.Operation operation
    ) external returns (bool success);
}
