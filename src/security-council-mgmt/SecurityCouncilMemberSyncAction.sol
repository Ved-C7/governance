// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.16;

/*
 * ============================================================
 * ANNOTATED IMPLEMENTATION WALKTHROUGH
 * Presentation: "The Governance Handbrake" - Security Councils
 * Slide 03
 * ============================================================
 *
 * The Gnosis Safe from Slide 03 stores its owners in a linked list on-chain. When an
 * election finishes and SecurityCouncilManager records the new members, this action
 * contract is what actually writes those changes into the Safe. It compares the current
 * owner list against the desired one and adds or removes members until they match.
 *
 * It runs through the UpgradeExecutor's module authority, which means it can modify
 * the Safe without collecting nine new signatures for the change. That module permission
 * was set up when the council was first deployed and can only be removed by the Safe
 * owners themselves, which requires nine signatures.
 *
 * The 9-of-12 threshold from Slide 03 is preserved automatically through every sync.
 * Whenever a member is added or removed, the threshold stays at 9. No human has to
 * remember to update it. The Safe enforces it as an invariant.
 * ============================================================
 */

import "./interfaces/IGnosisSafe.sol";
import "./SecurityCouncilMgmtUtils.sol";
import "../gov-action-contracts/execution-record/ActionExecutionRecord.sol";

/// @notice Action contract for updating security council members. Used by the security council management system.
///         Expected to be delegate called into by an Upgrade Executor
contract SecurityCouncilMemberSyncAction is ActionExecutionRecord {
    error PreviousOwnerNotFound(address targetOwner, address securityCouncil);
    error ExecFromModuleError(bytes data, address securityCouncil);

    event UpdateNonceTooLow(
        address indexed securityCouncil, uint256 currrentNonce, uint256 providedNonce
    );

    /// @dev Used in the gnosis safe as the first entry in their ownership linked list
    address public constant SENTINEL_OWNERS = address(0x1);

    constructor(KeyValueStore _store)
        ActionExecutionRecord(_store, "SecurityCouncilMemberSyncAction")
    {}

    // SLIDE 03: This is the function that actually changes who is in the Gnosis Safe. It gets
    // the full desired member list from SecurityCouncilManager, compares it against who is
    // currently in the Safe, and adds anyone missing or removes anyone who should not be there
    // anymore. The nine-of-twelve threshold is preserved the entire time. The nonce check at
    // the top prevents an old retryable ticket that expired and got re-queued from overwriting
    // a more recent update. If the nonce is not higher than the last one recorded, the
    // function returns early without making any changes.
    /// @notice Updates members of security council multisig to match provided array
    /// @dev    This function contains O(n^2) operations, so doesnt scale for large numbers of members. Expected count is 12, which is acceptable.
    ///         Gnosis OwnerManager handles reverting if address(0) is passed to remove/add owner
    /// @param _securityCouncil The security council to update
    /// @param _updatedMembers  The new list of members. The Security Council will be updated to have this exact list of members
    /// @return res indicates whether an update took place
    function perform(address _securityCouncil, address[] memory _updatedMembers, uint256 _nonce)
        external
        returns (bool res)
    {
        // make sure that _nonce is greater than the last nonce
        // we do this to ensure that a previous update does not occur after a later one
        // the mechanism just checks greater, not n+1, because the Security Council Manager always
        // sends the latest full list of members so it doesn't matter if some updates are missed
        // Additionally a retryable ticket could be used to execute the update, and since tickets
        // expire if not executed after some time, then allowing updates to be skipped means that the
        // system will not be blocked if a retryable ticket is expires
        uint256 updateNonce = getUpdateNonce(_securityCouncil);
        if (_nonce <= updateNonce) {
            // when nonce is too now, we simply return, we don't revert.
            // this way an out of date update will actual execute, rather than remaining in an unexecuted state forever
            emit UpdateNonceTooLow(_securityCouncil, updateNonce, _nonce);
            return false;
        }

        // store the nonce as a record of execution
        // use security council as the key to ensure that updates to different security councils are kept separate
        _setUpdateNonce(_securityCouncil, _nonce);

        IGnosisSafe securityCouncil = IGnosisSafe(_securityCouncil);
        // preserve current threshold, the safe ensures that the threshold is never lower than the member count
        uint256 threshold = securityCouncil.getThreshold();

        address[] memory previousOwners = securityCouncil.getOwners();

        for (uint256 i = 0; i < _updatedMembers.length; i++) {
            address member = _updatedMembers[i];
            if (!securityCouncil.isOwner(member)) {
                _addMember(securityCouncil, member, threshold);
            }
        }

        for (uint256 i = 0; i < previousOwners.length; i++) {
            address owner = previousOwners[i];
            if (!SecurityCouncilMgmtUtils.isInArray(owner, _updatedMembers)) {
                _removeMember(securityCouncil, owner, threshold);
            }
        }
        return true;
    }

    function _addMember(IGnosisSafe securityCouncil, address _member, uint256 _threshold)
        internal
    {
        _execFromModule(
            securityCouncil,
            abi.encodeWithSelector(IGnosisSafe.addOwnerWithThreshold.selector, _member, _threshold)
        );
    }

    function _removeMember(IGnosisSafe securityCouncil, address _member, uint256 _threshold)
        internal
    {
        address previousOwner = getPrevOwner(securityCouncil, _member);
        _execFromModule(
            securityCouncil,
            abi.encodeWithSelector(
                IGnosisSafe.removeOwner.selector, previousOwner, _member, _threshold
            )
        );
    }

    function getPrevOwner(IGnosisSafe securityCouncil, address _owner)
        public
        view
        returns (address)
    {
        // owners are stored as a linked list and removal requires the previous owner
        address[] memory owners = securityCouncil.getOwners();
        address previousOwner = SENTINEL_OWNERS;
        for (uint256 i = 0; i < owners.length; i++) {
            address currentOwner = owners[i];
            if (currentOwner == _owner) {
                return previousOwner;
            }
            previousOwner = currentOwner;
        }
        revert PreviousOwnerNotFound({
            targetOwner: _owner,
            securityCouncil: address(securityCouncil)
        });
    }

    function getUpdateNonce(address securityCouncil) public view returns (uint256) {
        return _get(uint160(securityCouncil));
    }

    function _setUpdateNonce(address securityCouncil, uint256 nonce) internal {
        _set(uint160(securityCouncil), nonce);
    }

    // SLIDE 03, Gnosis Safe module entry point: This is how the UpgradeExecutor modifies the
    // Safe without needing nine signatures from the current council members. The Safe has a
    // concept of trusted modules, which are contracts that are pre-authorized to call Safe
    // functions on its behalf. The UpgradeExecutor was set as a module when the council was
    // deployed. This means governance can update the member list through the election process
    // without the existing council having to sign off on their own replacements every time.
    /// @notice Execute provided operation via gnosis safe's trusted execTransactionFromModule entry point
    function _execFromModule(IGnosisSafe securityCouncil, bytes memory data) internal {
        if (
            !securityCouncil.execTransactionFromModule(
                address(securityCouncil), 0, data, OpEnum.Operation.Call
            )
        ) {
            revert ExecFromModuleError({data: data, securityCouncil: address(securityCouncil)});
        }
    }
}
