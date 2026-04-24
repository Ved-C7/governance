// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.16;

/*
 * ============================================================
 * ANNOTATED IMPLEMENTATION WALKTHROUGH
 * Presentation: "The Governance Handbrake" - Security Councils
 * Slides 04, 05, and 07
 * ============================================================
 *
 * This contract builds the calldata that gets a governance decision from L2 to wherever
 * it actually needs to execute. A proposal might need to change something on L1, or on
 * a different L2 chain entirely. This contract figures out the right path and encodes
 * all the nested calls needed to get there.
 *
 * For L1 targets the path is: L2 governor calls ArbSys which sends a message to the
 * L1 timelock, which calls the UpgradeExecutor, which runs the action contract. For
 * targets on other L2 chains there is one extra hop through the bridge inbox. Both
 * paths end at an UpgradeExecutor that holds the admin authority to run the action.
 *
 * One important thing about Slide 04: the Security Council does not use this builder
 * when it acts in an emergency. The council collects nine Gnosis Safe signatures and
 * calls the UpgradeExecutor directly and skips the timelock entirely. This contract is
 * for the standard DAO route and for scheduled membership updates. It is not for the
 * less-than-one-hour emergency path.
 *
 * The Kelp DAO rescue from Slide 07 used the same retryable ticket pattern that this
 * builder encodes for L2-chain targets. The payload that contained all four steps
 * (upgrade inbox, impersonate attacker, transfer ETH, restore inbox) was dispatched
 * through L1ArbitrumTimelock._execute() using the RETRYABLE_TICKET_MAGIC address.
 * ============================================================
 */

import "@arbitrum/nitro-contracts/src/precompiles/ArbSys.sol";
import "@offchainlabs/upgrade-executor/src/IUpgradeExecutor.sol";
import "./L1ArbitrumTimelock.sol";
import "./security-council-mgmt/Common.sol";

interface DefaultGovAction {
    function perform() external;
}

/// @notice The location of an upgrade executor, relative to the host chain.
///         Inbox is set to address(0) if the upgrade executor is on the host chain.
///         Inbox is set to the address of the inbox of another Arbitrum chain if the upgrade executor is
///         is not on the host chain.
struct UpExecLocation {
    address inbox; // Inbox should be set to address(0) to signify that the upgrade executor is on the L1/host chain
    address upgradeExecutor;
}

struct ChainAndUpExecLocation {
    uint256 chainId;
    UpExecLocation location;
}

/// @notice Builds calldata to target the execution of action contracts in upgrade executors that exist on other chains.
///         Routes target an upgrade executor which is either on the host chain, or can be accessed via the inbox.
///         So routes are of two possible forms:
///         1. Withdrawal => L1Timelock => UpgradeExecutor
///         2. Withdrawal => L1Timelock => Inbox => UpgradeExecutor
/// @dev    This contract makes the following assumptions:
///         * It is deployed on an L2 - more specifically it has access to an ArbSys which allows it to make withdrawal
///           transactions to a host chain
///         * It can only target one upgrade executor per chain
///         * The upgrade executors being targeted are either on the host chain, or are Arbitrum chains reachable
///           via inboxes on the host chain
///         * There exists a L1 timelock on the host chain
contract UpgradeExecRouteBuilder {
    error UpgadeExecDoesntExist(uint256 chainId);
    error UpgradeExecAlreadyExists(uint256 chindId);
    error ParamLengthMismatch(uint256 len1, uint256 len2);
    error EmptyActionBytesData(bytes[]);
    error InvalidActionType(uint256 actionType);

    // SLIDE 07, Step 01: When a proposal uses this address as its target instead of a real
    // contract, the L1 timelock knows to send the payload through the bridge as a retryable
    // ticket rather than executing it locally. This is how a single L1 transaction can trigger
    // an upgrade on any connected chain. In the Kelp rescue, the council's transaction
    // targeted this address, which told the timelock to route the inbox upgrade payload
    // through the bridge instead of running it on L1.
    /// @notice The magic value used by the L1 timelock to indicate that a retryable ticket should be created
    ///         See L1ArbitrumTimelock for more details
    address public constant RETRYABLE_TICKET_MAGIC = 0xa723C008e76E379c55599D2E4d93879BeaFDa79C;
    /// @notice Default args for creating a proposal, used by createProposalWithDefaulArgs and createProposalBatchWithDefaultArgs
    ///         Default is function selector for a perform function with no args: 'function perform() external'
    bytes public constant DEFAULT_GOV_ACTION_CALLDATA =
        abi.encodeWithSelector(DefaultGovAction.perform.selector);
    uint256 public constant DEFAULT_VALUE = 0;
    /// @notice Default predecessor used when calling the L1 timelock
    bytes32 public constant DEFAULT_PREDECESSOR = bytes32(0);

    /// @notice Address of the L1 timelock targeted by this route builder
    address public immutable l1TimelockAddr;
    // SLIDE 04, "TIME TO ACT: 7 days": This stores the L1 timelock's minimum delay at
    // deploy time. Every standard DAO proposal that crosses to L1 waits at least this long.
    // Because it is immutable, if the L1 timelock's delay ever changes, a new RouteBuilder
    // has to be deployed and governance has to approve the swap. That friction is intentional
    // and it prevents the delay from being quietly compressed without anyone noticing.
    /// @notice The minimum delay of the L1 timelock targeted by this route builder
    /// @dev    If the min delay for this timelock changes then a new route builder will need to be deployed
    uint256 public immutable l1TimelockMinDelay;
    /// @notice Upgrade Executor locations for each chain (chainId => location)
    mapping(uint256 => UpExecLocation) public upExecLocations;

    /// @param _upgradeExecutors    Locations of the upgrade executors on each chain
    /// @param _l1ArbitrumTimelock  Address of the core gov L1 timelock
    /// @param _l1TimelockMinDelay  Minimum delay for L1 timelock
    constructor(
        ChainAndUpExecLocation[] memory _upgradeExecutors,
        address _l1ArbitrumTimelock,
        uint256 _l1TimelockMinDelay
    ) {
        if (_l1ArbitrumTimelock == address(0)) {
            revert ZeroAddress();
        }

        for (uint256 i = 0; i < _upgradeExecutors.length; i++) {
            ChainAndUpExecLocation memory chainAndUpExecLocation = _upgradeExecutors[i];
            if (chainAndUpExecLocation.location.upgradeExecutor == address(0)) {
                revert ZeroAddress();
            }
            if (upExecLocationExists(chainAndUpExecLocation.chainId)) {
                revert UpgradeExecAlreadyExists(chainAndUpExecLocation.chainId);
            }
            upExecLocations[chainAndUpExecLocation.chainId] = chainAndUpExecLocation.location;
        }

        l1TimelockAddr = _l1ArbitrumTimelock;
        l1TimelockMinDelay = _l1TimelockMinDelay;
    }

    /// @notice Check if an upgrade executor exists for the supplied chain id
    /// @param _chainId ChainId for target UpExecLocation
    function upExecLocationExists(uint256 _chainId) public view returns (bool) {
        return upExecLocations[_chainId].upgradeExecutor != address(0);
    }

    /// @notice Creates the to address and calldata to be called to execute a route to a batch of action contracts.
    ///         See Governance Action Contracts for more details.
    /// @param chainIds         Chain ids containing the actions to be called
    /// @param actionAddresses  Addresses of the action contracts to be called
    /// @param actionValues     Values to call the action contracts with
    /// @param actionDatas      Call data to call the action contracts with
    /// @param actionTypes      Types of the action contracts to be called (0: execute, 1: executeCall)
    /// @param predecessor      A predecessor value for the l1 timelock operation
    /// @param timelockSalt     A salt for the l1 timelock operation
    function createActionRouteData2(
        uint256[] memory chainIds,
        address[] memory actionAddresses,
        uint256[] memory actionValues,
        bytes[] memory actionDatas,
        uint256[] memory actionTypes,
        bytes32 predecessor,
        bytes32 timelockSalt
    ) public view returns (address, bytes memory) {
        if (chainIds.length != actionAddresses.length) {
            revert ParamLengthMismatch(chainIds.length, actionAddresses.length);
        }
        if (chainIds.length != actionValues.length) {
            revert ParamLengthMismatch(chainIds.length, actionValues.length);
        }
        if (chainIds.length != actionDatas.length) {
            revert ParamLengthMismatch(chainIds.length, actionDatas.length);
        }
        if (chainIds.length != actionTypes.length) {
            revert ParamLengthMismatch(chainIds.length, actionTypes.length);
        }

        address[] memory schedTargets = new address[](chainIds.length);
        uint256[] memory schedValues = new uint256[](chainIds.length);
        bytes[] memory schedData = new bytes[](chainIds.length);

        // for each chain create calldata that targets the upgrade executor
        // from the l1 timelock
        for (uint256 i = 0; i < chainIds.length; i++) {
            UpExecLocation memory upExecLocation = upExecLocations[chainIds[i]];
            if (upExecLocation.upgradeExecutor == address(0)) {
                revert UpgadeExecDoesntExist(chainIds[i]);
            }
            if (actionDatas[i].length == 0) {
                revert EmptyActionBytesData(actionDatas);
            }

            bytes memory executorData;
            if (actionTypes[i] == 0) {
                executorData = abi.encodeWithSelector(
                    IUpgradeExecutor.execute.selector, actionAddresses[i], actionDatas[i]
                );
            } else if (actionTypes[i] == 1) {
                executorData = abi.encodeWithSelector(
                    IUpgradeExecutor.executeCall.selector, actionAddresses[i], actionDatas[i]
                );
            } else {
                revert InvalidActionType(actionTypes[i]);
            }

            // SLIDE 05 + 07: If the inbox is address(0), the UpgradeExecutor is on L1 and
            // the call goes there directly. If the inbox is set to something, the executor
            // is on a different L2, so the call gets wrapped in RETRYABLE_TICKET_MAGIC and
            // sent through the bridge. The Kelp rescue used this second path. The council
            // needed to reach the nitro-contracts Inbox proxy through this routing logic
            // to dispatch the four-step recovery transaction.
            // for L1, inbox is set to address(0):
            if (upExecLocation.inbox == address(0)) {
                schedTargets[i] = upExecLocation.upgradeExecutor;
                schedValues[i] = actionValues[i];
                schedData[i] = executorData;
            } else {
                // For L2 actions, magic is top level target, and value and calldata are encoded in payload
                schedTargets[i] = RETRYABLE_TICKET_MAGIC;
                schedValues[i] = 0;
                schedData[i] = abi.encode(
                    upExecLocation.inbox,
                    upExecLocation.upgradeExecutor,
                    actionValues[i],
                    0,
                    0,
                    executorData
                );
            }
        }

        // batch those calls to execute from the l1 timelock
        bytes memory timelockCallData = abi.encodeWithSelector(
            L1ArbitrumTimelock.scheduleBatch.selector,
            schedTargets,
            schedValues,
            schedData,
            predecessor,
            timelockSalt,
            l1TimelockMinDelay
        );

        // create a message to initiate a withdrawal to the L1 timelock
        return (
            address(100),
            abi.encodeWithSelector(ArbSys.sendTxToL1.selector, l1TimelockAddr, timelockCallData)
        );
    }

    /// @notice Creates the to address and calldata to be called to execute a route to a batch of action contracts.
    ///         Action types are defaulted to 0 (execute). See Governance Action Contracts for more details.
    /// @dev    This function is deprecated. Use createActionRouteData2 instead.
    /// @param chainIds         Chain ids containing the actions to be called
    /// @param actionAddresses  Addresses of the action contracts to be called
    /// @param actionValues     Values to call the action contracts with
    /// @param actionDatas      Call data to call the action contracts with
    /// @param predecessor      A predecessor value for the l1 timelock operation
    /// @param timelockSalt     A salt for the l1 timelock operation
    function createActionRouteData(
        uint256[] memory chainIds,
        address[] memory actionAddresses,
        uint256[] memory actionValues,
        bytes[] memory actionDatas,
        bytes32 predecessor,
        bytes32 timelockSalt
    ) public view returns (address, bytes memory) {
        return createActionRouteData2(
            chainIds,
            actionAddresses,
            actionValues,
            actionDatas,
            new uint256[](chainIds.length), // action types, default to 0 for execute
            predecessor,
            timelockSalt
        );
    }

    /// @notice Creates the to address and calldata to be called to execute a route to a batch of action contracts.
    ///         Uses common defaults for value, calldata and predecessor.
    ///         See Governance Action Contracts for more details.
    /// @param chainIds         Chain ids containing the actions to be called
    /// @param actionAddresses  Addresses of the action contracts to be called
    /// @param timelockSalt     A salt for the l1 timelock operation
    function createActionRouteDataWithDefaults(
        uint256[] memory chainIds,
        address[] memory actionAddresses,
        bytes32 timelockSalt
    ) public view returns (address, bytes memory) {
        uint256[] memory values = new uint256[](chainIds.length);
        bytes[] memory actionDatas = new bytes[](chainIds.length);
        for (uint256 i = 0; i < chainIds.length; i++) {
            actionDatas[i] = DEFAULT_GOV_ACTION_CALLDATA;
            values[i] = DEFAULT_VALUE;
        }
        return createActionRouteData(
            chainIds, actionAddresses, values, actionDatas, DEFAULT_PREDECESSOR, timelockSalt
        );
    }
}
