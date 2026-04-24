// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.16;

import "@openzeppelin/contracts-upgradeable/governance/TimelockControllerUpgradeable.sol";

/*
 * ============================================================
 * ANNOTATED IMPLEMENTATION WALKTHROUGH
 * Presentation: "The Governance Handbrake" - Security Councils
 * Slides 02 and 04
 * ============================================================
 *
 * This contract is the "7-day delay" that Slide 02 is entirely about. When the Arbitrum
 * DAO passes a proposal, it does not execute immediately. Instead, the proposal gets
 * scheduled here and has to wait a minimum number of seconds before anyone can run it.
 * The idea is that users can see what is coming and exit the protocol if they disagree.
 *
 * The problem Slide 02 describes is that this same delay that protects users also kills
 * them during an exploit. In the Compound incident, developers spotted the bug in minutes
 * but the only fix required another proposal and another 7-day wait. The drain ran the
 * entire time. This contract is that exact bottleneck.
 *
 * Slide 04 shows two routes to a state change. The standard DAO route goes through this
 * timelock and takes 7 days. The Security Council route bypasses the delay entirely by
 * using a special emergency role that sets the wait to zero. Both paths are set up at
 * initialization time through the proposers and executors arrays below.
 * ============================================================
 */

/// @title  Timelock to be used in Arbitrum governance
/// @notice Take care when using the predecessor field when scheduling. Since proposals
///         can make cross chain calls and those calls are async, it is not guaranteed that they will
//          be executed cross chain in the same order that they are executed in this timelock. Do not use
///         the predecessor field to preserve ordering in these situations.
/// @dev    This contract adds the ability to initialize TimelockControllerUpgradeable, and also has custom
///         logic for setting the min delay.
contract ArbitrumTimelock is TimelockControllerUpgradeable {
    constructor() {
        _disableInitializers();
    }

    // SLIDE 02 + 04: This is the delay number. Every proposal has to wait at least this many
    // seconds before it can execute. In the Compound incident this value was 7 days, which
    // is exactly why $80M drained while the community watched and could not do anything about it.
    // named differently to the private _minDelay on the base to avoid confusion
    uint256 private _arbMinDelay;

    /// @dev This empty reserved space is put in place to allow future versions to add new
    ///      variables without shifting down storage in the inheritance chain.
    ///      See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
    uint256[49] private __gap;

    /// @notice Initialise the timelock
    /// @param minDelay The minimum amount of delay enforced by this timelock
    // SLIDE 04: Both the DAO governor and the Security Council are listed as proposers here.
    // The difference between the two routes from Slide 04 is not who proposes, but what
    // delay they pass in. The governor uses the full minDelay. The Security Council uses zero,
    // which is how it gets the "less than one hour" response time shown in the diagram.
    /// @param proposers The accounts allowed to propose actions
    /// @param executors The accounts allowed to execute action
    function initialize(uint256 minDelay, address[] memory proposers, address[] memory executors)
        external
        initializer
    {
        __ArbitrumTimelock_init(minDelay, proposers, executors);
    }

    function __ArbitrumTimelock_init(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors
    ) internal onlyInitializing {
        // although we're passing minDelay into the TimelockController_init the state variable that it
        // sets will not be used since we override getMinDelay below. Given that we could pass in a 0
        // here to be clear that this param isn't used, however __TimelockController_init also emits the
        // MinDelayChange event so it's useful to keep the same value there as we are setting here
        __TimelockController_init(minDelay, proposers, executors);
        _arbMinDelay = minDelay;
    }

    /**
     * @dev Changes the minimum timelock duration for future operations.
     *
     * Emits a {MinDelayChange} event.
     *
     * Requirements:
     *
     * - the caller must have the TIMELOCK_ADMIN_ROLE role.
     *
     * This function is override to preserve the invariants that all changes to the system
     * must do a round trip, and must be executed from an UpgradeExecutor. The overriden function
     * only allows delay to be set by address(this). This is done by creating a proposal that has
     * address(this) as its target, and call updateDelay upon execution. This would mean that a
     * proposal could set the delay directly on the timelock, without originating from an UpgradeExecutor.
     * Here we override the the function and only allow it to be set by the timelock admin
     * which is expected to be the UpgradeExecutor to avoid the above scenario.
     *
     * It should be noted that although the avoided scenario does break the invariants we wish to
     * maintain, it doesn't pose a security risk as the proposal would still have to go through one timelock to change
     * the delay, and then future proposals would still need to go through the other timelocks.
     * So upon seeing the proposal to change the timelock users would still need to intiate their exits
     * before the timelock duration has passed, which is the same requirement we have for proposals
     * that properly do round trips.
     */
    // SLIDE 08: This override closes a loophole. Without it, a governance proposal could target
    // the timelock itself and shrink the delay down to zero, which would let an attacker with
    // majority voting power remove the very protection that makes governance safe. By restricting
    // this function to the TIMELOCK_ADMIN_ROLE, only the UpgradeExecutor can change the delay,
    // meaning any change still has to go through a full governance round trip first.
    function updateDelay(uint256 newDelay)
        external
        virtual
        override
        onlyRole(TIMELOCK_ADMIN_ROLE)
    {
        emit MinDelayChange(_arbMinDelay, newDelay);
        _arbMinDelay = newDelay;
    }

    // SLIDE 04: This returns the minimum wait time that every normal proposal has to respect.
    // The Security Council bypasses this entirely. Instead of scheduling through the proposer
    // path, it calls the UpgradeExecutor directly using the executor role, which skips the
    // delay check altogether. That is the actual mechanism behind the "less than one hour"
    // column in the Two Routes diagram.
    /// @inheritdoc TimelockControllerUpgradeable
    function getMinDelay() public view virtual override returns (uint256 duration) {
        return _arbMinDelay;
    }
}
