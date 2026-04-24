// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.16;

/*
 * ============================================================
 * ANNOTATED IMPLEMENTATION WALKTHROUGH
 * Presentation: "The Governance Handbrake" - Security Councils
 * Slide 05
 * ============================================================
 *
 * This is Power I from Slide 05, the Circuit Breaker. Slide 05 describes it as
 * "instantly freeze deposits, withdrawals, or trading on specific contracts. Least
 * destructive, stops the bleed without moving funds." This contract is exactly that,
 * in eleven lines of Solidity.
 *
 * All action contracts in this repo follow the same pattern: they are stateless, they
 * have one function called perform(), and they get called by the UpgradeExecutor. Being
 * stateless means they are easy to audit and cannot be tampered with after deployment.
 *
 * In an emergency using the Security Council route from Slide 04, the council would
 * detect the problem, coordinate out of band, collect nine Gnosis Safe signatures on a
 * transaction calling UpgradeExecutor.execute with this contract as the target, and
 * broadcast. The inbox freezes in one block with no timelock delay.
 *
 * However, as Slide 06 shows, a pause alone was not enough in the Kelp rescue. Pausing
 * stops new deposits but does not recover funds that are already bridged. That required
 * Power III, the arbitrary transaction, to intercept the ETH mid-flight.
 *
 * UnpauseInboxAction.sol is the mirror contract that lifts the freeze.
 * ============================================================
 */

import "../address-registries/interfaces.sol";

contract PauseInboxAction {
    IInboxGetter public immutable addressRegistry;

    constructor(IInboxGetter _addressRegistry) {
        addressRegistry = _addressRegistry;
    }

    // SLIDE 05, Power I: One line. Calling perform() freezes the Inbox, which stops all
    // new L1 to L2 message submissions and ETH deposits. No funds are moved. Slide 05 calls
    // this the least destructive option because it stops the damage without touching anything
    // that is already in the protocol. In the Kelp rescue, a pause alone would not have been
    // enough because the attacker had already bridged the ETH over. Stopping new deposits
    // does not get back what is already there.
    function perform() external {
        addressRegistry.inbox().pause();
    }
}
