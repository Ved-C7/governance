// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.16;

/*
 * ============================================================
 * ANNOTATED IMPLEMENTATION WALKTHROUGH
 * Presentation: "The Governance Handbrake" - Security Councils
 * Slides 05 and 07
 * ============================================================
 *
 * This is Power II from Slide 05 (the Hot Patch). Slide 05 describes it as "force an
 * immediate logic change on a proxy contract to patch a vulnerability. Rewrites behavior
 * in a single block." This contract does that in three lines.
 *
 * To understand why this works, it helps to know how upgradeable contracts are deployed.
 * Most contracts in Arbitrum use a transparent proxy pattern where the proxy holds all
 * the state (user balances, configuration, everything) but delegates all function calls
 * to a separate implementation contract that holds the actual logic. Upgrading means
 * pointing the proxy at a new implementation. The state stays untouched. The behavior
 * changes instantly.
 *
 * The Kelp DAO rescue from Slide 07 used this function twice. Step 01 (inbox.upgradeTo(temp))
 * called perform with a temporary implementation that had the impersonation and transfer
 * logic inside it. Step 04 (inbox.upgradeTo(orig)) called perform again with the original
 * implementation to close the backdoor. Both calls were encoded in the same atomic
 * retryable ticket, so there was no window between them for the attacker to react.
 * ============================================================
 */

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

contract ProxyUpgradeAction {
    // SLIDE 05 + 07, Steps 01 and 04: admin is the ProxyAdmin that owns the proxy, target
    // is the proxy being upgraded, and newLogic is the new implementation to point it at.
    // In the Kelp rescue, calling this with a temp implementation installed the custom logic
    // that could impersonate the attacker and move the funds. Calling it again with the
    // original implementation closed the backdoor. Both calls happened in the same transaction.
    function perform(address admin, address payable target, address newLogic) public payable {
        ProxyAdmin(admin).upgrade(TransparentUpgradeableProxy(target), newLogic);
    }
}
