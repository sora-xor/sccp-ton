// SPDX-License-Identifier: BSD-4-Clause
//
// Minimal contract used for validating SCCP codec + keccak256 in TVM.

import "messages"
import "sccp-codec"

type Allowed = TopUpTons

fun onInternalMessage(in: InMessage) {
    val _ = lazy Allowed.fromSlice(in.body);
    // no-op
}

get fun get_message_id(
    sourceDomain: uint32,
    destDomain: uint32,
    nonce: uint64,
    soraAssetId: uint256,
    amount: coins,
    recipient32: uint256,
): uint256 {
    return sccpBurnMessageIdV1(sourceDomain, destDomain, nonce, soraAssetId, amount, recipient32);
}

