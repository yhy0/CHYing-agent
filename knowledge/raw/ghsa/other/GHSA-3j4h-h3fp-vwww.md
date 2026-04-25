# LNbits improperly handles potential network and payment failures when using Eclair backend

**GHSA**: GHSA-3j4h-h3fp-vwww | **CVE**: CVE-2024-34694 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-754

**Affected Packages**:
- **lnbits** (pip): < 0.12.6

## Description

### Summary

Paying invoices in Eclair that do not get settled within the internal timeout (about 30s) lead to a payment being considered failed, even though it may still be in flight.

### Details

Using `blocking: true` on the API call will lead to a timeout error if a payment does not get settled in the 30s timeout with the error: `Ask timed out on [Actor[akka://eclair-node/user/$l#134241942]] after [30000 ms]. Message of type [fr.acinq.eclair.payment.send.PaymentInitiator$SendPaymentToNode]. A typical reason for AskTimeoutException is that the recipient actor didn't send a reply.`
https://github.com/lnbits/lnbits/blob/c04c13b2f8cfbb625571a07dfddeb65ea6df8dac/lnbits/wallets/eclair.py#L138

This is considered a payment failure by parts of the code, and assumes the payment is not going to be settled after:
https://github.com/lnbits/lnbits/blob/c04c13b2f8cfbb625571a07dfddeb65ea6df8dac/lnbits/wallets/eclair.py#L144
https://github.com/lnbits/lnbits/blob/c04c13b2f8cfbb625571a07dfddeb65ea6df8dac/lnbits/wallets/eclair.py#L141
https://github.com/lnbits/lnbits/blob/c04c13b2f8cfbb625571a07dfddeb65ea6df8dac/lnbits/wallets/eclair.py#L146

The best way to fix this is to check the payment status after an error, and when not sure, always consider a payment still in flight.

### PoC

A very simple way to exploit this is:
- Create a hold invoice
- Pay the invoice with the LNbits server backed by an Eclair node, until it times out
- Settle the hold invoice

### Impact

This vulnerability can lead to a total loss of funds for the node backend.

