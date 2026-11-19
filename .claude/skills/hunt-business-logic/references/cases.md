# Candidate families (not coverage completeness)

BL-00 is the anomaly-first pre-case sweep (quantity, price/currency/rounding,
coupon, sequence, idempotency, entitlement): at most 50 value-free cards per
workflow, owned context, T0/T1, no finding.

BL-01 contract/valid path · 02 prerequisite/skip · 03 order/re-entry · 04 stale
quote/version · 05 quantity/units · 06 money/currency/rounding (lab only initially)
· 07 transaction binding (lab only) · 08 promotions · 09 credit conservation (lab)
· 10 quota/reservation · 11 refund/cancel (lab) · 12 trials/subscriptions (lab)
· 13 invites/approval · 14 same-intent retry · 15 key identity/TTL · 16 business
event authenticity (lab) · 17 compensation (lab) · 18 alternate writers.

Pick only applicable families with a documented rule and oracle. `negative-for-variant`
means that exact variant/context/control survived; it does not close siblings.
