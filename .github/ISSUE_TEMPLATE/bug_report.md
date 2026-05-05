---
name: Bug report
about: Report a bug in mwan4
title: "[mwan4] "
labels: bug
assignees: stangri

---

**Describe the bug**

A clear and concise description of what the bug is.

**To reproduce**

1.
2.

**Expected behavior**

A clear and concise description of what you expected to happen.

**Diagnostic info**

Please run the following and paste the output (you can mask sensitive parts). See [Getting Help](https://docs.openwrt.melmac.ca/mwan4/#getting-help) in the docs for context.

```sh
ubus call system board
uci export network
uci export mwan4
mwan4 status
nft list table inet fw4
```
