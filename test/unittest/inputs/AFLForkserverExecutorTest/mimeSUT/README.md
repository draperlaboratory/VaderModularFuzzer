# Mime SUT design notes

Due to requirements to test older versions of AFL compiler instrumentation method for handshaking, the `mime_legacy` SUT is maintained as a commited binary in the source tree instead of levying the need to maintain an older version of the AFL compiler toolchain in all test containers.