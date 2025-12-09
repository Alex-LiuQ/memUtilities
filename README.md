## memUtilities
Ultimate memory-leak hunting toolkit for OpenWrt &amp; embedded Linux

High-precision LD_PRELOAD-based malloc/free hook + testing utilities specially crafted for resource-constrained embedded environments (routers, automotive, IoT).

## Features:
 - libmalloc_hook.so – accurate heap tracking, full backtrace, automatically filters musl popen false positives
 - leak_test         – reproduces a real-world 24-byte leak that starts 70 s after launch
 - test_malloc_hook  – stress test with threads, popen, strdup, calloc – everything that usually crashes a hook
 - memlogger         – lightweight long-term /proc/meminfo + AnonPages monitor

Successfully used on real OpenWrt routers to catch and fix “memory slowly grows a few hundred KB per hour” issues.

If you are fighting mysterious AnonPages growth or false positives from popen – this is your weapon.

## Quick Start (30 seconds)
git clone https://github.com/Alex-LiuQ/memUtilities.git
cd memUtilities
make                     # builds libmalloc_hook.so + all test programs
make run_leak            # runs leak_test with the hook injected

## You will see full backtrace pointing to leak_memory()
cat /tmp/memhook.log | grep LEAK

## Build & Usage
make                     # compile everything
LD_PRELOAD=./libmalloc_hook.so ./your_program          # inject into any binary
tail -f /tmp/memhook.log                                 # live report (every ~60 s)

## Convenience targets
make run_leak      # run the realistic leak test with hook
make run_test      # run the stress test
make clean

## License
Please read the LICENSE file.


