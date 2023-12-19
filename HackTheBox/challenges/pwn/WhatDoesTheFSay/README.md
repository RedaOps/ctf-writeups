* Leak canary and libc address with format string exploit, right after that there's a buffer overflow
* First, run the rop to leak PUTS address to see what libc the server is using (libc not included in download archive). Can use a libc search DB for this.
* Then, run the solver with the correct libc offsets doing a simple ret2system attack.
* Calculate libc base and rop to `system('/bin/sh')`
* Be careful to include canary when overflowing.