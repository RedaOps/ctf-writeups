Easy challenge:
* Stack canaries
* Buffer overflow with scanf for each 8 bytes.
* We can avoid writing to the canary by sending `.` for the canary double.
* Leak libc then ret2libc with `system('/bin/sh')`