The program loads the flag into a mapped memory segment, then deletes the address of that segment from the stack and executes user input.

A simple egghunter shellcode is enough, just print the buffer instead of jumping to it.