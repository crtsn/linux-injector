# linux-injector
Utility for injecting executable code into a running process on x64 Linux. It uses `ptrace()` to attach to a process, then `mmap()`'s memory regions for the injected code, a new stack, and space for trampoline shellcode. Finally, the trampoline in the target process is used to create a new thread and execute the chosen shellcode, so the main thread is allowed to continue. This project borrows from a number of other projects and research, see References below.

It also now loading project itself as .so. And all of injector code moved to a single file to be a single file example. Also it treats binary as .so when loaded on target, just for lulz but also for code locality.

## Disclaimer
Unfortunately there was high usage of **LLM** during changing this code, but it was only way to figure out this relatively quickly. But sometimes I was smarter than LLMs.

## Building
```sh
make
```

## Included programs and files
* **dummy**: A trivial program for injecting into. Prints a message every second, then sleeps.
* **injector**: The main program for injecting executable code into a running process. Simply provide it with the PID of the process to inject into:

  `./injector 1234`

## References
* original repo
* Used some info for loading shared library based on [linux-inject](https://github.com/gaffe23/linux-inject)


## License?
- Not sure about licensing, but mostly code based on work of Dan Staples:
Copyright (c) 2015, Dan Staples. This code is available under the [GNU General Public License, version 3](https://www.gnu.org/copyleft/gpl.html).

