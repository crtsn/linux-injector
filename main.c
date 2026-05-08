#include <errno.h>
#include <malloc.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#define EIP(R) (R)->rip
#define EAX(R) (R)->rax
#define USER_EAX offsetof(struct user, regs.rax)
#define ADDR2INT(R) (unsigned long long)(R)

#define MAX_CODE_SIZE		128
#define STACK_SIZE		0x1000
#define CLONE_FLAGS		CLONE_THREAD | CLONE_SIGHAND | CLONE_UNTRACED | CLONE_VM
#define MMAP_PROTS		PROT_READ | PROT_WRITE | PROT_EXEC
#define MMAP_FLAGS		MAP_PRIVATE | MAP_ANONYMOUS

static void mmap_start(void);
static void mmap_end(void);

static void clone_start(void);
static void clone_end(void);

static void payload_start(void);
static void payload_end(void);

int inject_code(int pid, unsigned char *payload, size_t payload_len);

int ptrace_attach(int pid);
int ptrace_detach(int pid);
int ptrace_getregs(int pid, struct user_regs_struct *regs);
int ptrace_setregs(int pid, struct user_regs_struct *regs);
int ptrace_continue(int pid, void *stop_addr);
int ptrace_readmem(int pid, void *addr, unsigned char *buf, size_t len);
int ptrace_writemem(int pid, void *addr, unsigned char *buf, size_t len);

int wait_stopped(int pid);

#define CHECK(A,M,...) \
  do { \
    if (!(A)) { \
      fprintf(stderr, \
          "(%s:%d: error: %d [%s]) " M "\n", \
          __FILE__, \
          __LINE__, \
          errno, \
          errno == 0 ? "None" : strerror(errno), \
          ##__VA_ARGS__); \
      errno = 0; \
      goto error; \
    } \
  } while(0)

#define DEBUG_PRINTING
#ifdef DEBUG_PRINTING
#define dprintf(M,...) printf("[*] [%s] " M "\n", __FUNCTION__, ##__VA_ARGS__)
#else
#define dprintf(...)
#endif

static void
_print_usage(void)
{
  printf("Usage: injector <target PID>\n");
}

int
main(int argc, char *argv[])
{
  if (argc != 2) {
    _print_usage();
    return 1;
  }

  int pid = atoi(argv[1]);

  size_t payload_len = (size_t)payload_end - (size_t)payload_start;
  size_t payload_size_aligned = payload_len + (sizeof(void*) - (payload_len % sizeof(void*)));
  unsigned char *payload = malloc(payload_size_aligned);
  CHECK(payload, "malloc error");
  memset(payload, 0x90, payload_size_aligned);
  memcpy(payload, (void*)payload_start, payload_len);

  CHECK(inject_code(pid, payload, payload_len), "Failed to inject code into target process %d", pid);

  printf("Code injection successful\n\n");

  return 0;
error:
  return 1;
}

struct pstate {
  struct user_regs_struct regs;
  size_t mem_len;
  unsigned char mem[1];
};

static struct pstate *target_state = NULL;

static int
_save_state(int pid)
{
  if (!target_state) {
    CHECK((target_state = calloc(1, sizeof(struct pstate) + MAX_CODE_SIZE - 1)),
        "Memory allocation error");
    target_state->mem_len = MAX_CODE_SIZE;
  }
  CHECK(ptrace_getregs(pid, &target_state->regs),
      "Failed to get registers of target process");

  // --- SYSCALL RESTART LOGIC ---
  long rax = (long)target_state->regs.rax;
  long orig_rax = (long)target_state->regs.orig_rax;
  // Check if thread was interrupted mid-syscall (ERESTARTSYS, ERESTARTNOHAND, etc.)
  if (orig_rax >= 0 && (rax == -512 || rax == -514 || rax == -513 || rax == -516)) {
      dprintf("Target interrupted in syscall %ld. Manually rewinding RIP.", orig_rax);

      target_state->regs.rip -= 2; // Rewind RIP to point back exactly at the 'syscall' instruction
      target_state->regs.rax = orig_rax; // Restore the syscall number to execute it again
      target_state->regs.orig_rax = -1; // Prevent the kernel from executing its own restart logic

      // Immediately apply these changes to the target thread so subsequent backups
      // and injections happen at the correctly rewound RIP.
      CHECK(ptrace_setregs(pid, &target_state->regs), "Failed to apply rewound registers");
  }

  dprintf("Saved registers");
  CHECK(ptrace_readmem(pid, (void*)EIP(&target_state->regs), target_state->mem, target_state->mem_len),
      "Failed to read %ld bytes of memory at target process instruction pointer",
      target_state->mem_len);
  dprintf("Saved %ld bytes from EIP %p", target_state->mem_len, target_state->mem);
  return 1;
error:
  return 0;
}

  static int
_restore_state(int pid)
{
  if (!target_state) return 1;
  CHECK(ptrace_setregs(pid, &target_state->regs),
      "Failed to set registers of target process");
  dprintf("Restored registers");
  CHECK(ptrace_writemem(pid, (void*)EIP(&target_state->regs), target_state->mem, target_state->mem_len),
      "Failed to write %ld bytes of memory to target process instruction pointer",
      target_state->mem_len);
  dprintf("Restored %ld bytes to EIP %p", target_state->mem_len, target_state->mem);
  free(target_state);
  target_state = NULL;
  return 1;
error:
  return 0;
}

  static int
_wait_trap(int pid)
{
  int status = 0;
  while(1) {
    CHECK(waitpid(pid, &status, 0) != -1,
        "waitpid error");

    if (WIFSTOPPED(status)) {
      dprintf("Process stopped with signal %d", WSTOPSIG(status));
    }
    if (WIFEXITED(status)) {
      dprintf("Process exited with signal %d", WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
      dprintf("Process terminated with signal %d", WTERMSIG(status));
      if (WCOREDUMP(status))
        dprintf("Process core dumped");
    }
    if (WIFCONTINUED(status)) {
      dprintf("Process was resumed by delivery of SIGCONT");
    }

    CHECK(!WIFEXITED(status), "Target process has exited");
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
      return 1;
  }
error:
  return 0;
}

  static int
_mmap_data(int pid, size_t len, void *base_address, int protections, int flags, void **out)
{
  int ret = 0;
  unsigned char *shellcode = NULL;

  size_t shellcode_len = (size_t)mmap_end - (size_t)mmap_start;
  // align shellcode size to 64-bit boundary
  size_t shellcode_len_aligned = shellcode_len + (sizeof(void*) - (shellcode_len % sizeof(void*)));
  shellcode = malloc(shellcode_len_aligned);
  CHECK(shellcode, "malloc error");
  memset(shellcode, 0x90, shellcode_len_aligned);
  memcpy(shellcode, (void*)mmap_start, shellcode_len);

  // get current registers
  struct user_regs_struct orig_regs, regs = {0};
  CHECK(ptrace_getregs(pid, &regs),
      "Failed to get registers of target process");
  orig_regs = regs;

  // put our arguments in the proper registers (see mmap64.asm)
  regs.rdi = (unsigned long long)base_address;
  regs.rsi = (unsigned long long)len;
  regs.rdx = (unsigned long long)((protections) ? protections : MMAP_PROTS);
  regs.r10 = (unsigned long long)((flags) ? flags : MMAP_FLAGS);
  CHECK(ptrace_setregs(pid, &regs),
      "Failed to set registers of target process");
  dprintf("Wrote our shellcode parameters into process registers");

  // write mmap code to target process EIP
  CHECK(ptrace_writemem(pid, (void*)EIP(&regs), shellcode, shellcode_len_aligned),
      "Failed to write mmap code to target process");
  dprintf("Wrote mmap code to EIP %p", (void*)EIP(&regs));

  // run mmap code and check return value
  CHECK(ptrace_continue(pid, 0), "Failed to execute mmap code");
  CHECK(_wait_trap(pid), "Error waiting for interrupt");
  dprintf("Mmap() finished execution");

  // get return value from mmap()
  CHECK(ptrace_getregs(pid, &regs),
      "Failed to get registers of target process");
  *out = (void*)EAX(&regs);
  dprintf("Mmap() returned %p", *out);
  CHECK(*out != MAP_FAILED, "Mmap() returned error");

  // restore registers
  CHECK(ptrace_setregs(pid, &orig_regs),
      "Failed to restore registers of target process");
  dprintf("Restored registers of target process");

  ret = 1;
error:
  if (shellcode)
    free(shellcode);
  return ret;
}

static int
_launch_payload(int pid, void *code_cave, size_t code_cave_size, void *stack_address, size_t stack_size, void *payload_address, size_t payload_len, void *payload_param, int flags)
{
  int ret = 0;
  unsigned char *shellcode = NULL;
  size_t shellcode_len = (size_t)clone_end - (size_t)clone_start;
  CHECK(shellcode_len > 0, "ftell error");
  CHECK(shellcode_len <= code_cave_size, "Shellcode is too big (%ld) for allocated code cave", shellcode_len);
  shellcode = malloc(code_cave_size);
  CHECK(shellcode, "malloc error");
  memset(shellcode, 0x90, code_cave_size); // fill with NOPs
  memcpy(shellcode, (void*)clone_start, shellcode_len);

  // get current registers
  struct user_regs_struct regs = {0};
  CHECK(ptrace_getregs(pid, &regs),
      "Failed to get registers of target process");

  // put our arguments in the proper registers (see clone64.asm)
  regs.rax = (unsigned long long)code_cave_size;
  regs.rdi = (unsigned long long)((flags) ? flags : CLONE_FLAGS);
  regs.rsi = (unsigned long long)stack_address;
  regs.rdx = (unsigned long long)stack_size;
  regs.rcx = (unsigned long long)payload_address;
  regs.r8  = (unsigned long long)payload_len;
  regs.r9  = (unsigned long long)payload_param;
  // move EIP to our code cave
  EIP(&regs) = ADDR2INT(code_cave);
  CHECK(ptrace_setregs(pid, &regs),
      "Failed to set registers of target process");
  dprintf("Wrote our shellcode parameters into process registers. EIP: %p", code_cave);

  // write shellcode to target process code cave
  CHECK(ptrace_writemem(pid, code_cave, shellcode, code_cave_size),
      "Failed to write clone trampoline code to target process");
  dprintf("Wrote clone trampoline code to address %p", code_cave);

  // run shellcode and check return value
  CHECK(ptrace_continue(pid, code_cave), "Failed to execute clone trampoline code");
  CHECK(_wait_trap(pid), "Error waiting for interrupt");
  dprintf("Clone() finished execution");
  CHECK(ptrace_getregs(pid, &regs),
      "Failed to get registers of target process");
  dprintf("New thread ID: %lld", EAX(&regs));
  CHECK((int)EAX(&regs) != -1, "Clone() returned error");

  // no need to restore registers, as we're about to call _restore_state()

  dprintf("Successfully launched payload");

  ret = 1;
error:
  if (ret == 0)
    dprintf("Failed to launch payload");
  if (shellcode)
    free(shellcode);
  return ret;
}

  int
inject_code(int pid, unsigned char *payload, size_t payload_len)
{
  int ret = 0, status = 0;
  void *payload_addr = NULL,
       *stack = NULL,
       *code_cave = NULL,
       *payload_aligned = NULL;
  size_t payload_size;

  // align shellcode size to 64-bit boundary
  payload_size = payload_len + (sizeof(void*) - (payload_len % sizeof(void*)));
  payload_aligned = malloc(payload_size);
  CHECK(payload_aligned, "malloc() error");
  memset(payload_aligned, 0x90, payload_size); // fill with NOPs
  memcpy(payload_aligned, payload, payload_len);

  printf("Injecting into target process %d\n", pid);

  // attach to process
  CHECK(ptrace_attach(pid), "Error attaching to target process %d", pid);
  dprintf("Attached to process");

  // wait to make sure process is in ptrace-stop state before continuing,
  // otherwise we may inadvertently kill the process
  CHECK(wait_stopped(pid), "Failed to wait until target process in stopped state");
  dprintf("Process is in stopped state");


  // save state (which handles the syscall rollback if needed)
  CHECK(_save_state(pid), "Failed to state target process state");
  dprintf("Saved state of target process");

  // allocate payload space
  CHECK(_mmap_data(pid, payload_size, NULL, 0, 0, &payload_addr),
        "Failed to allocate space for payload");
  dprintf("Allocated space for payload at location %p", payload_addr);

  // copy payload
  CHECK(ptrace_writemem(pid, payload_addr, payload_aligned, payload_size),
        "Failed to copy payload to target process");
  dprintf("Wrote payload to target process at address %p", payload_addr);

  // allocate new stack
  CHECK(_mmap_data(pid, STACK_SIZE, NULL, 0, 0, &stack),
        "Failed to allocate space for new stack");
  stack += STACK_SIZE; // use top address as stack base, since stack grows downward
  dprintf("Allocated new stack at location %p", stack);

  // allocate space for code cave
  CHECK(_mmap_data(pid, MAX_CODE_SIZE, NULL, 0, 0, &code_cave),
        "Failed to allocate space for code cave");
  dprintf("Allocated space for code cave at location %p", code_cave);

  // launch payload via clone(2)
  dprintf("Launching payload in new thread");
  CHECK(_launch_payload(pid, code_cave, MAX_CODE_SIZE, stack, STACK_SIZE, payload_addr, payload_size, NULL, 0),
        "Failed to launch payload");

  ret = 1;
error:
  if (payload_aligned)
    free(payload_aligned);
  _restore_state(pid);
  ptrace_detach(pid);
  return ret;
}

int
ptrace_attach(int pid)
{
  CHECK(ptrace(PTRACE_ATTACH, (pid_t)pid, NULL, NULL) == 0,
        "Failed to attach to target process %d", pid);
  return 1;
error:
  return 0;
}

int
ptrace_detach(int pid)
{
  CHECK(ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL) == 0,
        "Failed to detach to target process %d", pid);
  return 1;
error:
  return 0;
}

int
ptrace_getregs(int pid, struct user_regs_struct *regs)
{
  CHECK(ptrace(PTRACE_GETREGS, (pid_t)pid, NULL, regs) == 0,
        "Failed to get registers of target process %d", pid);
  return 1;
error:
  return 0;
}

int
ptrace_setregs(int pid, struct user_regs_struct *regs)
{
  CHECK(ptrace(PTRACE_SETREGS, (pid_t)pid, NULL, regs) == 0,
        "Failed to set registers of target process %d", pid);
  return 1;
error:
  return 0;
}

int
wait_stopped(int pid)
{
  int status = 0;
  while(1) {
    dprintf("START WAITPID %d", pid);
    CHECK(waitpid(pid, &status, 0) != -1,
          "waitpid error");
    dprintf("STOP WAITPID %d", pid);

    if (WIFSTOPPED(status)) {
      dprintf("Process stopped with signal %d", WSTOPSIG(status));
    }
    if (WIFEXITED(status)) {
      dprintf("Process exited with signal %d", WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
      dprintf("Process terminated with signal %d", WTERMSIG(status));
      if (WCOREDUMP(status))
	dprintf("Process core dumped");
    }
    if (WIFCONTINUED(status)) {
      dprintf("Process was resumed by delivery of SIGCONT");
    }

    CHECK(!WIFEXITED(status), "Target process has exited");
    if (WIFSTOPPED(status))
      break;
  }
  return 1;
error:
  return 0;
}

int
ptrace_continue(int pid, void *stop_addr)
{
  dprintf("Continuing execution of target process %d", pid);
  CHECK(ptrace(PTRACE_CONT, (pid_t)pid, NULL, NULL) == 0,
        "Failed to continue execution of target process %d", pid);
  return 1;
error:
  return 1;
}

int
ptrace_readmem(int pid, void *addr, unsigned char *buf, size_t len)
{
  CHECK(len % sizeof(void*) == 0, "Length of memory to read must be word-aligned");

  size_t wordlen = len / sizeof(void*);
  void **wordbuf = (void**)buf;

  errno = 0;
  for (size_t i = 0; i < wordlen; i++) {
    wordbuf[i] = (void*)ptrace(PTRACE_PEEKDATA, (pid_t)pid, addr + (i * sizeof(void*)), NULL);
    CHECK(errno == 0,
          "Failed to read memory of target process %d at location %p",
    pid,
    addr + (i * sizeof(void*)));
  }
  return 1;
error:
  return 0;
}

int
ptrace_writemem(int pid, void *addr, unsigned char *buf, size_t len)
{
  CHECK(len % sizeof(void*) == 0, "Length of memory to read must be word-aligned");

  size_t wordlen = len / sizeof(void*);
  void **wordbuf = (void**)buf;

  for (size_t i = 0; i < wordlen; i++) {
    long result = ptrace(PTRACE_POKEDATA, (pid_t)pid, addr + (i * sizeof(void*)), wordbuf[i]);
    CHECK(result == 0,
          "Failed to write memory to target process %d at location %p",
      pid,
      addr + (i * sizeof(void*)));
  }
  return 1;
error:
  return 0;
}

__attribute__((naked, aligned(8)))
static void
mmap_start() {
    __asm__ (
        ".intel_syntax noprefix;"  // Switch to Intel syntax
        "xor rax, rax;"
        "mov al, 9;"               // SYS_MMAP
        "xor		r8,r8;"            // fd
        "xor		r9,r9;"            // offset
        "syscall;"
        "int3;"                    // interrupt for caller to trap
        ".att_syntax;"             // Switch back to AT&T (good practice)
    );
}

void
mmap_end()
{
}

__attribute__((naked, aligned(8)))
static void
clone_start() {
__asm__ (
        ".intel_syntax noprefix;"
        "start:" 

        "mov rsp, rsi;" // start using new stack

        "push rax;"             // shellcode size
        "lea r11, [rip]; 1: sub r11, (1b - start); push r11;" // shellcode addr
        "push rdx;"             // stack size
        "push rsi;"             // stack addr
        "push r8;"              // payload size
        "push rcx;"             // payload addr
        "push rcx;"             // payload addr
        "push r9;"              // payload param
        "mov rsi, rsp;"         // update stack pointer for clone

        // 5. Execute SYS_CLONE (56)
        "mov rax, 56;"
        "xor rdx, rdx;"         // ptid = NULL
        "xor r10, r10;"         // ctid = NULL
        "xor r8, r8;"           // regs = NULL
        "syscall;"

        "test rax, rax;"
        "jz child_thread;"

        // Parent: Trap back to injector
        "int3;"

    "child_thread:"
        // 6. Child: Execute Payload
        "pop rdi;"              // Pop r9 (parameter)
        "pop rax;"              // Pop rcx (address)
        "call rax;"

    "cleanup:"
        "xor rax,rax;"
        "mov al, 11;"          // SYS_MUNMAP
        "xor rdx,rdx;"
        "mov dl,3;"
    "munmap:"
        "pop rdi;"              // Pop addr
        "pop rsi;"              // Pop size
        "syscall;"
        "dec dl;"
        "jnz munmap;"

    "child_exit:"
        "mov rax, 60;"          // SYS_EXIT
        "xor rdi, rdi;"
        "syscall;"

        ".att_syntax;"
    );
}

void
clone_end()
{
}

__attribute__((naked, aligned(8)))
static void
payload_start() {
    __asm__ (
        ".intel_syntax noprefix;"  // Switch to Intel syntax
        "jmp get_addr;"            // 1. Jump to the call
        "output_msg:"
        "xor rax, rax;"
        "mov al, 1;"               // SYS_WRITE
        "mov rdi, rax;"            // STDOUT (1)
        "pop rsi;"                 // 3. Pop string address into RSI
        "xor rdx, rdx;"
        "mov dl, 27;"              // Length of string
        "syscall;"
        "ret;"                    // Trap to return control to injector
        "get_addr:"
        "call output_msg;"         // 2. Call back; pushes string address to stack
        ".ascii \"hello from shellcode land!\\n\";"
        ".att_syntax;"             // Switch back to AT&T (good practice)
    );
}

void
payload_end()
{
}

