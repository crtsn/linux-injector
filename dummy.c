#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  while (1) {
    printf("sleeping...\n");
    sleep(10);
  }
  return 0;
}


// #include <stdio.h>
// #include <stdlib.h>
// #include <poll.h>
// #include <pthread.h>
// #include <unistd.h>
// #include <signal.h>
// 
// void* network_thread(void* arg) {
//     struct pollfd fds[1];
//     fds[0].fd = STDIN_FILENO;
//     fds[0].events = POLLIN;
// 
//     printf("[Thread] Entering ppoll (Internal: __GI_ppoll)\n");
//     // This call is a "cancellation point"
//     ppoll(fds, 1, NULL, NULL);
// 
//     return NULL;
// }
// 
// int main() {
//     pthread_t tid;
//     printf("[Main] Target PID: %d\n", getpid());
// 
//     // Create a thread to force GLIBC to use thread-safe/cancellable syscall wrappers
//     pthread_create(&tid, NULL, network_thread, NULL);
// 
//     pthread_join(tid, NULL);
//     return 0;
// }
