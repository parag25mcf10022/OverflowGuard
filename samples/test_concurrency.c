#include <pthread.h>

int global_counter = 0;

void* thread_func(void* arg) {
    global_counter++;
    return NULL;
}

int main() {
    pthread_t t1;
    pthread_create(&t1, NULL, thread_func, NULL);
    return 0;
}
