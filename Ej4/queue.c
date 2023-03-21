#include <stdlib.h>
#include <threads.h>
#include <stdbool.h>

// circular array
typedef struct _queue {
    int size;
    int used;
    int first;
    void **data;
    mtx_t mutex_cola;
    cnd_t *queue_full;
    cnd_t *queue_empty;
    bool terminado;
} _queue;

#include "queue.h"

queue q_create(int size) {
    queue q = malloc(sizeof(_queue));

    q->size = size;
    q->used = 0;
    q->first = 0;
    q->data = malloc(size * sizeof(void *));
    q->queue_full = malloc(sizeof(cnd_t));
    q->queue_empty = malloc(sizeof(cnd_t));
    cnd_init(q->queue_full);
    cnd_init(q->queue_empty);
    mtx_init(&q->mutex_cola, mtx_plain);
    q->terminado = false;
    return q;
}

int q_elements(queue q) {
    return q->used;
}


int q_insert(queue q, void *elem) {
    mtx_lock(&q->mutex_cola);
    while (q->used == q->size && !q->terminado) {
        cnd_wait(q->queue_full, &q->mutex_cola);
    }

    q->data[(q->first + q->used) % q->size] = elem;
    q->used++;

    if (q->used == 1) {
        cnd_broadcast(q->queue_empty);
    }
    mtx_unlock(&q->mutex_cola);
    return 0;
}

void *q_remove(queue q) {
    void *res;
    void *resultado;
    mtx_lock(&q->mutex_cola);
    // if (q->used == 0) return NULL;
    while (q->used== 0 && !q->terminado) {
        cnd_wait(q->queue_empty, &q->mutex_cola);
    }
    if(q->used == 0){
        mtx_unlock(&q->mutex_cola);
        return NULL;
    }
    res = q->data[q->first];
    resultado = res;

    q->first = (q->first + 1) % q->size;
    q->used--;

    if (q->used== q->size - 1) {
        cnd_broadcast(q->queue_full);
    }
    mtx_unlock(&q->mutex_cola);
    return resultado;
}

void queue_terminado(queue q){
    mtx_lock(&q->mutex_cola);
    q->terminado = true;
    cnd_broadcast(q->queue_empty);
    mtx_unlock(&q->mutex_cola);
}

void q_destroy(queue q) {

    mtx_destroy(&q->mutex_cola);
    cnd_destroy(q->queue_full);
    cnd_destroy(q->queue_empty);
    free(q->queue_empty);
    free(q->queue_full);
    free(q->data);
    free(q);
}
