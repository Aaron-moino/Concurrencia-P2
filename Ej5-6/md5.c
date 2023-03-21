#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <threads.h>

#include "options.h"
#include "queue.h"


#define MAX_PATH 1024
#define BLOCK_SIZE (10*1024*1024)
#define MAX_LINE_LENGTH (MAX_PATH * 2)


struct file_md5 {
    char *file;
    unsigned char *hash;
    unsigned int hash_size;
};

struct thr_args_getEntries {
    char *dir;
    queue *q;
    mtx_t mutex;
};

struct thr_args_calculationHash {
    queue *in_q, *out_q;
    mtx_t *mtx;
    int dirname_len;
    FILE * out;
};

struct thr_args_Writing {
    queue *out_q;
    int dirname_len;
    FILE *out;
    struct file_md5 *md5;
    mtx_t mtx;
};

struct thr_args_Read_File {
    char *dir;
    char * file;
    queue *q;
    mtx_t mutex;
};

struct thr_args_checkHashes {
    queue *in_q;
    mtx_t *mutex;
    int id;
};

void get_entries(char *dir, queue q);

int aux_getEntries(void *arg);

int aux_calculationHash(void *arg);

int aux_Writing(void *arg);

int aux_Read_File(void * arg);

int aux_check_Hashes(void *arg);

void print_hash(struct file_md5 *md5) {
    for (int i = 0; i < md5->hash_size; i++) {
        printf("%02hhx", md5->hash[i]);
    }
}

void read_hash_file(char *file, char *dir, queue q) {
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    char *file_name, *hash;
    int hash_len;

    if ((fp = fopen(file, "r")) == NULL) {
        printf("Could not open %s : %s\n", file, strerror(errno));
        exit(0);
    }

    while (fgets(line, MAX_LINE_LENGTH, fp) != NULL) {
        char *field_break;
        struct file_md5 *md5 = malloc(sizeof(struct file_md5));

        if ((field_break = strstr(line, ": ")) == NULL) {
            printf("Malformed md5 file\n");
            exit(0);
        }
        *field_break = '\0';

        file_name = line;
        hash = field_break + 2;
        hash_len = strlen(hash);

        md5->file = malloc(strlen(file_name) + strlen(dir) + 2);
        sprintf(md5->file, "%s/%s", dir, file_name);
        md5->hash = malloc(hash_len / 2);
        md5->hash_size = hash_len / 2;


        for (int i = 0; i < hash_len; i += 2)
            sscanf(hash + i, "%02hhx", &md5->hash[i / 2]);

        q_insert(q, md5);
    }

    fclose(fp);
}

void sum_file(struct file_md5 *md5) {
    EVP_MD_CTX *mdctx;
    int nbytes;
    FILE *fp;
    char *buf;

    if ((fp = fopen(md5->file, "r")) == NULL) {
        printf("Could not open %s\n", md5->file);
        return;
    }

    buf = malloc(BLOCK_SIZE);
    const EVP_MD *md = EVP_get_digestbyname("md5");

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);

    while ((nbytes = fread(buf, 1, BLOCK_SIZE, fp)) > 0)
        EVP_DigestUpdate(mdctx, buf, nbytes);

    md5->hash = malloc(EVP_MAX_MD_SIZE);
    EVP_DigestFinal_ex(mdctx, md5->hash, &md5->hash_size);

    EVP_MD_CTX_destroy(mdctx);
    free(buf);
    fclose(fp);
}

void recurse(char *entry, void *arg) {
    queue q = *(queue *) arg;
    struct stat st;

    stat(entry, &st);

    if (S_ISDIR(st.st_mode))
        get_entries(entry, q);
}

void add_files(char *entry, void *arg) {
    queue q = *(queue *) arg;
    struct stat st;

    stat(entry, &st);

    if (S_ISREG(st.st_mode))
        q_insert(q, strdup(entry));

}

void walk_dir(char *dir, void (*action)(char *entry, void *arg), void *arg) {
    DIR *d;
    struct dirent *ent;
    char full_path[MAX_PATH];

    if ((d = opendir(dir)) == NULL) {
        printf("Could not open dir %s\n", dir);
        return;
    }

    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        snprintf(full_path, MAX_PATH, "%s/%s", dir, ent->d_name);

        action(full_path, arg);
    }

    closedir(d);
}

void get_entries(char *dir, queue q) {
    walk_dir(dir, add_files, &q);
    walk_dir(dir, recurse, &q);
}

void check(struct options opt) {

    queue in_q;
    thrd_t thrd_Read_File,*thrd_check_Hashes=malloc(sizeof (thrd_t)*opt.num_threads);
    struct thr_args_Read_File args1;
    struct thr_args_checkHashes *args2= malloc(sizeof (struct thr_args_checkHashes)*opt.num_threads);
    mtx_t mutex,checks;
    int i;

    mtx_init(&mutex,mtx_plain);
    mtx_init(&checks,mtx_plain);

    in_q = q_create(1);

    args1.file=opt.file;
    args1.dir=opt.dir;
    args1.q=&in_q;
    mtx_init(&args1.mutex,mtx_plain);

    thrd_create(&thrd_Read_File,aux_Read_File,&args1);

    for(i=0;i<opt.num_threads;i++){
        args2[i].in_q=&in_q;
        args2[i].mutex=&checks;
        args2[i].id=i;
        thrd_create(&thrd_check_Hashes[i],aux_check_Hashes,&args2[i]);
    }

    for(i=0;i<opt.num_threads;i++){
        thrd_join(thrd_check_Hashes[i],NULL);
    }

    thrd_join(thrd_Read_File,NULL);

    q_destroy(in_q);

    mtx_destroy(&args1.mutex);
    mtx_destroy(&mutex);
    free(thrd_check_Hashes);
    free(args2);
}

int aux_Read_File(void * arg){
    struct thr_args_Read_File *args = arg;
    mtx_lock(&args->mutex);
    read_hash_file(args->file,args->dir ,*args->q);
    queue_terminado(*args->q);
    mtx_unlock(&args->mutex);
    return 0;
}

int aux_check_Hashes(void * arg){
    struct thr_args_checkHashes *args=arg;
    struct file_md5 *md5_in, md5_file;

    while ((md5_in = q_remove(*args->in_q))) {
        mtx_lock(args->mutex);
        md5_file.file = md5_in->file;
        printf("%d Comprobando Hash de %s\n",args->id,md5_file.file);

        sum_file(&md5_file);

        if (memcmp(md5_file.hash, md5_in->hash, md5_file.hash_size) != 0) {
            printf("File %s doesn't match.\nFound:    ", md5_file.file);
            print_hash(&md5_file);
            printf("\nExpected: ");
            print_hash(md5_in);
            printf("\n");
        }

        free(md5_file.hash);

        free(md5_in->file);
        free(md5_in->hash);
        free(md5_in);
        mtx_unlock(args->mutex);
    }
    return 0;
}

void sum(struct options opt) {
    struct thr_args_calculationHash *arg_cH = malloc(sizeof(struct thr_args_calculationHash) * opt.num_threads);
    struct thr_args_getEntries arg_getEntries;
    thrd_t *thrd_cH = malloc(sizeof(thrd_t) * opt.num_threads);
    thrd_t thrd_getEntries;
    mtx_t *mtx_cH = malloc(sizeof(mtx_t));
    queue in_q, out_q;
    FILE *out;
    struct file_md5 *md5 = malloc(sizeof(struct file_md5));
    int dirname_len;

    in_q = q_create(opt.queue_size);
    out_q = q_create(opt.queue_size);

    mtx_init(&arg_getEntries.mutex, mtx_plain);
    arg_getEntries.dir = opt.dir;
    arg_getEntries.q = &in_q;

    thrd_create(&thrd_getEntries, aux_getEntries, &arg_getEntries);

    queue_terminado(out_q);

    if ((out = fopen(opt.file, "w")) == NULL) {
        printf("Could not open output file\n");
        exit(0);
    }

    dirname_len = strlen(opt.dir) + 1; // length of dir + /

    mtx_init(mtx_cH, mtx_plain);
    for (int i = 0; i < opt.num_threads; i++) {
        arg_cH[i].in_q = &in_q;
        arg_cH[i].out_q = &out_q;
        arg_cH[i].mtx = mtx_cH;
        arg_cH[i].dirname_len=dirname_len;
        arg_cH[i].out=out;
        thrd_create(&thrd_cH[i], aux_calculationHash, &arg_cH[i]);
    }

    for (int j = 0; j < opt.num_threads; j++) {
        thrd_join(thrd_cH[j], NULL);
    }

    thrd_join(thrd_getEntries, NULL);

    mtx_destroy(mtx_cH);
    mtx_destroy(&arg_getEntries.mutex);

    free(thrd_cH);
    free(mtx_cH);
    free(md5);
    free(arg_cH);
    fclose(out);
    q_destroy(in_q);
    q_destroy(out_q);

}

int aux_getEntries(void *arg) {
    struct thr_args_getEntries *args = arg;
    mtx_lock(&args->mutex);
    get_entries(args->dir, *args->q);
    queue_terminado(*args->q);
    mtx_unlock(&args->mutex);
    return 0;
}

int aux_calculationHash(void *arg) {
    struct thr_args_calculationHash *args = arg;
    mtx_lock(args->mtx);
    char *ent;
    thrd_t thrd_w;
    struct thr_args_Writing args1;
    struct file_md5 * md5;

    while ((ent = q_remove(*args->in_q)) != NULL) {

        args1.out_q=args->out_q;
        args1.out=args->out;
        args1.dirname_len=args->dirname_len;
        mtx_init(&args1.mtx,mtx_plain);
        md5 = malloc(sizeof(struct file_md5));

        md5->file = ent;
        sum_file(md5);

        q_insert(*args->out_q, md5);
        thrd_create(&thrd_w,aux_Writing,&args1);
        thrd_join(thrd_w,NULL);
        mtx_destroy(&args1.mtx);
        md5=NULL;
    }
    mtx_unlock(args->mtx);
    return 0;
}

int aux_Writing(void *arg) {
    struct thr_args_Writing *args = arg;
    struct file_md5 * md5;
    mtx_lock(&args->mtx);
    while ((md5 = q_remove(*args->out_q)) != NULL) {
        fprintf(args->out, "%s: ", md5->file + args->dirname_len);

        for (int i = 0; i < md5->hash_size; i++)
            fprintf(args->out, "%02hhx", md5->hash[i]);
        fprintf(args->out, "\n");

        free(md5->file);
        free(md5->hash);
        free(md5);
    }
    mtx_unlock(&args->mtx);
    return 0;
}

int main(int argc, char *argv[]) {

    struct options opt;

    opt.num_threads = 5;
    opt.queue_size = 1000;
    opt.check = true;
    opt.file = NULL;
    opt.dir = NULL;

    read_options(argc, argv, &opt);


    if (opt.check) {
        check(opt);
    } else {
        sum(opt);

    }
}
