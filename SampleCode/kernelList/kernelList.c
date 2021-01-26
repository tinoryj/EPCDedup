#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

struct entry {
    int data;
    LIST_ENTRY(entry) entries;              /* List. */
};

LIST_HEAD(listhead, entry);

int main(void)
{
    struct entry *n1, *n2, *n3, *np;
    struct listhead head;                   /* List head. */
    int i;
    LIST_INIT(&head);                       /* Initialize the list. */
    n1 = malloc(sizeof(struct entry));      /* Insert at the head. */
    LIST_INSERT_HEAD(&head, n1, entries);
    n2 = malloc(sizeof(struct entry));      /* Insert after. */
    LIST_INSERT_AFTER(n1, n2, entries);
    n3 = malloc(sizeof(struct entry));      /* Insert before. */
    LIST_INSERT_BEFORE(n2, n3, entries);
    i = 0;                                  /* Forward traversal. */
    LIST_FOREACH(np, &head, entries)
        np->data = i++;
    LIST_REMOVE(n2, entries);               /* Deletion. */
    free(n2);
                                            /* Forward traversal. */
    LIST_FOREACH(np, &head, entries)
        printf("%i\n", np->data);
                                            /* List Deletion. */
    n1 = LIST_FIRST(&head);
    while (n1 != NULL) {
        n2 = LIST_NEXT(n1, entries);
        free(n1);
        n1 = n2;
    }
    LIST_INIT(&head);
    exit(EXIT_SUCCESS);
}