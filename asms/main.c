//#include <stdio.h>
//
//int add(int x, int y) { return x + y; }
//
//int main(void)
//{
//    int x = 34;
//    int y = 35;
//    int z = add(x, y);
//    printf("%d\n", z);
//    return 0;
//}

typedef struct {
    int x;
    char c;
} Strct;

int main(void)
{
    Strct s;
    s.x = 69;
    s.c = 'A';
    return 0;
}
