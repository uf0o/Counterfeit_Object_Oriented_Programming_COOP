#include <stdio.h>
#include<iostream>
#include <string.h>
#include <stdlib.h>

class OffSec {
public:
    char* a = 0;
    int (*callback)(char* a) = 0;

public:
    virtual void trigger(char* a1) {
        callback(a);

    }
};
