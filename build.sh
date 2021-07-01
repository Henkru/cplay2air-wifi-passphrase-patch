#!/bin/sh

arm-linux-gnueabi-gcc -Wall -shared -g -fPIC -o inject.o inject.c && arm-linux-gnueabi-strip inject.o
