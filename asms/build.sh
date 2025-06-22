#!/bin/bash

function assemble
{
    fasm "$1.asm" -m 524288 &&
    chmod +x $1
}

assemble "hello"
#assemble "loop"
assemble "variables"
