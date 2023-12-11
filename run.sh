#!/bin/bash

echo "Start to compile DOCA Graph code"
echo ""

sudo gcc -L ../../../lib/aarch64-linux-gnu/ -Wno-missing-braces -D DOCA_ALLOW_EXPERIMENTAL_API ./src/graph_main.c ./src/graph_sample.c ../../common.c ../../../applications/common/src/utils.c -I../../../applications/common/src/ -I../ -I../../ -I ../../../ -I../../../include/ -ldoca_common -ldoca_dma -ldoca_sha -o graph_sample

echo "Start to compile Pthread code"
echo ""
sudo gcc -L ../../../lib/aarch64-linux-gnu/ -Wno-missing-braces -D DOCA_ALLOW_EXPERIMENTAL_API ./src/pthread_sample.c ../../common.c ../../../applications/common/src/utils.c -I../../../applications/common/src/ -I../ -I../../ -I ../../../ -I../../../include/ -ldoca_common -ldoca_dma -ldoca_sha -o pthread_sample

echo "Start to compile sequential code"
echo ""
sudo gcc -L ../../../lib/aarch64-linux-gnu/ -Wno-missing-braces -D DOCA_ALLOW_EXPERIMENTAL_API ./src/sequential_sample.c ../../common.c ../../../applications/common/src/utils.c -I../../../applications/common/src/ -I../ -I../../ -I ../../../ -I../../../include/ -ldoca_common -ldoca_dma -ldoca_sha -o sequential_sample

echo "Finish compiling"

echo ""
echo "------------------------------ Start running DOCA Graph implementation -------------------------------"

numbers=(1 2 4 8 10 20 40 80 100 200 300 400 500)
for num in "${numbers[@]}"
do
    echo ""
    echo "Runtime of running DOCA Graph implementation with $num instances"
    /usr/bin/time ./graph_sample $num > /dev/null
done

echo ""
echo "------------------------------ Finish running DOCA Graph implementation ------------------------------"
echo ""
echo "------------------------------ Start running Pthread implementation ----------------------------------"

for num in "${numbers[@]}"
do
    echo ""
    echo "Runtime of running Pthread implementation with $num instances"
    /usr/bin/time ./pthread_sample $num > /dev/null
done

echo ""
echo "------------------------------ Finish running Pthread implementation ------------------------------"
echo ""
echo "------------------------------ Start running sequential implementation ----------------------------"

for num in "${numbers[@]}"
do
    echo ""
    echo "Runtime of running sequential implementation with $num instances"
    /usr/bin/time ./sequential_sample $num > /dev/null
done

echo "------------------------------ Finish running sequential implementation -----------------------------"
echo ""

sudo rm graph_sample
sudo rm pthread_sample
sudo rm sequential_sample
