# CS 839 SmartNIC Systems

## What is this repository about?
This assignment is to improve the execution time performance of parallel matrix multiplication (C=A*B)
using threadpool implementations.

## Implementations
There are six solutions implemented. They are
- Sequential
- Parallel with false sharing
- Parallel without false sharing
- Parallel with block matrix size
- Parallel with decentralized queues
- Parallel with decentralized queues and block matrix size


## Repository structure
- src : source files
- CMakeLists.txt : cmake file
- 3rd-party : 3rd-party libraries
- cmake : cmake file for Google benchmark 
- PA1-report.pdf : report

## Build
To build the executable, please follow the instructions below. The default compiler is g++.
```
mkdir build
cd build
cmake ../
make
cmake ../
make
```
***You need to cmake ../ and make twice to find the installed google benchmark libraries.***

## Run
To run the executable, please follow the instructions below.

```
cd build
./main
```

## Experiment results
The report is available [[here](./PA1-report.pdf)]
