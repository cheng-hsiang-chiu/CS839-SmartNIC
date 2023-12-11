# CS 839 SmartNIC Systems

## What is this repository about?
The is the repository of the final project of SmarNIC Systems.
It is to study the runtime performance of DOCA Graph programming model.


## Repository structure
After unzip the final_project.zip, there are five files
- graph_main.c: main function in the DOCA Graph implementation
- graph_sample.c: function definitions in the DOCA Graph implementation
- pthread_sample.c: a Pthread implementation
- sequential_sample.c: a sequential implementation
- run.sh: a script to compile and run the experiment

## Build and Run
To build and run the three implementations,
***You need to login in the DPU first and unzip the file in /opt/mellanox/doca/samples/doca_common***
Then simply type the command:
```
./run.sh
```

## Experiment results
The report is available [[here](./SmartNIC___Final_Project.pdf)]
and the presentation slide is available [[here]](./smartnic.pdf)