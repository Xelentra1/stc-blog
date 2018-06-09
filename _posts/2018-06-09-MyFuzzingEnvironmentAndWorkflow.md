---
title: "afl 0x0: my fuzzing environments and workflow"
layout: post
category: fuzzing
tags: fuzzing afl workflow bug-hunting vulnerability-research
---
I recently decided I wanted to learn more about using afl effectively and how it works under the hood. I've been using it for a short time and have stuck to fuzzing only applications that would build with the basic 'configure+make' combo, avoiding alternative build systems (since I don't know much about them), and only fuzzing applications, not libraries. But now I want to move past the basics and really do a deep dive. I've had a hard time finding much good information that isn't the same "how to install and instrument a simple binary", so I thought I could help fill in this gap a little bit. 

This will be the first in a series of posts about working with afl and documenting new things I learn about using it. I thought it would be good to start this off by describing my current fuzzing workflow and how I set everything up. I've found that it works well for me and lets me focus on the important stuff.


## Worflow
I'll begin with a quick overview of my typical fuzzing workflow, which will mention the different systems and tools involved.

### Local Build and Test Run
I begin working in a local Ubuntu Server VM. The system is configured automatically using a couple of scripts and has all the necessary tools installed. I like fuzzing packages from the Ubuntu repos, so I enable the source code repositories on this system. Once I've selected a target, I download the source files and build them with afl. This is where I figure out the exact build recipe that is needed for the particular package and catch any build issues. When everything is finally compiled and instrumented correctly, I create a recipe script so that I can easily reproduce the build if needed. Finally, I build a small test corpus and run a short fuzzing job to see how the binary reacts to it. 


### Cloud Fuzzing, Round 1
When I'm ready to do the real fuzzing, I copy the files to a cloud storage bucket, launch a new VM instance in the cloud and configure it using the same script used on the local VM, download the files to this new instance, and start fuzzing. This VM is privisioned with high CPU and memory to improve fuzzing performance. Multiple instances of afl are run to take advantage of these resources.

After the fuzzers have run long enough (at least long enough for the master to have completed one cycle), I stop the jobs and prepare to consolidate and minimize the resulting testcase files in the `queue/` directory of each fuzzer that ran in the job.

### Testcase Corpus Consolidation and Minimization
The files in each fuzzer's queue may contain other bugs that weren't uncovered in the first run. There will probably be lots of overlap between these these files, so I consolidate them into a single directory and run them through `afl-cmin`. This allows me go for another round of fuzzing with these testcases if I think it's worth it.

Once this is done, I delete the queues for each fuzzer and the directory that contained the combined queues to save space. I then create an archive of the target directory with the new files and upload them to the cloud storage bucket.


### Cloud Fuzzing, Round N
If it feels like it may be fruitful, I'll then replace the queues for each fuzzer with the minimized queue and go for another round of fuzzing. I do this as many times as I see fit, minimizing the queues and uploading the new files to the storage bucket for each run.


### Crash Minimization and Triage
Once I'm satisfied with the fuzzing, I prepare to analyze the resulting crash files. 

I download the archives for each fuzzing run to a cloud instance and perform a similar operation as above to minimize the crashing testcases for each fuzzing run (combining the crash directories of each fuzzer and running them through `afl-cmin`). This can potentially reduce thousands of crash files down to under a hundred. When this is complete, I upload these new files to the storage bucket and then download them to my local VM. I then move on to analyzing the crash files to determine the root cause of the crashes and potential exploitability. 

This process is much too involved to go into in this post, but I do plan on writing a post as part of this series that will deep dive into my crash triage process. 


## Components
The setup described above consists of the following components:

1. **fuzzy-scripts**: collection of scripts for initializing the environment and installing afl, as well as some utility scripts
2. **Local VM instance**: used for initial building, instrumentation, and testing fuzzing.
3. **Cloud VM instance**: used for longer fuzzing sessions once all of the parameters are figured out
4. **Cloud storage bucket**: centralized storage location for fuzz job files


### fuzzy-scripts
[fuzzy-scripts](https://github.com/mellow-hype/fuzzy-scripts) is a collection of scripts I wrote to automate the installation of afl and configuration of the environment. Most of the work is done by two scripts, `setup.sh` and `dbg-repos.sh`. Both the local VM instance and cloud instance are configured using the same scripts to create mirror environments.

Another script included with fuzzy-scripts is `init-target.sh`, located in the `tools/` directory. This script creates a directory under `~/targets` for a new fuzzing target. Inside, it creates the directories for testcases and findings used during the fuzzing process. This script is meant to eliminate having to repeat those commands every time.

#### setup.sh
This script does most of the heavy lifting. It begins by installing necessary packages and dependencies:

```sh
# update sources and install dependencies
echo "[+] Installing dependencies and making config changes for afl..."
sudo apt-get update
sudo apt-get install -y clang-3.8 build-essential llvm-3.8-dev gnuplot-nox
sudo update-alternatives --install /usr/bin/clang clang `which clang-3.8` 1
sudo update-alternatives --install /usr/bin/clang++ clang++ `which clang++-3.8` 1
sudo update-alternatives --install /usr/bin/llvm-config llvm-config `which llvm-config-3.8` 1
sudo update-alternatives --install /usr/bin/llvm-symbolizer llvm-symbolizer `which llvm-symbolizer-3.8` 1
```

After this, it enables coredumps, followed by downloading and installing the standard afl tools, as well as `afl-clang-fast` and `afl-clang-fast++`:

```sh
# ensure system doesnt interfere with dumps (has to be repeated after reboots)
echo "[+] Enabling core dumps..."
echo core | sudo tee /proc/sys/kernel/core_pattern

# get and build afl
echo "[+] Installing American Fuzzy Lop..."
cd tools
wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
tar xvf afl-latest.tgz &> /dev/null
cd afl-2*
make
make -C llvm_mode
sudo make install
echo "Done!"
```

Finally, it installs a gdb, pwndbg, and a few other useful tools in case they aren't already present:

```sh
# other installs
echo "[+] Installing gdb and pwndbg..."
sudo apt-get install -y gdb 
git clone https://github.com/pwndbg/pwndbg.git
cd pwndbg 
./setup.sh
echo "Done!"

echo ""
echo "[+] Installing some other tools in case they aren't already..."
sudo apt-get install -y yasm vim git 
echo "Done!"
echo ""
```


#### dbg-repos.sh
This script configures the debug-sym repositories for Ubuntu. These repos contain debug symbols for most packages avilable through apt, which can be a huge help when triaging bugs later on.

```sh
echo "Adding debug symbol repos at file /etc/apt/sources.list.d/ddebs.list"
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
    sudo tee -a /etc/apt/sources.list.d/ddebs.list

echo "Importing signing key..."
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 428D7C01 C8CAB6595FDFF622

echo "Updating repos..."
sudo apt-get update
```


#### tools/cmin.sh
This script automates the process of consolidating and minimizing the resulting testcases from each fuzzer's queue and minimizing the corpus with `afl-cmin`. The code is shown below:

```sh
#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
    echo "[!] usage: ./cmin.sh <fuzzer-basename>"
    echo ""
    echo "> the fuzzer basename is the name you assigned the your master and slave fuzzers, minus the number."
    echo "> the target command string passed to afl must be double-quoted "
    exit
fi

fuzzer_name=$1
cd syncdir
mkdir combined_queue
cp "${fuzzer_name}"*/queue/* combined_queue/
```

#### tools/init-target.sh
This is a simple convenience script that sets up the directory structure I use for each new target. It creates a new directory under `~/targets/` with the name provided. This directory contains three  directories: 

- `src/`: a place to keep the source code of the target program
- `inputs/`: the directory for testcase files fed to the fuzzer
- `syncdir/`: the directory where the fuzzers will output their results

This script also copies the `cmin.sh` script to the new target directory, since the minimization script expects to be run from this location.


### Local and Cloud Environments
As mentioned above, I start off working in a local VM and then transition over to a cloud instance for the actual fuzzing. 

The local fuzzing VM is used for target selection and doing the initial build and instrumentation of the target. This VM isn't very powerful because it doesn't really need to be. I use these specs for a VM on my laptop:

```
- 2 CPUs
- 20GB HDD
- 4GB RAM
- Ubuntu Server 16.04 64-bit
```

Once the VM is created, I do a clean install of the OS and take snapshot for easy redeployment in case something goes wrong. Then I use the scripts from above to do the configuration and installation of tools. 

Since the cloud instance is responsible for running the real fuzzing job, I provision it with more resources. There are times when I want to use different specs for the cloud VM, so I create instance templates with the following specs:

```
- 4 CPU
- 8GB RAM 
- 20GB HDD
- Ubuntu Server 16.04 64-bit

- 8 CPU
- 16GB RAM 
- 20GB HDD
- Ubuntu Server 16.04 64-bit

- 16 CPU
- 32GB RAM 
- 20GB HDD
- Ubuntu Server 16.04 64-bit
```

These VMs are configured with the same scripts as the local VM.

### Cloud Storage
The cloud storage bucket is used as a central storage point for the fuzzing files. After everything has been successfully built in the local VM and I've tested fuzzing, I copy the files to the storage bucket, where they will later be downloaded to the cloud instance for the full fuzzing job. I also store the resulting files for each round of fuzzing and crash case minimization in the cloud bucket.  


## Conclusion
There it is! Nothing too complicated or special happening, but this workflow lets me figure out all of the details locally and then get right to work in the cloud. I hope it will be helpful to anyone out there still figuring out their own process. In the next post I'll write about selecting interesting targets and where to find them. 