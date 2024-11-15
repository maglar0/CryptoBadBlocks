# CryptoBadBlocks

CryptoBadBlocks is a C++ command-line tool for testing disk integrity by writing and reading data in a random order. It has several 
interesting features compared to traditional tools like `badblocks`.

It currently works on MacOS and Linux.

**Note:** This project is a hobby project and the amount of testing that has been done is very limited.

## Overview

CryptoBadBlocks scans a disk for bad blocks by writing and reading data back in a random order with unpredictable data. This method 
provides several benefits:

- **Increased Stress Testing**: Writing in random order can place greater stress on the disk, simulating a more realistic workload.
- **SMR Disk Detection**: Shingled Magnetic Recording (SMR) disks often perform poorly when handling random writes, so this test can help 
figure out if the disk uses SMR.
- **Verifies true size**: The data written is, by default, unpredictable, making it resistant to compression, deduplication, or any firmware-level "faking" of disk size. If the test succeeds, you can be confident that the disk truly has the full capacity it claims.
- **Initialization for Deniable Encryption**: The randomness of the data makes it suitable for use in deniable encryption setups without additional processing (for instance, allowing "quick format" in VeraCrypt to be safely used).

It also provides the following features:
- **Resuming after interruption**: If the program was interrupted, e.g. because of a computer restart, it can quickly resume where it was (with
some caveats, e.g. it can't report read/write errors happening before the restart).
- **Overlapping writes with reads**: Some reads can be mixed in with the writing, instead of first writing the whole disk, and then reading it.
- **Statistics about disk performance**: After completion, statistics about the disk performance is printed.
- **Estimate of time left**: While working, an estimate of the time left is continuously printed. This can be quite accurate due to the
random order of operations (the same is not true when writing linearly, as HDDs tend to be slower closer to the end of the disk).

## Building and Running

To build and run CryptoBadBlocks, follow these steps:

1. **Create a build directory and compile**:
   ```bash
   mkdir build
   cd build
   cmake -DCMAKE_BUILD_TYPE=Release ..
   make
   ```

2. **Run the tool**:
   Replace `X` with the number of the drive you want to overwrite and verify:
   ```bash
   sudo time bin/CryptoBadBlocks "/dev/rdiskX"
   ```

   - `"/dev/rdiskX"` specifies the disk to be tested. On Linux, this might be something like `"/dev/disk/by-id/ata-WDC_WD100EZAZ-..."`.

**Warning**: Running this command will overwrite data on the specified drive. Ensure you have selected the correct drive to avoid accidental data loss.

## Usage

Run `bin/CryptoBadBlocks --help` for a full list of options and further information on usage.
