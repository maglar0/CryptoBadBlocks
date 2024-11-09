# CryptoBadBlocks

CryptoBadBlocks is a C++ command-line tool for testing disk integrity by writing and reading data in a random order. This approach offers several advantages over traditional tools like `badblocks`.

It currently works on MacOS, with Linux support hopefully coming very soon.

**Note:** This project is a work in progress, and most options listed by the `--help` command are not yet implemented.

## Overview

CryptoBadBlocks scans a disk for bad blocks by writing and reading data back in a random order. This method provides several benefits:

- **Increased Stress Testing**: Writing in random order can place greater stress on the disk, simulating a more realistic workload.
- **SMR Disk Detection**: Shingled Magnetic Recording (SMR) disks often perform poorly when handling random writes, so this test can help identify them.
- **Data Integrity Verification**: The data written is, by default, unpredictable, making it resistant to compression, deduplication, or any firmware-level "faking" of disk data. If the test succeeds, you can be confident that the disk has the full capacity it claims.
- **Suitability for Deniable Encryption**: The randomness of the data makes it suitable for use in deniable encryption setups without additional processing (for instance, allowing "quick format" in VeraCrypt to be safely used).

## Building and Running

To build and run CryptoBadBlocks, follow these steps:

1. **Create a build directory and compile**:
   ```bash
   mkdir build
   cd build
   cmake -DCMAKE_BUILD_TYPE=Debug ..
   make
   ```

2. **Run the tool**:
   Replace `X` with the number of the drive you want to overwrite and verify:
   ```bash
   sudo time bin/CryptoBadBlocks "/dev/rdiskX" --count=1000
   ```

   - `"/dev/rdiskX"` specifies the disk to be tested.
   - `--count=1000` sets the number of blocks to test.

**Warning**: Running this command will overwrite data on the specified drive. Ensure you have selected the correct drive to avoid accidental data loss.

## Usage

Refer to the `--help` command for a full list of options and further information on usage.
