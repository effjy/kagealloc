# KageAlloc: Hardware-Assisted Memory Safety

This project implements **KageAlloc**, a high-performance memory allocator that leverages Intel Memory Protection Keys (MPK/PKU) to achieve temporal memory safety, allocator metadata integrity, and control-flow isolation in systems software.

The repository includes both a console test harness and a professional **GTK3 Graphical Dashboard** to visualize and run the security mitigation test suite.

---

## File Structure

*   `paper.tex` / `paper.pdf`: Academic paper draft detailing the three security contributions.
*   `kagealloc.h` / `kagealloc.c`: Core allocator implementation (featuring BKR, TIMP, and RICCG).
*   `main.c`: Subprocess-isolated console test suite.
*   `gui.c`: Asynchronous GTK3 desktop interface visualizing the test logs and signal traps.
*   `Makefile`: Compilation rule-set compiling both CLI and GUI targets.

---

## Prerequisites

To compile and run KageAlloc, your Linux environment must have the following dependencies:

### 1. Development Tools
*   `gcc` or `clang` compiler supporting the `-ffixed-reg` flag.
*   `make` build automation tool.
*   `pkg-config` helper tool to query compiler and linker flags.

### 2. Libraries
*   **Glibc** (version 2.27 or higher is required for standard protection key syscall support).
*   **GTK+ 3 Development Files** (required for compiling the GUI dashboard).

#### Installing dependencies on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install build-essential pkg-config libgtk-3-dev
```

#### Installing dependencies on Fedora/RHEL/CentOS:
```bash
sudo dnf groupinstall "Development Tools"
sudo dnf install pkg-config gtk3-devel
```

---

## Compilation

The `Makefile` compiles both the console test harness and the GTK3 GUI.

To build **both** targets:
```bash
make all
```

To build **only the console test harness** (`kagealloc_test`):
```bash
make CLI
```
*(or run `make` without arguments)*

To build **only the GTK3 GUI** (`kagealloc_gui`):
```bash
make GUI
```

To clean build assets:
```bash
make clean
```

---

## Running the Targets

### 1. Console Test Harness
To run the full suite of sequential isolated tests:
```bash
./kagealloc_test
```

To run individual tests in raw mode (useful for debugging, will trigger direct SIGSEGV/SIGILL crashes):
*   `./kagealloc_test --raw-bkr` (runs the Batched Key-Rotation Use-After-Free test)
*   `./kagealloc_test --raw-timp` (runs the Thread-Isolated Metadata Partitioning test)
*   `./kagealloc_test --raw-riccg` (runs the Register-Isolated Cryptographic Call Gates ROP test)

### 2. GTK3 Graphical Dashboard
To run the graphical dashboard:
```bash
./kagealloc_gui
```
The GUI will open a window. You can click **"Run"** next to individual cards to run tests asynchronously or **"Run All Tests"** to evaluate the complete mitigation suite. Terminal logs and exit statuses will print in the trace logs section.

---

## Hardware Fallback (Simulated Mode)
KageAlloc auto-detects if the host CPU and kernel support hardware Memory Protection Keys (MPK/PKU). If unsupported (e.g. running inside virtualized containers or non-Intel environments), KageAlloc gracefully falls back to a **Simulated Mode** utilizing page-level kernel permissions (`mprotect(..., PROT_NONE)`). This guarantees that the security isolation guarantees, child signal traps, and exit statuses compile and run successfully on any standard Linux environment.
