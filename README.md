# Lightweight Authenticated Encryption for MAVLink

Code and data of the undergraduate thesis *Lightweight Authenticated Encryption for MAVLink: A Software-in-the-Loop Evaluation of Ascon-AEAD128 against AES-GCM, ChaCha20-Poly1305 and DTLS 1.3* (Nikol Katherin Rodriguez Ortiz, Department of Systems and Computing Engineering, Universidad de los Andes, Bogotá, Colombia, 2026).

The thesis integrates Ascon-AEAD128 (NIST SP 800-232), AES-GCM and ChaCha20-Poly1305 into the MAVLink send and receive paths of ArduCopter, adds a DTLS 1.3 tunnel as a standard-protocol baseline, and compares them with an unprotected link in a software-in-the-loop (SITL) testbed with emulated link impairments (NetEm), complemented by instruction counting on an emulated ARM Cortex-A9 (QEMU). Every table and figure of the thesis is regenerated from the data in this repository with the scripts below.

## Layout

| Path | Content |
|---|---|
| `kit/common` | AEAD core shared by the firmware and the tools: protected frame format, nonce construction, anti-replay window (`mavcrypt_core.c/.h`) |
| `kit/drone` | `AP_MAVCrypt` module for ArduPilot, the patch script that installs it (`apply_mavcrypt.py`), the build script of every firmware (`build_all.sh`) and the RAM/CPU monitor (`ram_monitor.sh`) |
| `kit/gcs` | Ground-station side: secure proxy (`secure_proxy.py`), metric instruments (`latency_timesync.py`, `stream_monitor.py`, `pcap_overhead.py`), per-run summary (`summarize.py`), statistics (`analysis.py`) and tables/figures of the results (`make_results.py`) |
| `kit/bench` | Network-namespace bench with NetEm profiles (`netbench.sh`), DTLS 1.3 tunnel (`dtls_tunnel.c`, `build_wolfssl.sh`, `gen_tls_cert.sh`, `dtls_selfcheck.sh`), QEMU instruction-counting plug-in (`count.c`, `build_qemu_plugin.sh`, `qemu_microbench_all.sh`, `qemu_sweep.sh`), host microbenchmark (`host_microbench.sh`) and campaign scripts (`run_campaign.sh`, `run_all.sh`, `run_extra.sh`, `run_confirmatory.sh`, `sitl_nostorage.sh`, `check_sitl_state.py`) |
| `kit/tests` | Unit tests and end-to-end runs (`build_and_test.sh`, `bench_e2e.sh`, `sitl_e2e.sh`, `check_run.py`, ...) |
| `kit/tools` | `mavcrypt_tool`: microbenchmark and cross-check tool (`bench <L> <iterations> <seal|open>`) |
| `kit/third_party` | `ascon-c` (designers' reference collection, commit 446347f, CC0) and `pyascon` (independent Python reference, used in the tests), each with its licence |
| `kit/gen_key.py` | Generates the pre-shared key (`kit/keys/`, not versioned) |
| `data/sitl` | One CSV per run and metric (see *Data*) and the per-run summaries |
| `data/analysis` | Output of `analysis.py`: run-level medians, descriptive statistics, comparisons, Kruskal-Wallis/Dunn, equivalence (TOST), Shapiro-Wilk |
| `data/*.csv` | Host microbenchmark (`microbench_host.csv`) and Cortex-A9 instruction counts (`qemu_instructions.csv`, `qemu_sweep.csv`, `qemu_weighted.csv`) |
| `figures` | Scripts of the thesis figures (English and Spanish labels) |

## Software versions

| Component | Version |
|---|---|
| Host | Ubuntu 26.04 LTS under WSL2, kernel `6.18.33.2-microsoft-standard-WSL2` (with `CONFIG_NET_SCH_NETEM=m`) |
| Compilers | gcc 15.2.0 (x86-64); arm-linux-gnueabihf-g++-13 13.4.0 (ARM cross build) |
| ArduPilot | `cafe67457776027a1bad6e165c409828c1a851e5` (ArduCopter master) |
| Ascon | `ascon-c` commit `446347f` (`opt32` variant), validated with the official KAT |
| OpenSSL | 3.5.5 (system `libcrypto`; static armhf build for the ARM microbenchmark) |
| wolfSSL | v5.9.4-stable (commit `3c5eead`), built with `--enable-dtls --enable-dtls13` |
| QEMU | 10.2.1 (`qemu-arm -cpu cortex-a9`, built with `--enable-plugins`) |
| Python | 3.14.4 with pandas 3.0.6, SciPy 1.18.1, scikit-posthocs 0.17.1, NumPy 2.5.3, pymavlink, cryptography 46.0.5 |

MD5 of the SITL binaries used in every run:

| Binary | MD5 |
|---|---|
| `arducopter_plain_sitl` | `e12cd73278f0452319648cf4d85fff23` |
| `arducopter_ascon_sitl` | `8d7e16af57365a79c5b118827d47e963` |
| `arducopter_aesgcm_sitl` | `b8415ce793a85c644b6d38cad781d109` |
| `arducopter_chacha_sitl` | `4c7a8c19867eaf44f4529725bdee3023` |

## Reproducing the study

All commands are run from `kit/`, as `root` inside WSL2 where network namespaces are needed. Set `ARDUPILOT` to the ArduPilot tree and `PY` to the Python interpreter that has the packages above.

```sh
# 1. keys, unit tests, KAT, cross-compiled tools
python3 gen_key.py --alg ascon && python3 gen_key.py --alg aesgcm && python3 gen_key.py --alg chacha
sh tests/build_and_test.sh                       # unit tests: ALL ... PASSED

# 2. firmware: install AP_MAVCrypt and build every treatment from the same tree
python3 drone/apply_mavcrypt.py "$ARDUPILOT"
sh drone/build_all.sh sitl

# 3. DTLS 1.3 tunnel and QEMU plug-in
sh bench/gen_tls_cert.sh && sh bench/build_wolfssl.sh && sh bench/dtls_selfcheck.sh
sh bench/build_qemu_plugin.sh

# 4. bench and runs (one run: scheme profile scenario run [tamper_every])
sudo sh bench/netbench.sh up                     # namespaces + veth; N0..N3 profiles
. bench/sitl_nostorage.sh                        # SITL working directory (no persistent parameters)
bash tests/bench_e2e.sh ascon N1 S1 01           # one run
bash tests/bench_e2e.sh aesgcm N1 T0 01 10       # tamper test (every 10th uplink frame)

# 5. campaign: first part (210 runs), second part (80 runs), confirmatory phase (20 runs)
bash bench/run_all.sh
bash bench/run_extra.sh
bash bench/run_confirmatory.sh

# 6. primitive cost: host microbenchmark and instructions per frame on the Cortex-A9
bash bench/host_microbench.sh > ../data/microbench_host.csv
bash bench/qemu_microbench_all.sh > ../data/qemu_instructions.csv
SIZES="12 36 64 100 160 255" bash bench/qemu_microbench_all.sh > ../data/qemu_sweep.csv

# 7. analysis, tables and figures
python3 gcs/summarize.py ../data/sitl
python3 gcs/analysis.py ../data/sitl --out ../data/analysis
python3 gcs/make_results.py ../data/sitl ../data/analysis --tables ../tables --figures ../figures/out \
        --microbench ../data/microbench_host.csv
python3 ../figures/make_figures.py               # figures with English labels
python3 ../figures/make_figures_es.py            # figures with Spanish labels
```

Steps 1-6 need the host described above; step 7 runs on any machine with the Python packages and reproduces the tables of the thesis from `data/`.

## Data

`data/sitl` contains the 310 runs analysed in the thesis (scenarios S1-S4, profiles N0-N3, treatments `plain`, `ascon`, `aesgcm`, `chacha`, `dtls`, `aesgcm-hw`, `chacha-hw`; five runs per cell, ten in the S1/N1 cells of `plain`, `ascon`, `aesgcm` and `chacha`) and the tamper test (`T0`). Files are named `<scenario>_<profile>_<scheme>_run<NN>_<metric>.csv`:

| Metric | Columns |
|---|---|
| `latency` | `seq, t_send_ns, rtt_us, lost` |
| `throughput` | `t_s, msgs, bytes, timesync_msgs, n_types, seq_gaps` |
| `ram` (and `ram_tunnel` for the UAV-side DTLS endpoint) | `t_s, pid, vmrss_kb, vmhwm_kb, utime_ticks, stime_ticks` |
| `proxy` (gzip-compressed) | `t_ns, dir, wire_bytes, frames, frame_bytes, plain_bytes, crypto_ns, auth_fail, replay` |

The `dtls` runs also store `_dtls.txt` (handshake time, negotiated version and suite, tunnel counters). `summary.csv` has one row per run and `summary_by_scheme.csv` the aggregates; both are produced by `summarize.py`. The packet captures (`_capture.pcap`) are not included because of their size (about 1.8 GB). Every metric of the thesis is reproduced from the remaining files: the per-frame overhead of the in-protocol schemes comes from the `proxy` files, and that of `dtls` was measured on the capture at the end of each run by `pcap_overhead.py` and stored in its `_dtls.txt` file. The pre-shared keys and the DTLS certificate are not included; they are generated with `gen_key.py` and `bench/gen_tls_cert.sh`.

## Licence

Not yet specified. The third-party code in `kit/third_party` keeps its own licence.
