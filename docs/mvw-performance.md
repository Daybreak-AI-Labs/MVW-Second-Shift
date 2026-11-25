# Second Shift performance at MVW's size

Measure the six workloads on a local PostgreSQL 16 database using the
resource limits in the Azure kit. The hosted benchmark builds the Azure
image and checks the effective Linux CPU quota and memory limit in the
container before starting. The traffic driver runs outside that quota.
It uses a synthetic signed-in workspace and a local Teams signer and
connector. Timings are end-to-end HTTP milliseconds.

The serial run samples each operation four times without concurrency.
The 100-person burst starts one page request per person at the same time,
with traffic split among the three pages. The initial 500-person steady
comparisons last 60 seconds. Each person opens a page every 30 seconds.
Each of 100 agents screens and reports a run every 30 seconds. Ten Teams
card decisions are distributed over the same interval. All attempts count
in the distribution, including refused requests.

The serial target is under 200 ms for every sample. The burst target is 95%
of pages under 2 seconds. The steady target is 95% of pages under 1 second
and no failed page or Teams requests.

### Before request-cost changes, 0.5 CPU and 1 GiB

[Hosted run](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/actions/runs/45535250824)

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Serial | Home | 197.76 | 202.11 | 202.11 | 2/4 | 0 |
| Serial | Outside agents | 90.27 | 97.01 | 97.01 | 4/4 | 0 |
| Serial | Approvals | 177.17 | 199.87 | 199.87 | 4/4 | 0 |
| Serial | Screen | 58.41 | 59.06 | 59.06 | 4/4 | 0 |
| Serial | Report run | 107.08 | 110.15 | 110.15 | 4/4 | 0 |
| Serial | Teams card | 113.94 | 167.93 | 167.93 | 4/4 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Burst | Home | 21,464.48 | 24,632.30 | 24,634.92 | 0/34 | 0 |
| Burst | Outside agents | 24,580.39 | 24,659.07 | 24,663.18 | 0/33 | 0 |
| Burst | Approvals | 20,847.26 | 24,641.76 | 24,642.97 | 0/33 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Steady | Home | 87,861.94 | 110,232.82 | 112,067.49 | 1/333 | 0 |
| Steady | Outside agents | 95,414.50 | 126,945.61 | 128,211.16 | 2/334 | 0 |
| Steady | Approvals | 84,186.55 | 110,472.16 | 112,425.92 | 0/333 | 0 |
| Steady | Screen | 32,037.66 | 92,911.80 | 97,118.60 | 2/200 | 115 |
| Steady | Report run | 36,348.56 | 93,017.84 | 96,587.27 | 1/200 | 105 |
| Steady | Teams card | 101,203.42 | 114,077.75 | 114,077.75 | 0/10 | 0 |

The baseline missed all three latency targets. Home was the only serial
operation that crossed 200 ms. The steady run recorded no page or Teams
failures and 220 agent gateway capacity refusals.

The cProfile run recorded 945 named-record reads across start-up, fixture
preparation and the serial sample. Existence checks accounted for 542 of
those reads. Run reports and some screens reopened the world model, which
rechecked the PostgreSQL schema and row policies. The page and card traces
also repeated roster access and approval reads.

### After request-cost changes, 0.5 CPU and 1 GiB

[Hosted run](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/actions/runs/45535952387)

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Serial | Home | 113.93 | 135.06 | 135.06 | 4/4 | 0 |
| Serial | Outside agents | 77.83 | 118.36 | 118.36 | 4/4 | 0 |
| Serial | Approvals | 83.71 | 85.62 | 85.62 | 4/4 | 0 |
| Serial | Screen | 59.92 | 60.91 | 60.91 | 4/4 | 0 |
| Serial | Report run | 75.51 | 78.95 | 78.95 | 4/4 | 0 |
| Serial | Teams card | 129.05 | 160.14 | 160.14 | 4/4 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Burst | Home | 12,254.61 | 15,433.82 | 15,434.66 | 0/34 | 0 |
| Burst | Outside agents | 12,325.27 | 14,490.67 | 14,594.10 | 0/33 | 0 |
| Burst | Approvals | 12,226.01 | 15,180.33 | 15,432.51 | 0/33 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Steady | Home | 63,631.41 | 79,697.44 | 82,793.37 | 0/333 | 0 |
| Steady | Outside agents | 62,876.95 | 77,471.98 | 80,935.05 | 0/334 | 0 |
| Steady | Approvals | 63,341.52 | 79,376.36 | 81,270.16 | 0/333 | 0 |
| Steady | Screen | 17,364.94 | 85,012.51 | 91,901.06 | 4/200 | 107 |
| Steady | Report run | 21,455.57 | 87,800.09 | 93,649.31 | 1/200 | 123 |
| Steady | Teams card | 61,314.61 | 79,120.07 | 79,120.07 | 0/10 | 0 |

Home went under 200 ms in all four serial samples. The 100-person mixed
burst is faster, and its page times are still above two seconds. The
steady workload still queues work. Job 2 increases the available CPU
for that workload.

### Four workers, 4 vCPU and 8 GiB

[Hosted run](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/actions/runs/45538236449)

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Serial | Home | 109.99 | 125.95 | 125.95 | 4/4 | 0 |
| Serial | Outside agents | 77.35 | 85.30 | 85.30 | 4/4 | 0 |
| Serial | Approvals | 79.21 | 81.69 | 81.69 | 4/4 | 0 |
| Serial | Screen | 61.42 | 62.90 | 62.90 | 4/4 | 0 |
| Serial | Report run | 78.95 | 82.99 | 82.99 | 4/4 | 0 |
| Serial | Teams card | 127.62 | 162.10 | 162.10 | 4/4 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Burst | Home | 2,869.82 | 2,993.48 | 2,993.59 | 6/34 | 0 |
| Burst | Outside agents | 2,237.12 | 2,645.32 | 2,991.06 | 7/33 | 0 |
| Burst | Approvals | 2,563.49 | 2,970.59 | 2,992.41 | 5/33 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Steady | Home | 109.49 | 176.19 | 590.77 | 333/333 | 0 |
| Steady | Outside agents | 59.53 | 139.26 | 460.85 | 334/334 | 0 |
| Steady | Approvals | 74.45 | 107.43 | 544.70 | 333/333 | 0 |
| Steady | Screen | 53.63 | 273.51 | 718.25 | 200/200 | 0 |
| Steady | Report run | 91.14 | 284.52 | 943.58 | 200/200 | 0 |
| Steady | Teams card | 219.16 | 380.65 | 380.65 | 10/10 | 0 |

Under steady traffic, 1,000/1,000 pages finished under 1 second (highest page p95
176 ms) with 0 page or Teams failures. All serial requests finished under 200 ms.
In the burst, 18/100 pages finished under 2 seconds. The burst target remains
open.

### Sessions and recorder stores in PostgreSQL, 4 vCPU and 8 GiB

[Hosted run](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/actions/runs/45539524408)

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Serial | Home | 98.74 | 123.98 | 123.98 | 4/4 | 0 |
| Serial | Outside agents | 72.84 | 73.39 | 73.39 | 4/4 | 0 |
| Serial | Approvals | 73.39 | 74.79 | 74.79 | 4/4 | 0 |
| Serial | Screen | 58.32 | 60.83 | 60.83 | 4/4 | 0 |
| Serial | Report run | 72.08 | 77.00 | 77.00 | 4/4 | 0 |
| Serial | Teams card | 116.16 | 141.20 | 141.20 | 4/4 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Burst | Home | 3,342.76 | 3,386.31 | 3,387.04 | 8/34 | 0 |
| Burst | Outside agents | 3,353.17 | 3,397.58 | 3,398.04 | 9/33 | 0 |
| Burst | Approvals | 3,338.92 | 3,382.56 | 3,382.67 | 9/33 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Steady | Home | 62.97 | 107.61 | 144.75 | 333/333 | 0 |
| Steady | Outside agents | 36.91 | 80.82 | 105.49 | 334/334 | 0 |
| Steady | Approvals | 69.87 | 76.41 | 99.52 | 333/333 | 0 |
| Steady | Screen | 29.88 | 70.75 | 151.19 | 200/200 | 0 |
| Steady | Report run | 76.02 | 81.82 | 114.85 | 200/200 | 0 |
| Steady | Teams card | 123.08 | 165.88 | 165.88 | 10/10 | 0 |

Under steady traffic, 1,000/1,000 pages finished under 1 second (highest page p95
108 ms) with 0 page or Teams failures. All serial requests finished under 200 ms.
In the burst, 26/100 pages finished under 2 seconds. The burst target remains
open.

### Size of the old identity records

The sample uses one fixed-length synthetic person, sign-in name, name and
revocation timestamp per employee. Each person has two subject identifiers
(an Entra object ID and an email) and one Teams link. Sizes use the old JSON
formatters and measure the payload before any account profile encryption.

| Record | Bytes per additional person | Serialized bytes at 20,000 people |
| --- | ---: | ---: |
| Account names | 148 | 2,960,027 |
| Sign-in subject identifiers | 300 | 6,000,000 |
| Teams links | 240 | 4,800,057 |
| Signed-out sessions | 74 | 1,480,002 |

The old subject directory accepted 13,981 such people (4,194,300 bytes).
It refused at 13,982 (4,194,600 bytes). The old Teams limit allowed 5,000
links (1,200,057 bytes) and refused the 5,001st link.

PostgreSQL now updates individual records. Sign-in uses the same indexed
statements and touches the same number of rows with 25 or 25,000 people
already recorded. The sign-in directory and Teams each support at least
50,000 people in PostgreSQL.

### Per-person records, 4 vCPU and 8 GiB

[Hosted run](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/actions/runs/45540903746)

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Serial | Home | 104.91 | 106.01 | 106.01 | 4/4 | 0 |
| Serial | Outside agents | 75.20 | 76.31 | 76.31 | 4/4 | 0 |
| Serial | Approvals | 77.72 | 104.94 | 104.94 | 4/4 | 0 |
| Serial | Screen | 60.91 | 60.97 | 60.97 | 4/4 | 0 |
| Serial | Report run | 74.62 | 79.07 | 79.07 | 4/4 | 0 |
| Serial | Teams card | 121.84 | 153.06 | 153.06 | 4/4 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Burst | Home | 3,322.23 | 3,736.84 | 3,737.05 | 7/34 | 0 |
| Burst | Outside agents | 3,365.01 | 3,741.69 | 3,743.86 | 7/33 | 0 |
| Burst | Approvals | 3,311.10 | 3,732.69 | 3,733.47 | 9/33 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Steady | Home | 76.05 | 110.92 | 122.30 | 333/333 | 0 |
| Steady | Outside agents | 40.70 | 83.12 | 115.77 | 334/334 | 0 |
| Steady | Approvals | 72.05 | 79.99 | 115.95 | 333/333 | 0 |
| Steady | Screen | 32.31 | 71.44 | 122.60 | 200/200 | 0 |
| Steady | Report run | 79.06 | 85.15 | 119.64 | 200/200 | 0 |
| Steady | Teams card | 131.96 | 212.21 | 212.21 | 10/10 | 0 |

Every serial sample finished under 200 ms. All 1,000 steady pages finished
within one second (highest page p95 111 ms) with no page or Teams failures.
In the 100-person burst, 23 pages finished within two seconds and page p95
reached 3.74 seconds. The burst target remains open.

### Full MVW workload, 20,000 people and the selected Azure limits

[Hosted run](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/actions/runs/45551358398/job/138993038063)

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Serial | Home | 72.96 | 73.86 | 73.86 | 4/4 | 0 |
| Serial | Outside agents | 62.17 | 62.45 | 62.45 | 4/4 | 0 |
| Serial | Approvals | 60.49 | 61.97 | 61.97 | 4/4 | 0 |
| Serial | Screen | 59.76 | 61.90 | 61.90 | 4/4 | 0 |
| Serial | Report run | 74.55 | 76.21 | 76.21 | 4/4 | 0 |
| Serial | Teams card | 117.17 | 151.83 | 151.83 | 4/4 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Burst | Home | 904.43 | 1,420.32 | 1,426.68 | 34/34 | 0 |
| Burst | Outside agents | 815.77 | 1,368.75 | 1,407.08 | 33/33 | 0 |
| Burst | Approvals | 870.61 | 1,381.34 | 1,384.05 | 33/33 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Steady | Home | 34.62 | 54.82 | 88.12 | 667/667 | 0 |
| Steady | Outside agents | 23.56 | 37.50 | 78.34 | 667/667 | 0 |
| Steady | Approvals | 18.40 | 30.08 | 52.27 | 666/666 | 0 |
| Steady | Screen | 34.97 | 46.46 | 94.02 | 400/400 | 0 |
| Steady | Report run | 38.96 | 58.37 | 105.33 | 400/400 | 0 |
| Steady | Teams card | 114.47 | 180.51 | 180.51 | 10/10 | 0 |

| Scenario | Operation | Median | P95 | Maximum | Under target | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 500 arriving | Home | 2,586.60 | 4,986.82 | 5,214.89 | 63/167 | 0 |
| 500 arriving | Outside agents | 2,587.75 | 4,857.71 | 5,203.69 | 63/167 | 0 |
| 500 arriving | Approvals | 2,468.06 | 4,772.29 | 5,174.12 | 68/166 | 0 |
| Steady with 25 agents | Home | 34.72 | 42.07 | 78.90 | 667/667 | 0 |
| Steady with 25 agents | Outside agents | 23.82 | 29.14 | 60.71 | 667/667 | 0 |
| Steady with 25 agents | Approvals | 15.36 | 18.63 | 49.92 | 666/666 | 0 |
| Steady with 25 agents | Screen | 32.68 | 49.10 | 78.89 | 100/100 | 0 |
| Steady with 25 agents | Report run | 39.44 | 57.85 | 79.11 | 100/100 | 0 |
| Steady with 25 agents | Teams card | 91.03 | 122.66 | 122.66 | 10/10 | 0 |
| 100 agents arriving | Screen | 985.96 | 2,946.68 | 3,104.47 | 76/100 | 0 |
| 100 agents arriving | Report run | 845.87 | 2,626.29 | 2,856.14 | 87/100 | 0 |

The speed gates passed with 100/100 burst pages under two seconds and
2,000/2,000 steady pages under one second. Every serial sample finished
within 152 ms. The 100-agent steady workload had zero page or Teams
failures. Both steady workloads ran for 120 seconds.

Two more runs passed on the same Intel Xeon model. The worst serial
response across all three was 157 ms, and the highest burst page p95 was
1.50 seconds. An earlier build on AMD EPYC 7763 met the steady gate and
completed 46 of 100 burst pages within two seconds.
[Earlier AMD run](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/actions/runs/45548121662/job/138985528161)

The one-hour workload scheduled 2,000 synthetic recorders to poll every
five seconds and hand over activity every 30 seconds. The hosted output
reports 1,440,000 scheduled instruction polls, while the cadence yields
720,000. The poll totals remain unverified.

| Recorder operation | Scheduled | Attempted | Completed successfully | Devices with successes | P95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Recorder hand-over | 238,000 | 137,629 | 51,835 | 2,000 | 7,465 ms |

The app returned 85,660 capacity refusals. The driver canceled 134
remaining attempts at the deadline and left 100,371 hand-overs
unattempted.

[One-hour recorder run](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/actions/runs/45547283337/job/138979818081)
