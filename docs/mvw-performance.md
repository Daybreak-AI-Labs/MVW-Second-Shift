# Second Shift performance at MVW's size

Measure the six workloads on a local PostgreSQL 16 database using the
resource limits in the Azure kit. The hosted benchmark builds the Azure
image and checks the effective Linux CPU quota and memory limit in the
container before starting. The traffic driver runs outside that quota.
It uses a synthetic signed-in workspace and a local Teams signer and
connector. Timings are end-to-end HTTP milliseconds.

The serial run samples each operation four times without concurrency.
The 100-person burst starts one page request per person at the same time,
with traffic split among the three pages. The 500-person steady run lasts
60 seconds. Each person opens a page every 30 seconds, and each of 100
agents screens and reports a run every 30 seconds. Ten Teams card decisions
are distributed over the same interval. All attempts count in the
distribution, including refused requests.

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
