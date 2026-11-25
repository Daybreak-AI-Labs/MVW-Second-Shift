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
