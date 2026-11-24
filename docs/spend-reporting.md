# Report outside-agent spending

Open **Spend** in the sidebar. Any Second Shift role with view permission can
read the report and download the same tables as CSV. The report covers the
current workspace.

The agent, department, platform and month tables add up costs from completed
outside-agent episodes in the Operating Record, including failed runs that
reported a cost. The report covers the current calendar month and the
previous eleven months in UTC. The month is the completion month. Department
comes from the recorded run, with missing departments shown as Unassigned.
Older run records do not store the agent's platform, so the report uses the
current enrollment's platform and labels retired or unmatched agents Unknown
platform. The report uses the costs agents reported in USD.

The **Agent budgets** table shows how much each enrolled agent has used
against its configured monthly or cumulative limit. It uses the same
budget meters as Outside agents, so a budget reset changes the meter even
when older runs still appear in the spend tables. The estimate adds the
current month's reported daily average, based on at least one elapsed day,
over the remainder of the month. An agent already over its limit is shown
separately from an agent projected to cross it.

The page, `GET /api/v1/spend`, and `GET /api/v1/spend.csv` use the same
report. The CSV's `table` column identifies each table. Report labels that
could be interpreted as spreadsheet formulas are exported as text.
