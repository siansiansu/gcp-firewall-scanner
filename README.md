# GCP Firewall Scanner

A simple tool designed to scan Google Cloud Platform (GCP) firewall rules and identify any unused rules.

## Usage

Print tables in a terminal.

```bash
go run ./main.go --projectID=${ProjectID} --format table
```

Create a CSV file with the results.

```bash
go run ./main.go --projectID=${ProjectID} --format csv
```

Efficiently scan only the running instances.

```bash
go run ./main.go --projectID=${ProjectID} --format csv --running
```


If you choose to output the results as a CSV file, these two files will be created in your current directory.
- instances_`${projectID}`.csv
- firewalls_`${projectID}`.csv
