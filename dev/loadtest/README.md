# SBOM throughput load test

Measures how many SBOMs one API server finishes per hour on a single machine.
An SBOM counts as finished when `GET /api/v1/event/token/{uuid}` reports `COMPLETED`,
which covers BOM import, vulnerability analysis, policy evaluation, and project metrics.

This is a diagnostic, and it can't settle what a multi-replica deployment reaches.
Results describe the machine they ran on. Publish them with the conditions below.

## What runs

| Service    | Limits             | Notes                                                       |
|:-----------|:-------------------|:------------------------------------------------------------|
| API server | 4 CPU, 4 GB        | One replica, image pinned by digest                         |
| PostgreSQL | 4 CPU, 8 GB        | [PGTune][pgtune] baseline plus the [database guide][dbguide]'s tuning |
| k6         | None               | Builds BOMs from `bom-bloated.json` and the e2e BOM         |
| Monitoring | None               | Prometheus and Grafana from `dev/monitoring`                |

The API server also has these settings:

* The package metadata worker is off, so runs don't call public registries.
* The task scheduler is off, so mirrors, portfolio metrics, portfolio analysis,
  and maintenance tasks can't run during a run. Metrics partitions are created at startup.
* Only the internal analyzer is enabled, and there are no notification rules.
* Two global policies fail on license `ISC` and severity `CRITICAL`,
  because policy evaluation does little with no policies.

## Before you run

1. Give Docker at least 18 GB of memory. API server and PostgreSQL limits alone take 12 GB.
2. Stop other containers and apps, and plug in the laptop.
3. Check that no other Compose project is called `dt-sbom-benchmark`. `up` refuses to reuse volumes it didn't create.

Commands need Python 3.9 or newer and Docker. There's nothing to install.

## Run it

```shell
cd dev/loadtest

python3 loadtest.py up
python3 loadtest.py bootstrap   # refuses unless the database is fresh, ends with a canary check
python3 loadtest.py mirror      # mirrors OSV for npm and Maven, then writes a dump. Duration unmeasured

python3 loadtest.py step                                       # 1, 2, 4, 5.56 SBOMs/s, 15 minutes each
python3 loadtest.py step                                       # repeat, because a laptop's results can drift
python3 loadtest.py hold --rate 5.56 --pg-latency-ms 1         # use the highest rate that passed
python3 loadtest.py hold --rate 5.56 --pg-latency-ms 1
python3 loadtest.py burst --count 20000                        # optional, about 30 GB of disk or more
python3 loadtest.py step --components 50 --rates 2,4,8,16      # optional
python3 loadtest.py step --rates 12 --pg-latency-ms 1          # optional, also works for step
python3 loadtest.py step --rates 12 --projects 500             # optional, re-uploads to 500 projects, 5% of components change

python3 loadtest.py down        # deletes this project's volumes
```

To test a local build, run `make build-image AGENT=1`, tag the image, and set `LOADTEST_APISERVER_IMAGE` to the tag.

To find the most imports a build can do, offer a rate it can't keep up with.
`imports_per_second` in `report.json` then shows its limit, even though the run itself fails.

`step`, `hold`, and `burst` restore the dump first, so each starts from the same database.
A restart creates metrics partitions for today and tomorrow, so keep each run under a day.

While a run is going, Grafana is at <http://127.0.0.1:3000>,
and its dashboards show whether the API server or PostgreSQL is saturated.

## Reading results

Each run writes to `results/<date>-<scenario>/`:

| File                 | Contents                                                     |
|:---------------------|:-------------------------------------------------------------|
| `report.json`        | Pass or fail with reasons, completions per hour, latency percentiles |
| `metadata.json`      | Image, commit, PostgreSQL settings, final row counts, mirror date |
| `k6-summary.json`    | Request rates and timings, including polling                 |
| `docker-stats.jsonl` | CPU and memory per container, every 30 s                     |
| `therm.log`          | macOS thermal state, every 30 s                              |
| `tokens.json`        | Each SBOM's token, status, and timestamps                    |

A rate passes when all of these hold:

* Every upload returned 200, and k6 dropped no iterations.
* Every SBOM uploaded after the first 5 minutes reached `COMPLETED`.
* The achieved arrival rate is within 1% of the target.
* Backlog grew by at most rate × 20 s for a step, or rate × 60 s for a hold.
* The API server and PostgreSQL containers didn't crash, and the status endpoint agrees with every token.

A burst passes when every SBOM completes within one hour of the first upload.

Completion time comes from `/api/v2/internal/workflow-runs`, so polling frequency doesn't affect timing.
Each upload also makes 12 status polls, because real CI clients poll and that load should count.

## Publishing results

Publish completions per hour from `report.json`, never the upload rate. An upload only means the BOM was accepted.
Run each scenario at least twice, and don't publish a number if the runs differ by more than about 25%.
State these conditions next to the number:

* The machine, Docker's CPU and memory, and SBOM size.
* All services share one machine. Holds delay PostgreSQL's replies by 1 ms to stand in for a network hop.
  Measure the resulting round trip with `ping` on your machine, because timers can make it longer.
  On the M1 Pro under OrbStack, it went from about 0.26 ms to about 2.6 ms on average.
* One replica, which is below the production guide's two-instance minimum for high availability.
* The task scheduler and package metadata resolution are off,
  and there's no reverse proxy, external analyzer, or notification rule.
* The pool has 9,188 purls, about 98.6% npm, with no CPEs, so CPE matching isn't exercised.
* The OSV mirror date from `metadata.json`.

## Updating versions

Digests are pinned in `compose.yaml`.
After changing the API server image, delete `.state/osv.dump` and run `mirror` again from a fresh `up`.

The PostgreSQL settings in `compose.yaml` come from PGTune's calculation for the inputs listed there.
Changing the memory, CPU, or connection count needs new values from [PGTune][pgtune].

Run the report tests with `python3 test_loadtest.py`.

[dbguide]: https://dependencytrack.github.io/docs/next/guides/administration/configuring-database/
[pgtune]: https://pgtune.leopard.in.ua/
