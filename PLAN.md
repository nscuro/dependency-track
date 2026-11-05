# SBOM throughput benchmark plan

The [website](https://dependencytrack.org/) claims "20,000+ SBOMs/hour in a single instance",
with no conditions stated.
This is a one-person, zero-cost version of a benchmark: one API server, on one machine.
It finds out how far a single replica gets and what limits it.

The tooling and usage docs are in [`dev/loadtest`](dev/loadtest/README.md).

## Status

| Step                                    | State                      |
|:----------------------------------------|:---------------------------|
| Compose override, k6 script, driver     | Built, smoke tested        |
| Report logic                            | Unit tested                |
| OSV mirror                              | Not run, needs a go-ahead  |
| Step, hold, burst                       | Not run, needs a go-ahead  |
| Website wording                         | Not changed                |

## Decisions

| Topic              | Decision                                                                             |
|:-------------------|:-------------------------------------------------------------------------------------|
| Definition of done | The token status endpoint reports `COMPLETED`                                        |
| Target             | 20,000 SBOMs/h, which is 5.56 SBOMs/s                                                |
| Deployment         | One API replica with 4 CPU and 4 GB, PostgreSQL with 4 CPU and 8 GB                  |
| Machine            | An M1 Pro laptop, all services on one machine                                        |
| Image              | `5-snapshot` at commit `a87035fbc`, pinned by digest. Rerun on its release before publishing |
| SBOM size          | 500 components, a placeholder until we have real size data. Optionally 50            |
| PostgreSQL config  | PGTune plus the database guide's advanced tuning, nothing else                       |
| Vulnerability data | One OSV mirror for `npm` and `Maven`, reused through a `pg_dump`                     |
| Package metadata   | Worker disabled, and the result says so                                              |
| Scheduled tasks    | Task scheduler disabled, and the result says so                                      |

## Runs

1. Step through 1, 2, 4, and 5.56 SBOMs/s, 15 minutes each, twice.
2. Hold the highest passing rate for 1 hour, twice.
3. Optionally, burst 20,000 SBOMs and time the drain.
4. Optionally, step at 50 components, the closest size to ReARM's.

## What the result means

| Result at 5.56 SBOMs/s, 500 components | Conclusion                                                                    |
|:---------------------------------------|:------------------------------------------------------------------------------|
| Passes                                 | The claim is well supported. Link the conditions next to it                   |
| Fails                                  | We know one replica's limit and its bottleneck. 20k/h isn't disproved for larger deployments, so publish the measured number and replace the claim, or attribute it to an adopter |

Publish only if repeated runs agree within about 25%, with the conditions listed in the README.
If the API server is the bottleneck, an async-profiler run should show where the time goes.

## Website wording

Our docs use "instance" for a replica, while the website means a deployment.
Change "in a single instance" to "in a single deployment" regardless of the result.
Until there's a measured number, attribute the claim: "Adopters have reported 20,000+ SBOMs/hour. Conditions vary."

## Out of scope

Multiple replicas, cloud hosts, other SBOM sizes, repeat uploads to existing projects,
and the website's "1M+ SBOMs" claim.
Add these only if a result is close to a decision, or someone challenges it.
