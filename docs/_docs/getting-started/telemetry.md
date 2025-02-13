---
title: Telemetry
category: Getting Started
chapter: 1
order: 14
---

## Collected data

| Data                     | Example                              |
|:-------------------------|:-------------------------------------|
| System ID                | 78701907-3044-493d-92b5-6a45e08aecd3 |
| Dependency-Track version | 4.13.0                               |
| Database type            | PostgreSQL                           |
| Database version         | 15.2                                 |

Information that could allow this data to be traced back to specific organizations,
such as IP addresses, is explicitly **not** collected.

The system ID is randomly generated upon a Dependency-Track instance's first launch.
It is used to correlate multiple data points of the same system over time,
but can not be traced back to actual deployments.

The Dependency-Track version is collected to allow the maintainers to gauge
adoption of new releases.

Database type and version are collected to... TODO

The insights gained from telemetry collection will be made available to the public.

## Submission frequency

Telemetry data is first submitted 30 seconds after application startup.  
From then onwards, it is submitted daily.

## Opting out

Telemetry submission can be disabled in multiple ways.

TODO