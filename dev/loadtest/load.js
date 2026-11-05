/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
import { SharedArray } from 'k6/data';
import exec from 'k6/execution';
import http from 'k6/http';
import { Counter, Rate } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://apiserver:8080/api';
const API_KEY = __ENV.API_KEY;
const COMPONENTS = parseInt(__ENV.COMPONENTS || '500');
const POLLS = parseInt(__ENV.POLLS || '12');
const VUS = parseInt(__ENV.VUS || '64');
const RUN_ID = __ENV.RUN_ID || 'adhoc';
const PROJECTS = parseInt(__ENV.PROJECTS || '0');
const CHANGED = Math.ceil(COMPONENTS * 0.05);
const TOKENS_PER_VU = 8;
const INDEX_STEP = 104729; // Prime, so stepping through the pool visits each component once.

const headers = { 'X-Api-Key': API_KEY };
const uploadFailed = new Counter('upload_failed');
const uploadOk = new Rate('upload_ok');

// Serialized once and shared, because generating BOMs per VU costs about 22 MiB of memory per VU.
const pool = new SharedArray('components', () =>
  [
    '/src/apiserver/src/test/resources/unit/bom-bloated.json',
    '/src/e2e/src/test/resources/dtrack-apiserver-4.5.0.bom.json',
  ].flatMap((path) =>
    JSON.parse(open(path)).components.map((component) => {
      // Some of these URLs fail the upload's schema validation.
      delete component.externalReferences;
      return JSON.stringify(component);
    }),
  ),
);
const refs = new SharedArray('refs', () => pool.map((component) => JSON.parse(component)['bom-ref']));

function scenario() {
  if (__ENV.MODE === 'burst') {
    return {
      executor: 'shared-iterations',
      vus: VUS,
      iterations: parseInt(__ENV.COUNT),
      maxDuration: '3h',
    };
  }
  return {
    executor: 'constant-arrival-rate',
    rate: Math.round(parseFloat(__ENV.RATE) * 100),
    timeUnit: '100s',
    duration: `${parseFloat(__ENV.MINUTES) * 60}s`,
    preAllocatedVUs: VUS,
    maxVUs: VUS,
    gracefulStop: '60s',
  };
}

export const options = {
  scenarios: { load: scenario() },
  thresholds: {
    upload_ok: [{ threshold: 'rate>0.99', abortOnFail: true, delayAbortEval: '5m' }],
  },
  summaryTrendStats: ['avg', 'p(50)', 'p(95)', 'p(99)', 'max'],
};

function buildBom(project, upload) {
  const start = (project * 7919) % pool.length;
  const indexes = [];
  for (let i = 0; i < COMPONENTS; i++) {
    // Positions past COMPONENTS are outside the first upload, so replacing with them can't create duplicates.
    const position =
      upload > 0 && i < CHANGED ? COMPONENTS + (upload * CHANGED + i) % (pool.length - COMPONENTS) : i;
    indexes.push((start + position * INDEX_STEP) % pool.length);
  }
  const dependencies = [{ ref: 'root', dependsOn: indexes.slice(0, 10).map((i) => refs[i]) }];
  indexes.forEach((index, position) => {
    const children = [indexes[2 * position + 1], indexes[2 * position + 2]].filter((i) => i !== undefined);
    dependencies.push({ ref: refs[index], dependsOn: children.map((i) => refs[i]) });
  });
  const metadata = { component: { type: 'application', 'bom-ref': 'root', name: `lt-${RUN_ID}`, version: `${project}` } };
  return (
    `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":${JSON.stringify(metadata)},` +
    `"components":[${indexes.map((i) => pool[i]).join(',')}],"dependencies":${JSON.stringify(dependencies)}}`
  );
}

const recentTokens = [];
let nextPoll = 0;

export default function () {
  const seq = exec.scenario.iterationInTest;
  const project = PROJECTS ? seq % PROJECTS : seq;
  const upload = PROJECTS ? Math.floor(seq / PROJECTS) : 0;
  const response = http.post(
    `${BASE_URL}/v1/bom`,
    {
      projectName: `lt-${RUN_ID}-${project}`,
      projectVersion: '1',
      autoCreate: 'true',
      bom: http.file(buildBom(project, upload), 'bom.json', 'application/json'),
    },
    { headers, tags: { name: 'upload' }, timeout: '120s' },
  );

  const ok = response.status === 200;
  uploadOk.add(ok);
  if (!ok) {
    uploadFailed.add(1);
    console.error(`Upload failed with ${response.status}: ${String(response.body).slice(0, 300)}`);
    return;
  }

  recentTokens.push(response.json('token'));
  if (recentTokens.length > TOKENS_PER_VU) {
    recentTokens.shift();
  }
  for (let i = 0; i < POLLS; i++) {
    const token = recentTokens[nextPoll++ % recentTokens.length];
    http.get(`${BASE_URL}/v1/event/token/${token}`, { headers, tags: { name: 'status' } });
  }
}

export function handleSummary(data) {
  return { [`${__ENV.RESULTS_DIR}/k6-summary.json`]: JSON.stringify(data) };
}
