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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.policy;

import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.ProgramOption;
import org.projectnessie.cel.checker.Decls;

import java.util.Collections;
import java.util.List;

public class CelPolicyLibrary implements Library {

    @Override
    public List<EnvOption> getCompileOptions() {
        return List.of(
                EnvOption.declarations(
                        Decls.newVar(
                                "component",
                                Decls.newObjectType(Component.getDescriptor().getFullName())),
                        Decls.newVar(
                                "project",
                                Decls.newObjectType(Project.getDescriptor().getFullName())),
                        Decls.newVar(
                                "vulns",
                                Decls.newListType(Decls.newObjectType(Vulnerability.getDescriptor().getFullName()))
                        )
                ),
                EnvOption.types(
                        Component.getDefaultInstance(),
                        License.getDefaultInstance(),
                        Project.getDefaultInstance(),
                        Vulnerability.getDefaultInstance(),
                        Vulnerability.Alias.getDefaultInstance()
                )
        );
    }

    @Override
    public List<ProgramOption> getProgramOptions() {
        return Collections.emptyList();
    }

}
