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

import alpine.common.logging.Logger;
import alpine.server.cache.CacheManager;
import com.google.api.expr.v1alpha1.CheckedExpr;
import com.google.api.expr.v1alpha1.Type;
import com.google.common.util.concurrent.Striped;
import org.apache.commons.codec.digest.DigestUtils;
import org.dependencytrack.policy.CelPolicyScript.Requirement;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.projectnessie.cel.Ast;
import org.projectnessie.cel.CEL;
import org.projectnessie.cel.Env;
import org.projectnessie.cel.Env.AstIssuesTuple;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.Program;
import org.projectnessie.cel.common.types.pb.ProtoTypeRegistry;
import org.projectnessie.cel.tools.ScriptCreateException;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.stream.Collectors;

public class CelPolicyScriptHost {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyScriptHost.class);
    private static CelPolicyScriptHost INSTANCE;

    private final Striped<Lock> locks;
    private final CacheManager cacheManager;
    private final Env environment;

    CelPolicyScriptHost(final CacheManager cacheManager) {
        this.locks = Striped.lock(128);
        this.cacheManager = cacheManager;
        this.environment = Env.newCustomEnv(
                ProtoTypeRegistry.newRegistry(),
                List.of(
                        Library.StdLib(),
                        Library.Lib(new CelPolicyLibrary())
                )
        );
    }

    public static synchronized CelPolicyScriptHost getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new CelPolicyScriptHost(CacheManager.getInstance());
        }

        return INSTANCE;
    }

    public CelPolicyScript compile(final String scriptSrc) throws ScriptCreateException {
        final String scriptDigest = DigestUtils.sha256Hex(scriptSrc);

        // Acquire a lock for the SHA256 digest of the script source.
        // It is possible that compilation of the same script will be attempted multiple
        // times concurrently.
        final Lock lock = locks.get(scriptDigest);
        lock.lock();

        try {
            CelPolicyScript script = cacheManager.get(CelPolicyScript.class, scriptDigest);
            if (script != null) {
                return script;
            }

            LOGGER.debug("Compiling script: %s".formatted(scriptSrc));
            AstIssuesTuple astIssuesTuple = environment.parse(scriptSrc);
            if (astIssuesTuple.hasIssues()) {
                throw new ScriptCreateException("Failed to parse script", astIssuesTuple.getIssues());
            }

            astIssuesTuple = environment.check(astIssuesTuple.getAst());
            if (astIssuesTuple.hasIssues()) {
                throw new ScriptCreateException("Failed to check script", astIssuesTuple.getIssues());
            }

            final Ast ast = astIssuesTuple.getAst();
            final Program program = environment.program(ast);
            final Set<Requirement> requirements = analyzeRequirements(CEL.astToCheckedExpr(ast));

            script = new CelPolicyScript(program, requirements);
            cacheManager.put(scriptDigest, script);
            return script;
        } finally {
            lock.unlock();
        }
    }

    private static Set<Requirement> analyzeRequirements(final CheckedExpr expr) {
        final var requirements = new HashSet<Requirement>();

        final Set<String> typeNames = expr.getTypeMapMap().values().stream()
                .map(Type::getMessageType)
                .collect(Collectors.toSet());

        // For the majority of cases, it is sufficient to check whether a given type
        // is present in the type map constructed by the type checker. This works as long
        // as a field of the respective type is accessed in the script, e.g.
        //
        //   component.license.name
        //
        // will result in the License type being present in the type map. However, it does NOT
        // work when only the presence of a field is checked in the script, e.g.
        //
        //   has(component.license)
        //
        // will result in the License type NOT being present in the type map.
        //
        // To cover this limitation, we could implement a visitor that traverses the AST
        // and keeps track of which fields are access for which type.
        if (typeNames.contains(Project.getDescriptor().getFullName())) {
            requirements.add(Requirement.PROJECT);

            if (typeNames.contains(Project.Property.getDescriptor().getFullName())) {
                requirements.add(Requirement.PROJECT_PROPERTIES);
            }
        }
        if (typeNames.contains(License.getDescriptor().getFullName())) {
            requirements.add(Requirement.LICENSE);

            if (typeNames.contains(License.Group.getDescriptor().getFullName())) {
                requirements.add(Requirement.LICENSE_GROUPS);
            }
        }
        if (typeNames.contains(Vulnerability.getDescriptor().getFullName())) {
            requirements.add(Requirement.VULNERABILITIES);

            if (typeNames.contains(Vulnerability.Alias.getDescriptor().getFullName())) {
                requirements.add(Requirement.VULNERABILITY_ALIASES);
            }
        }

        return requirements;
    }

}
