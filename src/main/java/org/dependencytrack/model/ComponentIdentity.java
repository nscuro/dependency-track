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
package org.dependencytrack.model;

import com.github.packageurl.PackageURL;
import org.dependencytrack.util.PurlUtil;
import org.json.JSONObject;

import java.util.UUID;

/**
 * A transient object that carries component identity information.
 *
 * @since 4.0.0
 */
public record ComponentIdentity(ObjectType objectType, PackageURL purl, PackageURL purlCoordinates,
                                String cpe, String swidTagId, String group, String name, String version, UUID uuid) {

    public enum ObjectType {
        COMPONENT,
        SERVICE
    }

    public ComponentIdentity(final ObjectType objectType, final PackageURL purl, final PackageURL purlCoordinates,
                             final String cpe, final String swidTagId, final String group, final String name,
                             final String version, final UUID uuid) {
        this.objectType = objectType;
        this.purl = purl;
        this.purlCoordinates = purlCoordinates;
        this.cpe = cpe;
        this.swidTagId = swidTagId;
        this.group = group;
        this.name = name;
        this.version = version;
        this.uuid = uuid;
    }

    public ComponentIdentity(final PackageURL purl, final String cpe, final String swidTagId,
                             final String group, final String name, final String version) {
        this(ObjectType.COMPONENT, purl, PurlUtil.silentPurlCoordinatesOnly(purl),
                cpe, swidTagId, group, name, version, null);
    }

    public ComponentIdentity(final Component component) {
        this(ObjectType.COMPONENT, component.getPurl(), PurlUtil.silentPurlCoordinatesOnly(component.getPurl()),
                component.getCpe(), component.getSwidTagId(), component.getBomRef(), component.getName(),
                component.getVersion(), component.getUuid());
    }

    public ComponentIdentity(final org.cyclonedx.model.Component component) {

//        try {
//            this.purl = new PackageURL(component.getPurl());
//            this.purlCoordinates = PurlUtil.purlCoordinatesOnly(purl);
//        } catch (MalformedPackageURLException e) {
//            // throw it away
//        }
        this(ObjectType.COMPONENT, null, null, component.getCpe(), component.getSwid().getTagId(),
                component.getGroup(), component.getName(), component.getVersion(), null);
    }

    public ComponentIdentity(final ServiceComponent service) {
        this(ObjectType.SERVICE, null, null, null, null, service.getGroup(), service.getName(),
                service.getVersion(), service.getUuid());
    }

    public ComponentIdentity(final org.cyclonedx.model.Service service) {
        this(ObjectType.SERVICE, null, null, null, null, service.getGroup(), service.getName(),
                service.getVersion(), null);
    }

    public PackageURL getPurl() {
        return purl;
    }

    public String getCpe() {
        return cpe;
    }

    public String getSwidTagId() {
        return swidTagId;
    }

    public String getGroup() {
        return group;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public UUID getUuid() {
        return uuid;
    }

    public JSONObject toJSON() {
        final JSONObject jsonObject = new JSONObject();
        jsonObject.put("uuid", this.uuid());
        jsonObject.put("group", this.group());
        jsonObject.put("name", this.name());
        jsonObject.put("version", this.version());
        jsonObject.put("purl", this.purl());
        jsonObject.put("purlCoordinates", this.purlCoordinates());
        jsonObject.put("cpe", this.cpe());
        jsonObject.put("swidTagId", this.swidTagId());
        jsonObject.put("objectType", this.objectType());
        return jsonObject;
    }
}
