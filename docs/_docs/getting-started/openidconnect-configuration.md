---
title: OpenID Connect Configuration
category: Getting Started
chapter: 1
order: 9
---

> OpenID Connect is available in Dependency-Track v4.0.0 and later

Generally, Dependency-Track can be used with any identity provider (IdP) that implements the [OpenID Connect standard](https://openid.net/connect/).
connect2id maintains a list of [public OpenID Connect providers](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk/openid-connect-providers).
Although usage with public providers is technically possible, it's strongly recommended to only use providers
that you or your organization have full control over. Misconfiguration may allow third parties to gain access to
your Dependency-Track instance!

Dependency-Track has been tested with multiple OpenID Connect providers. The following are
some example configurations that are known to work. If you find that the provider of your choice does not work
with Dependency-Track, please [file an issue](https://github.com/DependencyTrack/dependency-track/issues).

> Because the frontend is a JavaScript application and as such is executed in a browser, your IdP of choice must 
> set CORS headers on its OAuth2 / OpenID Connect endpoints. If you encounter CORS errors, please contact your service 
> provider and ask them to set the required headers. 

#### GitLab (gitlab.com)

Please refer to the official documentation on [how to use GitLab as OpenID Connect identity provider](https://docs.gitlab.com/ee/integration/openid_connect_provider.html).

In your application configuration, point *redirect URI* to `/static/oidc-callback.html` on your frontend host.
Select the scopes`email`, `openid` and `profile`:

![GitLab client configuration](/images/screenshots/oidc-gitlab-client-config.png)

> gitlab.com currently does not set CORS headers on its OAuth2 and OpenID Connect endpoints, see https://gitlab.com/gitlab-org/gitlab/-/issues/209259

##### Backend

```ini
alpine.oidc.enabled=true
alpine.oidc.issuer=https://gitlab.com
alpine.oidc.user.provisioning=true
alpine.oidc.username.claim=nickname
alpine.oidc.team.synchronization=true
alpine.oidc.always.sync.teams=true
alpine.oidc.teams.claim=groups
```

##### Frontend

```json
{
  "OIDC_ISSUER": "https://gitlab.com",
  "OIDC_CLIENT_ID": "your-client-id"
}
```

#### Keycloak

Create a new OpenID Connect client with *access type* set to `public` and *standard flow* enabled.
In order for Keycloak to set CORS headers, add the *web origin* `*`:

![Keycloak client configuration](/images/screenshots/oidc-keycloak-client-config.png)

##### Backend

```ini
alpine.oidc.enabled=true
alpine.oidc.issuer=http://localhost:8081/auth/realms/master
alpine.oidc.user.provisioning=true
alpine.oidc.username.claim=preferred_username
alpine.oidc.team.synchronization=true
alpine.oidc.always.sync.teams=true
alpine.oidc.teams.claim=groups
```

##### Frontend

```json
{
  "OIDC_ISSUER": "http://localhost:8081/auth/realms/master",
  "OIDC_CLIENT_ID": "dependency-track"
}
```

Keycloak does not include group or role information in its UserInfo endpoint per default. If you want to use 
Dependency-Track's team synchronization feature, you'll have to create a mapper for the Dependency-Track client:

![Keycloak mapper creation](/images/screenshots/oidc-keycloak-groups-mapping.png)

Depending on your setup, you would use the mapper types `Group Membership` (as shown above) or `User Realm Role`.
Make sure `Add to userinfo` is enabled.
