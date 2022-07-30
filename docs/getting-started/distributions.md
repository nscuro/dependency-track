Dependency-Track has three distribution variants. They are:

| Package    | Package Format          |   Recommended    |       Supported        |      Docker      |     Download      |
|:-----------|:------------------------|:----------------:|:----------------------:|:----------------:|:-----------------:|
| API Server | Executable WAR          | :material-check: |    :material-check:    | :material-check: | :material-check:  | 
| Frontend   | Single Page Application | :material-check: |    :material-check:    | :material-check: | :material-check:  |
| Bundled    | Executable WAR          | :material-close: | :material-exclamation: | :material-check: | :material-check:  |

### API Server

The API Server contains an embedded Jetty server and all server-side functionality, but excludes the frontend user
interface.

### Frontend

The Frontend is the user interface that is accessible in a web browser. The Frontend is a Single Page Application (SPA)
that can be deployed independently of the Dependency-Track API Server.

### Bundled

The Bundled variant combines the API Server and the Frontend user interface. This variant was previously referred to as
the executable war and was the preferred distribution from Dependency-Track v3.0 - v3.8.

!!! warning "Deprecation Notice"
    This variant is supported but deprecated and will be discontinued in a future release.
