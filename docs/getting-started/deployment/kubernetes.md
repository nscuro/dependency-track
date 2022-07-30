You can install on Kubernetes using the [community-maintained chart](https://github.com/evryfs/helm-charts/tree/master/charts/dependency-track) like this:

=== "Helm v3"

    ```shell
    helm repo add evryfs-oss https://evryfs.github.io/helm-charts/
    helm install dependency-track evryfs-oss/dependency-track --namespace dependency-track --create-namespace
    ```

=== "Helm v2"

    ```shell
    helm repo add evryfs-oss https://evryfs.github.io/helm-charts/
    helm install evryfs-oss/dependency-track --name dependency-track --namespace dependency-track --create-namespace
    ```

!!! note
    By default, it will install PostgreSQL and use persistent volume claims for the `data` directory used for vulnerability feeds.