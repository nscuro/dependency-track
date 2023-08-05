package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Test;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.assertj.core.api.Assertions.assertThat;

public class PolicyConditionResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(PolicyConditionResource.class)
                                .register(ApiFilter.class)
                                .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void testCreatePolicyConditionWithInvalidExpression() {
        final Policy policy = qm.createPolicy("foo", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        final var jsonPolicyCondition = new PolicyCondition();
        jsonPolicyCondition.setSubject(PolicyCondition.Subject.EXPRESSION);
        jsonPolicyCondition.setOperator(PolicyCondition.Operator.MATCHES);
        jsonPolicyCondition.setValue("""
                component.doesNotExist == "bar"
                """);

        final Response response = target("%s/%s/condition".formatted(V1_POLICY, policy.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(jsonPolicyCondition, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("""
                The provided CEL expression is invalid: Failed to check script: ERROR: <input>:1:10: undefined field 'doesNotExist'
                 | component.doesNotExist == "bar"
                 | .........^\
                """);
    }

}