package com.sap.cloudfoundry.client.facade;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.cloudfoundry.client.v3.jobs.JobState;
import org.cloudfoundry.client.v3.serviceinstances.ServiceInstanceType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.sap.cloudfoundry.client.facade.domain.CloudAsyncJob;
import com.sap.cloudfoundry.client.facade.domain.CloudPackage;
import com.sap.cloudfoundry.client.facade.domain.CloudServiceBroker;
import com.sap.cloudfoundry.client.facade.domain.CloudServiceInstance;
import com.sap.cloudfoundry.client.facade.domain.ImmutableCloudRouteSummary;
import com.sap.cloudfoundry.client.facade.domain.ImmutableCloudServiceBroker;
import com.sap.cloudfoundry.client.facade.domain.ImmutableCloudServiceInstance;
import com.sap.cloudfoundry.client.facade.domain.ImmutableStaging;
import com.sap.cloudfoundry.client.facade.util.JsonUtil;

class ServicesCloudControllerClientIntegrationTest extends CloudControllerClientIntegrationTest {

    private static final String SYSLOG_DRAIN_URL = "syslogDrain";
    private static final Map<String, Object> USER_SERVICE_CREDENTIALS = Map.of("testCredentialsKey", "testCredentialsValue");

    private static boolean pushedServiceBroker = false;

    @BeforeAll
    static void setUp() throws InterruptedException {
        String brokerPathString = ITVariable.PATH_TO_SERVICE_BROKER_APPLICATION.getValue();
        if (brokerPathString == null) {
            return;
        }
        Path brokerPath = Paths.get(brokerPathString);
        if (Files.notExists(brokerPath)) {
            fail(MessageFormat.format("Specified service broker path \"{0}\" not exists", brokerPathString));
        }
        pushServiceBrokerApplication(brokerPath);
        createServiceBroker(IntegrationTestConstants.SERVICE_BROKER_NAME, "configurations/1");
        pushedServiceBroker = true;
    }

    @AfterAll
    static void tearDown() throws InterruptedException {
        if (pushedServiceBroker) {
            String jobId = client.deleteServiceBroker(IntegrationTestConstants.SERVICE_BROKER_NAME);
            pollServiceBrokerOperation(jobId, IntegrationTestConstants.SERVICE_BROKER_NAME);
            client.deleteApplication(IntegrationTestConstants.SERVICE_BROKER_APP_NAME);
            client.deleteRoute(IntegrationTestConstants.SERVICE_BROKER_HOST, client.getDefaultDomain()
                                                                                   .getName(),
                               null);
        }
    }

    @Test
    @DisplayName("Create a user provided service and verify its parameters")
    void createUserProvidedServiceTest() {
        String serviceName = "test-service-1";
        try {
            client.createUserProvidedServiceInstance(buildUserProvidedService(serviceName), USER_SERVICE_CREDENTIALS, SYSLOG_DRAIN_URL);
            CloudServiceInstance service = client.getServiceInstance(serviceName);
            Map<String, Object> serviceCredentials = client.getUserProvidedServiceInstanceParameters(service.getGuid());
            assertEquals(SYSLOG_DRAIN_URL, service.getSyslogDrainUrl());
            assertEquals(USER_SERVICE_CREDENTIALS, serviceCredentials);
            assertTrue(service.isUserProvided());
        } catch (Exception e) {
            fail(e);
        } finally {
            client.deleteServiceInstance(serviceName);
        }
    }

    @Test
    @DisplayName("Create a user provided service and update its parameters")
    void updateUserProvidedServiceTest() {
        String serviceName = "test-service-2";
        Map<String, Object> updatedServiceCredentials = Map.of("newTestCredentialsKey", "newTestCredentialsValue");
        String updatedSyslogDrainUrl = "newSyslogDrain";
        List<String> updatedTags = List.of("tag1", "tag2");
        try {
            client.createUserProvidedServiceInstance(buildUserProvidedService(serviceName), USER_SERVICE_CREDENTIALS, SYSLOG_DRAIN_URL);

            client.updateServiceParameters(serviceName, updatedServiceCredentials);

            client.updateServiceSyslogDrainUrl(serviceName, updatedSyslogDrainUrl);

            client.updateServiceTags(serviceName, updatedTags);

            CloudServiceInstance service = client.getServiceInstance(serviceName);
            Map<String, Object> serviceCredentials = client.getUserProvidedServiceInstanceParameters(service.getGuid());

            assertEquals(updatedSyslogDrainUrl, service.getSyslogDrainUrl());
            assertEquals(updatedServiceCredentials, serviceCredentials);
            assertTrue(service.getTags()
                              .containsAll(updatedTags),
                       MessageFormat.format("Expected tags \"{0}\" but was \"{1}\"", updatedTags, service.getTags()));
        } catch (Exception e) {
            fail(e);
        } finally {
            client.deleteServiceInstance(serviceName);
        }

    }

    static Stream<Arguments> createManagedService() {
        return Stream.of(
                         // (1) Without specified broker name
                         Arguments.of("test-managed-service", null),
                         // (2) With specified broker name
                         Arguments.of("test-managed-service-with-broker", "test-service-broker"));
    }

    @ParameterizedTest
    @MethodSource
    @DisplayName("Create a managed service")
    void createManagedService(String serviceName, String brokerName) {
        if (!pushedServiceBroker) {
            return;
        }

        try {
            client.createServiceInstance(ImmutableCloudServiceInstance.builder()
                                                                      .name(serviceName)
                                                                      .label(IntegrationTestConstants.SERVICE_OFFERING)
                                                                      .plan(IntegrationTestConstants.SERVICE_PLAN)
                                                                      .broker(brokerName)
                                                                      .build());
            CloudServiceInstance service = client.getServiceInstance(serviceName);
            assertEquals(serviceName, service.getName());
            assertEquals(IntegrationTestConstants.SERVICE_OFFERING, service.getLabel());
            assertEquals(IntegrationTestConstants.SERVICE_PLAN, service.getPlan());
        } catch (Exception e) {
            fail(e);
        } finally {
            client.deleteServiceInstance(serviceName);
        }

    }

    @Test
    @DisplayName("Update managed service")
    void updateManagedService() {
        if (!pushedServiceBroker) {
            return;
        }
        String serviceName = "test-service";
        Map<String, Object> parameters = Map.of("test-key", "test-value", "test-key-2", "test-value-2");
        List<String> serviceTags = List.of("test", "prod");

        try {
            client.createServiceInstance(ImmutableCloudServiceInstance.builder()
                                                                      .name(serviceName)
                                                                      .label(IntegrationTestConstants.SERVICE_OFFERING)
                                                                      .plan(IntegrationTestConstants.SERVICE_PLAN)
                                                                      .build());

            client.updateServicePlan(serviceName, IntegrationTestConstants.SERVICE_PLAN_2);

            client.updateServiceParameters(serviceName, parameters);

            client.updateServiceTags(serviceName, serviceTags);

            CloudServiceInstance service = client.getServiceInstance(serviceName);
            Map<String, Object> resultParameters = client.getServiceInstanceParameters(service.getGuid());

            assertEquals(serviceName, service.getName());
            assertEquals(IntegrationTestConstants.SERVICE_OFFERING, service.getLabel());
            assertEquals(IntegrationTestConstants.SERVICE_PLAN_2, service.getPlan());
            assertEquals(parameters, resultParameters);
            assertTrue(service.getTags()
                              .containsAll(serviceTags),
                       MessageFormat.format("Expected tags \"{0}\" but was \"{1}\"", serviceTags, service.getTags()));
        } catch (Exception e) {
            fail(e);
        } finally {
            client.deleteServiceInstance(serviceName);
        }

    }

    static Stream<Arguments> getServiceInstance() {
        return Stream.of(Arguments.of("test-service", true, null, true),
                         Arguments.of("not-exist", true, CloudOperationException.class, false),
                         Arguments.of("not-exist-optional", false, null, false));
    }

    @ParameterizedTest
    @MethodSource
    @DisplayName("Get service instance")
    void getServiceInstance(String serviceName, boolean required, Class<? extends Exception> expectedException, boolean expectedService) {
        if (!pushedServiceBroker) {
            return;
        }
        String serviceNameToCreate = "test-service";

        try {
            client.createServiceInstance(ImmutableCloudServiceInstance.builder()
                                                                      .name(serviceNameToCreate)
                                                                      .label(IntegrationTestConstants.SERVICE_OFFERING)
                                                                      .plan(IntegrationTestConstants.SERVICE_PLAN)
                                                                      .build());

            if (expectedException != null) {
                assertThrows(expectedException, () -> client.getServiceInstance(serviceName, required));
                return;
            }

            CloudServiceInstance service = client.getServiceInstance(serviceName, required);
            if (expectedService) {
                assertEquals(serviceName, service.getName());
                return;
            }
            assertNull(service);
        } catch (Exception e) {
            fail(e);
        } finally {
            client.deleteServiceInstance(serviceNameToCreate);
        }
    }

    @Test
    @DisplayName("Delete service instance")
    void deleteServiceInstance() {
        if (!pushedServiceBroker) {
            return;
        }
        String serviceName = "test-service";

        try {
            client.createServiceInstance(ImmutableCloudServiceInstance.builder()
                                                                      .name(serviceName)
                                                                      .label(IntegrationTestConstants.SERVICE_OFFERING)
                                                                      .plan(IntegrationTestConstants.SERVICE_PLAN)
                                                                      .build());

            client.deleteServiceInstance(serviceName);
            assertThrows(CloudOperationException.class, () -> client.getServiceInstance(serviceName));
        } catch (Exception e) {
            fail(e);
        } finally {
            CloudServiceInstance service = client.getServiceInstance(serviceName, false);
            if (service != null) {
                client.deleteServiceInstance(service);
            }
        }
    }

    @Test
    @DisplayName("Create space scoped service broker")
    void createSpaceScopedServiceBroker() throws InterruptedException {
        if (!pushedServiceBroker) {
            return;
        }
        String serviceBrokerName = "test-space-scoped-service-broker";
        String defaultDomain = client.getDefaultDomain()
                                     .getName();
        String expectedServiceBrokerUrl = MessageFormat.format("https://{0}.{1}/{2}", IntegrationTestConstants.SERVICE_BROKER_HOST,
                                                               defaultDomain, "configurations/2");

        try {
            createServiceBroker(serviceBrokerName, "configurations/2");

            CloudServiceBroker broker = client.getServiceBroker(serviceBrokerName);
            assertEquals(serviceBrokerName, broker.getName());
            assertEquals(target.getMetadata()
                               .getGuid()
                               .toString(),
                         broker.getSpaceGuid());
            assertEquals(expectedServiceBrokerUrl, broker.getUrl());
        } catch (Exception e) {
            fail(e);
        } finally {
            String jobId = client.deleteServiceBroker(serviceBrokerName);
            pollServiceBrokerOperation(jobId, serviceBrokerName);
        }
    }

    @Test
    @DisplayName("Update space scoped service broker")
    void updateSpaceScopedServiceBroker() throws InterruptedException {
        if (!pushedServiceBroker) {
            return;
        }
        String serviceBrokerName = "test-space-scoped-service-broker";
        String targetSpaceGuid = target.getMetadata()
                                       .getGuid()
                                       .toString();
        String defaultDomain = client.getDefaultDomain()
                                     .getName();
        String expectedServiceBrokerUrl = MessageFormat.format("https://{0}.{1}/{2}", IntegrationTestConstants.SERVICE_BROKER_HOST,
                                                               defaultDomain, "configurations/3");

        try {
            createServiceBroker(serviceBrokerName, "configurations/2");

            String jobId = client.updateServiceBroker(ImmutableCloudServiceBroker.builder()
                                                                                 .name(serviceBrokerName)
                                                                                 .username("new-user")
                                                                                 .password("new-password")
                                                                                 .url(MessageFormat.format("https://{0}.{1}/{2}",
                                                                                                           IntegrationTestConstants.SERVICE_BROKER_HOST,
                                                                                                           defaultDomain,
                                                                                                           "configurations/3"))
                                                                                 .spaceGuid(targetSpaceGuid)
                                                                                 .build());
            pollServiceBrokerOperation(jobId, serviceBrokerName);

            CloudServiceBroker broker = client.getServiceBroker(serviceBrokerName);
            assertEquals(serviceBrokerName, broker.getName());
            assertEquals(target.getMetadata()
                               .getGuid()
                               .toString(),
                         broker.getSpaceGuid());
            assertEquals(expectedServiceBrokerUrl, broker.getUrl());
        } catch (Exception e) {
            fail(e);
        } finally {
            String jobId = client.deleteServiceBroker(serviceBrokerName);
            pollServiceBrokerOperation(jobId, serviceBrokerName);
        }
    }

    @Test
    @DisplayName("Delete space scoped service broker")
    void deleteSpaceScopedServiceBroker() throws InterruptedException {
        if (!pushedServiceBroker) {
            return;
        }
        String serviceBrokerName = "test-space-scoped-service-broker";

        try {
            createServiceBroker(serviceBrokerName, "configurations/2");

            String jobId = client.deleteServiceBroker(serviceBrokerName);
            pollServiceBrokerOperation(jobId, serviceBrokerName);

            assertThrows(CloudOperationException.class, () -> client.getServiceBroker(serviceBrokerName));
        } catch (Exception e) {
            fail(e);
        } finally {
            CloudServiceBroker broker = client.getServiceBroker(serviceBrokerName, false);
            if (broker != null) {
                String jobId = client.deleteServiceBroker(serviceBrokerName);
                pollServiceBrokerOperation(jobId, serviceBrokerName);
            }
        }
    }

    private static void pushServiceBrokerApplication(Path brokerPath) throws InterruptedException {
        client.createApplication(IntegrationTestConstants.SERVICE_BROKER_APP_NAME, ImmutableStaging.builder()
                                                                                                   .addBuildpack(IntegrationTestConstants.JAVA_BUILDPACK)
                                                                                                   .build(),
                                 IntegrationTestConstants.SERVICE_BROKER_DISK_IN_MB, IntegrationTestConstants.SERVICE_BROKER_MEMORY_IN_MB,
                                 Set.of(ImmutableCloudRouteSummary.builder()
                                                                  .host(IntegrationTestConstants.SERVICE_BROKER_HOST)
                                                                  .domain(client.getDefaultDomain()
                                                                                .getName())
                                                                  .build()));

        Map<String, String> appEnv = getServiceBrokerEnvConfiguration();
        client.updateApplicationEnv(IntegrationTestConstants.SERVICE_BROKER_APP_NAME, appEnv);

        CloudPackage cloudPackage = ApplicationUtil.uploadApplication(client, IntegrationTestConstants.SERVICE_BROKER_APP_NAME, brokerPath);
        ApplicationUtil.stageApplication(client, IntegrationTestConstants.SERVICE_BROKER_APP_NAME, cloudPackage);

        ApplicationUtil.startApplication(client, IntegrationTestConstants.SERVICE_BROKER_APP_NAME);
    }

    private static Map<String, String> getServiceBrokerEnvConfiguration() {
        URL url = ServicesCloudControllerClientIntegrationTest.class.getResource(IntegrationTestConstants.SERVICE_BROKER_ENV_CONTENT);
        String configuration;
        try {
            configuration = Files.readString(Paths.get(url.toURI()));
        } catch (URISyntaxException | IOException e) {
            throw new IllegalStateException(e);
        }
        return JsonUtil.convertJsonToMap(configuration)
                       .entrySet()
                       .stream()
                       .collect(Collectors.toMap(Map.Entry::getKey,
                                                 ServicesCloudControllerClientIntegrationTest::convertMapEntryValueToString));

    }

    private static String convertMapEntryValueToString(Map.Entry<String, Object> entry) {
        if (entry.getValue() instanceof String) {
            return (String) entry.getValue();
        }
        return JsonUtil.convertToJson(entry.getValue(), true);
    }

    private static void createServiceBroker(String serviceBrokerName, String serviceBrokerEndpoint) throws InterruptedException {
        String defaultDomain = client.getDefaultDomain()
                                     .getName();
        String targetSpaceGuid = target.getMetadata()
                                       .getGuid()
                                       .toString();
        String jobId = client.createServiceBroker(ImmutableCloudServiceBroker.builder()
                                                                             .name(serviceBrokerName)
                                                                             .username(IntegrationTestConstants.SERVICE_BROKER_USERNAME)
                                                                             .password(IntegrationTestConstants.SERVICE_BROKER_PASSWORD)
                                                                             .url(MessageFormat.format("https://{0}.{1}/{2}",
                                                                                                       IntegrationTestConstants.SERVICE_BROKER_HOST,
                                                                                                       defaultDomain,
                                                                                                       serviceBrokerEndpoint))
                                                                             .spaceGuid(targetSpaceGuid)
                                                                             .build());
        pollServiceBrokerOperation(jobId, serviceBrokerName);
    }

    private static void pollServiceBrokerOperation(String jobId, String serviceBrokerName) throws InterruptedException {
        CloudAsyncJob job = client.getAsyncJob(jobId);
        while (job.getState() != JobState.COMPLETE && !hasAsyncJobFailed(job)) {
            Thread.sleep(1000);
            job = client.getAsyncJob(jobId);
        }
        if (hasAsyncJobFailed(job)) {
            fail(MessageFormat.format("Polling async operation of service broker \"{0}\" failed with \"{1}\"", serviceBrokerName,
                                      job.getErrors()));
        }
    }

    private static boolean hasAsyncJobFailed(CloudAsyncJob job) {
        return job.getState() == JobState.FAILED;
    }

    private CloudServiceInstance buildUserProvidedService(String serviceName) {
        return ImmutableCloudServiceInstance.builder()
                                            .name(serviceName)
                                            .type(ServiceInstanceType.USER_PROVIDED)
                                            .build();
    }

}
