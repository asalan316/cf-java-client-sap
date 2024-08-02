package com.sap.cloudfoundry.client.facade.adapters;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.function.Function;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.cloudfoundry.client.CloudFoundryClient;
import org.cloudfoundry.client.v3.organizations.OrganizationsV3;
import org.cloudfoundry.client.v3.spaces.SpacesV3;
import org.cloudfoundry.reactor.ConnectionContext;
import org.cloudfoundry.reactor.DefaultConnectionContext;
import org.cloudfoundry.reactor.client.ReactorCloudFoundryClient;
import org.cloudfoundry.reactor.client.v3.organizations.ReactorOrganizationsV3;
import org.cloudfoundry.reactor.client.v3.spaces.ReactorSpacesV3;
import org.immutables.value.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import com.sap.cloudfoundry.client.facade.CloudException;
import com.sap.cloudfoundry.client.facade.CloudOperationException;
import com.sap.cloudfoundry.client.facade.Messages;
import com.sap.cloudfoundry.client.facade.oauth2.OAuthClient;
import com.sap.cloudfoundry.client.facade.rest.CloudSpaceClient;
import com.sap.cloudfoundry.client.facade.util.CloudUtil;
import com.sap.cloudfoundry.client.facade.util.JsonUtil;

import reactor.core.publisher.Mono;
import reactor.netty.http.Http11SslContextSpec;
import reactor.netty.tcp.SslProvider;
import reactor.netty.tcp.TcpSslContextSpec;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;

@Value.Immutable
public abstract class CloudFoundryClientFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(CloudFoundryClientFactory.class);

    static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
                                                    .executor(Executors.newSingleThreadExecutor())
                                                    .followRedirects(HttpClient.Redirect.NORMAL)
                                                    .connectTimeout(Duration.ofMinutes(10))
                                                    .build();

    private final Map<String, ConnectionContext> connectionContextCache = new ConcurrentHashMap<>();

    public abstract Optional<Duration> getSslHandshakeTimeout();

    public abstract Optional<Duration> getConnectTimeout();

    public abstract Optional<Integer> getConnectionPoolSize();

    public abstract Optional<Integer> getThreadPoolSize();

    public abstract Optional<Duration> getResponseTimeout();

    public CloudFoundryClient createClient(URL controllerUrl, OAuthClient oAuthClient, Map<String, String> requestTags) {
        return ReactorCloudFoundryClient.builder()
                                        .connectionContext(getOrCreateConnectionContext(controllerUrl.getHost()))
                                        .tokenProvider(oAuthClient.getTokenProvider())
                                        .requestTags(requestTags)
                                        .build();
    }

    public LogCacheClient createLogCacheClient(URL controllerUrl, OAuthClient oAuthClient, Map<String, String> requestTags) {
        String logCacheApi;
        try {
            var links = CloudUtil.executeWithRetry(() -> callCfRoot(controllerUrl, requestTags));
            @SuppressWarnings("unchecked")
            var logCache = (Map<String, Object>) links.get("log_cache");
            logCacheApi = (String) logCache.get("href");
        } catch (CloudException e) {
            LOGGER.warn(MessageFormat.format(Messages.CALL_TO_0_FAILED_WITH_1, controllerUrl.toString(), e.getMessage()), e);
            logCacheApi = controllerUrl.toString()
                                       .replace("api", "log-cache");
        }
        return new LogCacheClient(logCacheApi, oAuthClient, requestTags);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> callCfRoot(URL controllerUrl, Map<String, String> requestTags) {
        HttpResponse<String> response;
        try {
            HttpRequest request = buildCfRootRequest(controllerUrl, requestTags);
            LOGGER.info(MessageFormat.format(Messages.CALLING_CF_ROOT_0_TO_ACCESS_LOG_CACHE_URL, controllerUrl));
            response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                var status = HttpStatus.valueOf(response.statusCode());
                throw new CloudOperationException(status, status.getReasonPhrase(), response.body());
            }
            LOGGER.info(Messages.CF_ROOT_REQUEST_FINISHED);
        } catch (InterruptedException | URISyntaxException | IOException e) {
            throw new CloudException(e.getMessage(), e);
        }
        var map = JsonUtil.convertJsonToMap(response.body());
        return (Map<String, Object>) map.get("links");
    }

    private HttpRequest buildCfRootRequest(URL controllerUrl, Map<String, String> requestTags) throws URISyntaxException {
        var requestBuilder = HttpRequest.newBuilder()
                                        .GET()
                                        .uri(controllerUrl.toURI())
                                        .timeout(Duration.ofMinutes(5));
        requestTags.forEach(requestBuilder::header);
        return requestBuilder.build();
    }

    public CloudSpaceClient createSpaceClient(URL controllerUrl, OAuthClient oAuthClient, Map<String, String> requestTags) {
        String v3Api;
        try {
            var links = CloudUtil.executeWithRetry(() -> callCfRoot(controllerUrl, requestTags));
            @SuppressWarnings("unchecked")
            var ccv3 = (Map<String, Object>) links.get("cloud_controller_v3");
            v3Api = (String) ccv3.get("href");
        } catch (CloudException e) {
            LOGGER.warn(MessageFormat.format(Messages.CALL_TO_0_FAILED_WITH_1, controllerUrl.toString(), e.getMessage()), e);
            v3Api = controllerUrl + "/v3";
        }
        LOGGER.info("custom-test: calling createV3SpacesClient");
        var spacesV3 = createV3SpacesClient(controllerUrl, v3Api, oAuthClient, requestTags);
        var orgsV3 = createV3OrgsClient(controllerUrl, v3Api, oAuthClient, requestTags);
        return new CloudSpaceClient(spacesV3, orgsV3);
    }

    private SpacesV3 createV3SpacesClient(URL controllerUrl, String v3Api, OAuthClient oAuthClient, Map<String, String> requestTags) {
        return new ReactorSpacesV3(getOrCreateConnectionContext(controllerUrl.getHost()),
                                   Mono.just(v3Api),
                                   oAuthClient.getTokenProvider(),
                                   requestTags);
    }

    private OrganizationsV3 createV3OrgsClient(URL controllerUrl, String v3Api, OAuthClient oAuthClient, Map<String, String> requestTags) {
        return new ReactorOrganizationsV3(getOrCreateConnectionContext(controllerUrl.getHost()),
                                          Mono.just(v3Api),
                                          oAuthClient.getTokenProvider(),
                                          requestTags);
    }

    public ConnectionContext getOrCreateConnectionContext(String controllerApiHost) {
        LOGGER.info("custom-test: calling createConnectionContext");
        LOGGER.info("custom-test: checking connectionContextCache" + connectionContextCache);
        return createConnectionContext(controllerApiHost); // create connection context everytime
        //return connectionContextCache.computeIfAbsent(controllerApiHost, this::createConnectionContext);
    }

    private ConnectionContext createConnectionContext(String controllerApiHost) {
        LOGGER.info("started custom-test: inside createConnectionContext");
        DefaultConnectionContext.Builder builder = DefaultConnectionContext.builder()
                            .apiHost(controllerApiHost);
        LOGGER.info("custom-test: connection skipSslValidation");
        getSslHandshakeTimeout().ifPresent(builder::sslHandshakeTimeout);
        getConnectTimeout().ifPresent(builder::connectTimeout);
        getConnectionPoolSize().ifPresent(builder::connectionPoolSize);
        getThreadPoolSize().ifPresent(builder::threadPoolSize);
        LOGGER.info("custom-test: connection before getAdditionalHttpClientConfiguration");
        builder.additionalHttpClientConfiguration(this::getAdditionalHttpClientConfiguration);
        LOGGER.info("custom-test: connection after getAdditionalHttpClientConfiguration");
        builder.secure(false);
        builder.skipSslValidation(true);

        reactor.netty.http.client.HttpClient client = reactor.netty.http.client.HttpClient.create();
        builder.httpClient(client.secure( ssl -> {
            try {
                ssl.sslContext(SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build());
            } catch (SSLException e) {
                LOGGER.info("custom-test: ssl.sslContext(SslContextBuilder.forClient(): " + e);
                builder.httpClient(client.noSSL());
            }
        } ));

        DefaultConnectionContext build = builder.build();
        LOGGER.info("finished custom-test: inside createConnectionContext: " + build);
        return build;
    }

    private reactor.netty.http.client.HttpClient getAdditionalHttpClientConfiguration(reactor.netty.http.client.HttpClient client) {
        var clientWithOptions = client;
        if (getResponseTimeout().isPresent()) {
            clientWithOptions = clientWithOptions.responseTimeout(getResponseTimeout().get());
        }
        clientWithOptions = clientWithOptions.metrics(true, Function.identity());
        LOGGER.info("custom-test: before getAdditionalHttpClientConfiguration");
        // TODO: just commect the next line
        clientWithOptions = clientWithOptions.noSSL();
        FascadeSSLUtil.disableSSLValidation();
        Http11SslContextSpec http11SslContextSpec =
                Http11SslContextSpec.forClient()
                        .configure(builder -> builder.trustManager(FascadeSSLUtil.NULL_TRUST_MANAGER));
        clientWithOptions.secure(spec -> spec.sslContext(http11SslContextSpec));

        LOGGER.info("custom-test: after getAdditionalHttpClientConfiguration");

        return clientWithOptions;
    }

}
