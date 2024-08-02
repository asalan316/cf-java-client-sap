package com.sap.cloudfoundry.client.facade.adapters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.*;

public class FascadeSSLUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(FascadeSSLUtil.class);

    private FascadeSSLUtil() {
    }

    public static final X509TrustManager NULL_TRUST_MANAGER = new X509ExtendedTrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            LOGGER.info("custom==starting from getAcceptedIssuers");
            return new X509Certificate[]{};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            LOGGER.info("custom==checkServerTrusted");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
            LOGGER.info("custom==checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            LOGGER.info("custom==checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)");
        }
    };

    public static SSLContext disableSSLValidation() {
        LOGGER.info("==starting from disableSSLValidation");
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { NULL_TRUST_MANAGER }, new SecureRandom());
            //SSLContext.setDefault(sslContext);
           // HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            LOGGER.info("custom ==error occured from disableSSLValidation");
            throw new IllegalStateException(e);
        }
        LOGGER.info("==returning from disableSSLValidation");
        return sslContext;
    }

    public static SSLContext disableSSLCertValidation() {
        SSLContext context;
        try {
            context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] { NULL_TRUST_MANAGER }, null);

        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        return context;
    }

}
