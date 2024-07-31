package com.sap.cloudfoundry.client.facade.adapters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.*;

public class FascadeSSLUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(FascadeSSLUtil.class);

    private FascadeSSLUtil() {
    }

    private static final X509TrustManager NULL_TRUST_MANAGER = new X509TrustManager(){


        @Override
        public void checkClientTrusted(X509Certificate[] xcs, String string) {
            // NOSONAR
        }

        @Override
        public void checkServerTrusted(X509Certificate[] xcs, String string) {
            LOGGER.info("==checking checkServerTrusted with X509Certificate");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

    };

    public static void disableSSLValidation() {
        LOGGER.info("==starting from disableSSLValidation");
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] { NULL_TRUST_MANAGER }, null);
            SSLContext.setDefault(context);
            HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        LOGGER.info("==returning from disableSSLValidation");
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
