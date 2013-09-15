/*
 * Copyright 2010 Ning, Inc.
 *
 * Ning licenses this file to you under the Apache License, version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.asynchttpclient.async;

import static org.testng.Assert.*;

import java.io.InputStream;
import java.net.ConnectException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.AsyncHttpClientConfig.Builder;
import org.asynchttpclient.Response;
import org.asynchttpclient.async.util.TestUtils;
import org.testng.annotations.Test;

public abstract class BasicHttpsTest extends AbstractBasicHttpsTest {

    protected String getTargetUrl() {
        return String.format("https://127.0.0.1:%d/foo/test", port1);
    }

    @Test(groups = { "standalone", "default_provider" })
    public void zeroCopyPostTest() throws Exception {

        final AsyncHttpClient client = getAsyncHttpClient(new Builder().setSSLContext(createSSLContext(new AtomicBoolean(true))).build());
        try {
            Response resp = client.preparePost(getTargetUrl()).setBody(TestUtils.SIMPLE_TEXT_FILE).setHeader("Content-Type", "text/html").execute().get();
            assertNotNull(resp);
            assertEquals(resp.getStatusCode(), HttpServletResponse.SC_OK);
            assertEquals(resp.getResponseBody(), "This is a simple test file");
        } finally {
            client.close();
        }
    }

    @Test(groups = { "standalone", "default_provider" })
    public void multipleSSLRequestsTest() throws Exception {
        final AsyncHttpClient c = getAsyncHttpClient(new Builder().setSSLContext(createSSLContext(new AtomicBoolean(true))).build());
        try {
            String body = "hello there";

            // once
            Response response = c.preparePost(getTargetUrl()).setBody(body).setHeader("Content-Type", "text/html").execute().get(TIMEOUT, TimeUnit.SECONDS);

            assertEquals(response.getResponseBody(), body);

            // twice
            response = c.preparePost(getTargetUrl()).setBody(body).setHeader("Content-Type", "text/html").execute().get(TIMEOUT, TimeUnit.SECONDS);

            assertEquals(response.getResponseBody(), body);
        } finally {
            c.close();
        }
    }

    @Test(groups = { "standalone", "default_provider" })
    public void multipleSSLWithoutCacheTest() throws Exception {
        AsyncHttpClient c = getAsyncHttpClient(new Builder().setSSLContext(createSSLContext(new AtomicBoolean(true))).setAllowSslConnectionPool(false).build());
        try {
            String body = "hello there";
            c.preparePost(getTargetUrl()).setBody(body).setHeader("Content-Type", "text/html").execute();

            c.preparePost(getTargetUrl()).setBody(body).setHeader("Content-Type", "text/html").execute();

            Response response = c.preparePost(getTargetUrl()).setBody(body).setHeader("Content-Type", "text/html").execute().get();

            assertEquals(response.getResponseBody(), body);
        } finally {
            c.close();
        }
    }

    @Test(groups = { "standalone", "default_provider" })
    public void reconnectsAfterFailedCertificationPath() throws Exception {
        AtomicBoolean trusted = new AtomicBoolean(false);
        AsyncHttpClient c = getAsyncHttpClient(new Builder().setSSLContext(createSSLContext(trusted)).build());
        try {
            String body = "hello there";

            // first request fails because server certificate is rejected
            try {
                c.preparePost(getTargetUrl()).setBody(body).setHeader("Content-Type", "text/html").execute().get(TIMEOUT, TimeUnit.SECONDS);
            } catch (final ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof ConnectException) {
                    assertNotNull(cause.getCause());
                    assertTrue(cause.getCause() instanceof SSLHandshakeException, "Expected an SSLHandshakeException, got a " + cause.getCause());
                } else {
                    assertTrue(cause instanceof SSLHandshakeException, "Expected an SSLHandshakeException, got a " + cause);
                }
            }

            trusted.set(true);

            // second request should succeed
            Response response = c.preparePost(getTargetUrl()).setBody(body).setHeader("Content-Type", "text/html").execute().get(TIMEOUT, TimeUnit.SECONDS);

            assertEquals(response.getResponseBody(), body);
        } finally {
            c.close();
        }
    }

    private static SSLContext createSSLContext(AtomicBoolean trusted) {
        InputStream keyStoreStream = BasicHttpsTest.class.getResourceAsStream("ssltest-cacerts.jks");
        try {
            char[] keyStorePassword = "changeit".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(keyStoreStream, keyStorePassword);

            // Set up key manager factory to use our key store
            char[] certificatePassword = "changeit".toCharArray();
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, certificatePassword);

            // Initialize the SSLContext to work with our key managers.
            KeyManager[] keyManagers = kmf.getKeyManagers();
            TrustManager[] trustManagers = new TrustManager[] { dummyTrustManager(trusted) };
            SecureRandom secureRandom = new SecureRandom();

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, trustManagers, secureRandom);

            return sslContext;
        } catch (Exception e) {
            throw new Error("Failed to initialize the server-side SSLContext", e);
        } finally {
            IOUtils.closeQuietly(keyStoreStream);
        }
    }

    private static final TrustManager dummyTrustManager(final AtomicBoolean trusted) {
        return new X509TrustManager() {

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if (!trusted.get()) {
                    throw new CertificateException("Server certificate not trusted.");
                }
            }
        };
    }
}
