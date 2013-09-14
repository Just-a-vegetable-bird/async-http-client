/*
 * Copyright (c) 2010-2012 Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package org.asynchttpclient.async;

import static org.testng.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;

import org.asynchttpclient.AsyncCompletionHandlerBase;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.AsyncHttpClientConfig;
import org.asynchttpclient.ProxyServer;
import org.asynchttpclient.RequestBuilder;
import org.asynchttpclient.Response;
import org.asynchttpclient.SimpleAsyncHttpClient;
import org.eclipse.jetty.proxy.ConnectHandler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Proxy usage tests.
 */
public abstract class ProxyTunnellingTest extends AbstractBasicTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProxyTunnellingTest.class);

    private Server server2;

    public abstract String getProviderClass();

    public AbstractHandler configureHandler() throws Exception {
        return new ConnectHandler();
    }

    @BeforeClass(alwaysRun = true)
    public void setUpGlobal() throws Exception {

        server = new Server();
        server2 = new Server();
        port1 = findFreePort();
        port2 = findFreePort();

        ServerConnector listener = new ServerConnector(server);
        listener.setHost("127.0.0.1");
        listener.setPort(port1);

        server.addConnector(listener);

        server.setHandler(configureHandler());
        server.start();

        ClassLoader cl = getClass().getClassLoader();

        URL keystoreUrl = cl.getResource("ssltest-keystore.jks");
        String keyStoreFile = new File(keystoreUrl.toURI()).getAbsolutePath();
        LOGGER.info("SSL keystore path: {}", keyStoreFile);
        SslContextFactory sslContextFactory = new SslContextFactory(keyStoreFile);
        sslContextFactory.setKeyStorePassword("changeit");

        String trustStoreFile = new File(cl.getResource("ssltest-cacerts.jks").toURI()).getAbsolutePath();
        LOGGER.info("SSL certs path: {}", trustStoreFile);
        sslContextFactory.setTrustStorePath(trustStoreFile);
        sslContextFactory.setTrustStorePassword("changeit");

        HttpConfiguration http_config = new HttpConfiguration();
        http_config.setSecureScheme("https");
        http_config.setSecurePort(port2);

        HttpConfiguration https_config = new HttpConfiguration(http_config);
        https_config.addCustomizer(new SecureRequestCustomizer());

        ServerConnector connector = new ServerConnector(server2, new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory(https_config));
        connector.setHost("127.0.0.1");
        connector.setPort(port2);
        server2.addConnector(connector);

        server2.setHandler(new EchoHandler());
        server2.start();

        log.info("Local HTTP server started successfully");
    }

    @AfterClass(alwaysRun = true)
    public void tearDownGlobal() throws Exception {
        server.stop();
        server2.stop();
    }

    @Test(groups = { "online", "default_provider" })
    public void testRequestProxy() throws IOException, InterruptedException, ExecutionException, TimeoutException {
        AsyncHttpClientConfig.Builder b = new AsyncHttpClientConfig.Builder();
        b.setFollowRedirects(true);

        ProxyServer ps = new ProxyServer(ProxyServer.Protocol.HTTPS, "127.0.0.1", port1);

        AsyncHttpClientConfig config = b.build();
        AsyncHttpClient asyncHttpClient = getAsyncHttpClient(config);
        try {
            RequestBuilder rb = new RequestBuilder("GET").setProxyServer(ps).setUrl(getTargetUrl2());
            Future<Response> responseFuture = asyncHttpClient.executeRequest(rb.build(), new AsyncCompletionHandlerBase() {

                public void onThrowable(Throwable t) {
                    t.printStackTrace();
                    log.debug(t.getMessage(), t);
                }

                @Override
                public Response onCompleted(Response response) throws Exception {
                    return response;
                }
            });
            Response r = responseFuture.get();
            assertEquals(r.getStatusCode(), 200);
            assertEquals(r.getHeader("X-Proxy-Connection"), "keep-alive");
        } finally {
            asyncHttpClient.close();
        }
    }

    @Test(groups = { "online", "default_provider" })
    public void testConfigProxy() throws IOException, InterruptedException, ExecutionException, TimeoutException {
        AsyncHttpClientConfig.Builder b = new AsyncHttpClientConfig.Builder();
        b.setFollowRedirects(true);

        ProxyServer ps = new ProxyServer(ProxyServer.Protocol.HTTPS, "127.0.0.1", port1);
        b.setProxyServer(ps);

        AsyncHttpClientConfig config = b.build();
        AsyncHttpClient asyncHttpClient = getAsyncHttpClient(config);
        try {
            RequestBuilder rb = new RequestBuilder("GET").setUrl(getTargetUrl2());
            Future<Response> responseFuture = asyncHttpClient.executeRequest(rb.build(), new AsyncCompletionHandlerBase() {

                public void onThrowable(Throwable t) {
                    t.printStackTrace();
                    log.debug(t.getMessage(), t);
                }

                @Override
                public Response onCompleted(Response response) throws Exception {
                    return response;
                }
            });
            Response r = responseFuture.get();
            assertEquals(r.getStatusCode(), 200);
            assertEquals(r.getHeader("X-Proxy-Connection"), "keep-alive");
        } finally {
            asyncHttpClient.close();
        }
    }

    @Test(groups = { "online", "default_provider" })
    public void testSimpleAHCConfigProxy() throws IOException, InterruptedException, ExecutionException, TimeoutException {

        SimpleAsyncHttpClient client = new SimpleAsyncHttpClient.Builder().setProviderClass(getProviderClass()).setProxyProtocol(ProxyServer.Protocol.HTTPS)
                .setProxyHost("127.0.0.1").setProxyPort(port1).setFollowRedirects(true).setUrl(getTargetUrl2()).setHeader("Content-Type", "text/html").build();
        try {
            Response r = client.get().get();

            assertEquals(r.getStatusCode(), 200);
            assertEquals(r.getHeader("X-Proxy-Connection"), "keep-alive");
        } finally {
            client.close();
        }
    }
}
