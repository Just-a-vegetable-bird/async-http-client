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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.Charset;
import java.util.Enumeration;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.FileUtils;
import org.asynchttpclient.AsyncCompletionHandler;
import org.asynchttpclient.AsyncHandler;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.AsyncHttpClientConfig;
import org.asynchttpclient.HttpResponseBodyPart;
import org.asynchttpclient.HttpResponseHeaders;
import org.asynchttpclient.HttpResponseStatus;
import org.asynchttpclient.Response;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;

public abstract class AbstractBasicTest {
    protected final Logger log = LoggerFactory.getLogger(AbstractBasicTest.class);
    protected Server server;
    protected int port1;
    protected int port2;

    public final static int TIMEOUT = 30;
    public static final File TMP = new File(System.getProperty("java.io.tmpdir"), "ahc-tests-" + UUID.randomUUID().toString().substring(0, 8));
    public static final byte[] PATTERN_BYTES = "FooBarBazQixFooBarBazQixFooBarBazQixFooBarBazQixFooBarBazQixFooBarBazQix".getBytes(Charset.forName("UTF-16"));
    public static final File LARGE_IMAGE_FILE;
    public static byte[] LARGE_IMAGE_BYTES;
    public static final File SIMPLE_TEXT_FILE;

    static {
        try {
            TMP.mkdirs();
            TMP.deleteOnExit();
            LARGE_IMAGE_FILE = new File(AbstractBasicTest.class.getClassLoader().getResource("300k.png").toURI());
            LARGE_IMAGE_BYTES = FileUtils.readFileToByteArray(LARGE_IMAGE_FILE);
            SIMPLE_TEXT_FILE = new File(AbstractBasicTest.class.getClassLoader().getResource("SimpleTextFile.txt").toURI());
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static File createTempFile(byte[] pattern, int repeat) throws IOException {
        File tmpFile = File.createTempFile("tmpfile-", ".data", TMP);
        tmpFile.deleteOnExit();
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(tmpFile);
            for (int i = 0; i < repeat; i++) {
                out.write(pattern);
            }
            
            long expectedFileSize = PATTERN_BYTES.length * repeat;
            Assert.assertEquals(expectedFileSize, tmpFile.length(), "Invalid file length");
            
            return tmpFile;
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }

    public static class EchoHandler extends AbstractHandler {

        @Override
        public void handle(String pathInContext, Request request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException, ServletException {

            if (httpRequest.getHeader("X-HEAD") != null) {
                httpResponse.setContentLength(1);
            }

            if (httpRequest.getHeader("X-ISO") != null) {
                httpResponse.setContentType("text/html; charset=ISO-8859-1");
            } else {
                httpResponse.setContentType("text/html; charset=utf-8");
            }

            if (request.getMethod().equalsIgnoreCase("OPTIONS")) {
                httpResponse.addHeader("Allow", "GET,HEAD,POST,OPTIONS,TRACE");
            }
            ;

            Enumeration<?> e = httpRequest.getHeaderNames();
            String param;
            while (e.hasMoreElements()) {
                param = e.nextElement().toString();

                if (param.startsWith("LockThread")) {
                    try {
                        Thread.sleep(40 * 1000);
                    } catch (InterruptedException ex) {
                    }
                }

                if (param.startsWith("X-redirect")) {
                    httpResponse.sendRedirect(httpRequest.getHeader("X-redirect"));
                    return;
                }
                httpResponse.addHeader("X-" + param, httpRequest.getHeader(param));
            }

            Enumeration<?> i = httpRequest.getParameterNames();

            StringBuilder requestBody = new StringBuilder();
            while (i.hasMoreElements()) {
                param = i.nextElement().toString();
                httpResponse.addHeader("X-" + param, httpRequest.getParameter(param));
                requestBody.append(param);
                requestBody.append("_");
            }

            String pathInfo = httpRequest.getPathInfo();
            if (pathInfo != null)
                httpResponse.addHeader("X-pathInfo", pathInfo);

            String queryString = httpRequest.getQueryString();
            if (queryString != null)
                httpResponse.addHeader("X-queryString", queryString);

            httpResponse.addHeader("X-KEEP-ALIVE", httpRequest.getRemoteAddr() + ":" + httpRequest.getRemotePort());

            Cookie[] cs = httpRequest.getCookies();
            if (cs != null) {
                for (Cookie c : cs) {
                    httpResponse.addCookie(c);
                }
            }

            if (requestBody.length() > 0) {
                httpResponse.getOutputStream().write(requestBody.toString().getBytes());
            }

            int size = 16384;
            if (httpRequest.getContentLength() > 0) {
                size = httpRequest.getContentLength();
            }
            byte[] bytes = new byte[size];
            if (bytes.length > 0) {
                int read = 0;
                while (read > -1) {
                    read = httpRequest.getInputStream().read(bytes);
                    if (read > 0) {
                        httpResponse.getOutputStream().write(bytes, 0, read);
                    }
                }
            }

            httpResponse.setStatus(200);
            httpResponse.getOutputStream().flush();
            httpResponse.getOutputStream().close();
        }
    }

    @BeforeClass(alwaysRun = true)
    public void setUpGlobal() throws Exception {
        server = new Server();

        port1 = findFreePort();
        port2 = findFreePort();

        Connector listener = new SelectChannelConnector();

        listener.setHost("127.0.0.1");
        listener.setPort(port1);

        server.addConnector(listener);

        listener = new SelectChannelConnector();
        listener.setHost("127.0.0.1");
        listener.setPort(port2);

        server.addConnector(listener);

        server.setHandler(configureHandler());
        server.start();
        log.info("Local HTTP server started successfully");
    }

    @AfterClass(alwaysRun = true)
    public void tearDownGlobal() throws Exception {
        if (server != null)
            server.stop();
    }

    protected synchronized int findFreePort() throws IOException {
        ServerSocket socket = null;

        try {
            socket = new ServerSocket(0);

            return socket.getLocalPort();
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    protected String getTargetUrl() {
        return String.format("http://127.0.0.1:%d/foo/test", port1);
    }

    protected String getTargetUrl2() {
        return String.format("https://127.0.0.1:%d/foo/test", port2);
    }

    public AbstractHandler configureHandler() throws Exception {
        return new EchoHandler();
    }

    public static class AsyncCompletionHandlerAdapter extends AsyncCompletionHandler<Response> {
        public Runnable runnable;

        @Override
        public Response onCompleted(Response response) throws Exception {
            return response;
        }

        @Override
        public void onThrowable(Throwable t) {
            t.printStackTrace();
            Assert.fail("Unexpected exception: " + t.getMessage(), t);
        }

    }

    public static class AsyncHandlerAdapter implements AsyncHandler<String> {

        @Override
        public void onThrowable(Throwable t) {
            t.printStackTrace();
            Assert.fail("Unexpected exception", t);
        }

        @Override
        public STATE onBodyPartReceived(final HttpResponseBodyPart content) throws Exception {
            return STATE.CONTINUE;
        }

        @Override
        public STATE onStatusReceived(final HttpResponseStatus responseStatus) throws Exception {
            return STATE.CONTINUE;
        }

        @Override
        public STATE onHeadersReceived(final HttpResponseHeaders headers) throws Exception {
            return STATE.CONTINUE;
        }

        @Override
        public String onCompleted() throws Exception {
            return "";
        }
    }

    public abstract AsyncHttpClient getAsyncHttpClient(AsyncHttpClientConfig config);
}
