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

import static org.testng.AssertJUnit.*;
import static org.testng.FileAssert.fail;

import java.io.BufferedInputStream;
import java.io.FileInputStream;

import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.AsyncHttpClientConfig;
import org.asynchttpclient.Request;
import org.asynchttpclient.RequestBuilder;
import org.asynchttpclient.Response;
import org.asynchttpclient.async.util.TestUtils;
import org.asynchttpclient.generators.InputStreamBodyGenerator;
import org.testng.annotations.Test;

/**
 * Test that the url fetcher is able to communicate via a proxy
 * 
 * @author dominict
 */
abstract public class ChunkingTest extends AbstractBasicTest {
    // So we can just test the returned data is the image,
    // and doesn't contain the chunked delimeters.

    /**
     * Tests that the custom chunked stream result in success and content returned that is unchunked
     */
    @Test()
    public void testCustomChunking() throws Exception {
        AsyncHttpClientConfig.Builder bc = new AsyncHttpClientConfig.Builder();

        bc.setAllowPoolingConnection(true);
        bc.setMaximumConnectionsPerHost(1);
        bc.setMaximumConnectionsTotal(1);
        bc.setConnectionTimeoutInMs(1000);
        bc.setRequestTimeoutInMs(1000);
        bc.setFollowRedirects(true);

        AsyncHttpClient c = getAsyncHttpClient(bc.build());
        try {

            RequestBuilder builder = new RequestBuilder("POST");
            builder.setUrl(getTargetUrl());
            // made buff in stream big enough to mark.
            builder.setBody(new InputStreamBodyGenerator(new BufferedInputStream(new FileInputStream(TestUtils.LARGE_IMAGE_FILE), 400000)));

            Request r = builder.build();

            Response response = c.executeRequest(r).get();
            if (500 == response.getStatusCode()) {
                System.out.println("==============");
                System.out.println("500 response from call");
                System.out.println("Headers:" + response.getHeaders());
                System.out.println("==============");
                System.out.flush();
                assertEquals("Should have 500 status code", 500, response.getStatusCode());
                assertTrue("Should have failed due to chunking", response.getHeader("X-Exception").contains("invalid.chunk.length"));
                fail("HARD Failing the test due to provided InputStreamBodyGenerator, chunking incorrectly:" + response.getHeader("X-Exception"));
            } else {
                assertEquals(TestUtils.LARGE_IMAGE_BYTES, response.getResponseBodyAsBytes());
            }
        } finally {
            c.close();
        }
    }
}
