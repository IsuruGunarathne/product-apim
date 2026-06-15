/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.am.integration.tests.other;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.am.integration.test.utils.base.APIMIntegrationBaseTest;
import org.wso2.carbon.automation.engine.context.TestUserMode;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.moreThanOrExactly;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * Positive-control integration test for SSRF protection of <em>embedded</em> OpenAPI {@code $ref} URLs.
 *
 * <p>Runs in the same {@code <test>} as {@link HostValidationEmbeddedRefAllowTestSuite}, which applies the
 * {@code hostValidationEmbeddedRefAllow} configuration (deny mode, {@code block_private_network_access=false}). Because
 * {@code bpna=false} and the loopback host is not in the deny list, a {@code $ref} to a 127.0.0.1 WireMock URL is an
 * <em>allowed</em> target — so the embedded-ref guard must let resolution proceed and the document must actually be
 * fetched.</p>
 *
 * <p>This is the inverse of {@link HostValidationEmbeddedRefTestCase}: where that test proves a blocked {@code $ref} is
 * never fetched (zero requests), this test proves an allowed {@code $ref} <em>is</em> fetched (at least one request),
 * catching a fail-closed-everywhere regression where the guard would wrongly reject (or skip) every embedded ref. The
 * load-bearing assertions are that validation does NOT fail with an SSRF "not trusted" 400 and that the WireMock stub
 * receives at least one request. Whether validation ultimately succeeds (or has unrelated schema errors) is not
 * asserted.</p>
 */
public class HostValidationEmbeddedRefAllowTestCase extends APIMIntegrationBaseTest {

    private static final Log log = LogFactory.getLog(HostValidationEmbeddedRefAllowTestCase.class);

    private static final String INTERNAL_PATH = "/internal.yaml";

    private WireMockServer wireMockServer;
    private int wireMockPort;

    @BeforeClass(alwaysRun = true)
    public void setEnvironment() throws Exception {
        super.init(TestUserMode.SUPER_TENANT_ADMIN);
        startWireMockServer();
    }

    @Test(groups = {"wso2.am"},
            description = "SSRF [bpna=false]: an embedded $ref to an allowed loopback URL is fetched, not blocked")
    public void testEmbeddedLoopbackRefAllowedIsFetched() throws Exception {
        wireMockServer.resetRequests();
        File definitionFile = tempFileWithContent(buildOAS30WithLoopbackRef());
        try {
            restAPIPublisher.validateOASDefinition(definitionFile);
            // Validation returned without an exception — acceptable. The ref host is allowed, so any unrelated
            // schema validity outcome is fine; we deliberately do not assert isValid here.
        } catch (org.wso2.am.integration.clients.publisher.api.ApiException e) {
            // The only failure we must guard against is an SSRF "not trusted" block — an allowed ref must NOT be
            // rejected. Any other failure mode is out of scope for this positive control.
            boolean ssrfBlocked = e.getCode() == HttpStatus.SC_BAD_REQUEST
                    && e.getResponseBody() != null && e.getResponseBody().contains("not trusted");
            Assert.assertFalse(ssrfBlocked,
                    "An embedded $ref to an allowed (non-blocked) loopback host must not be rejected as SSRF, got: "
                            + e.getResponseBody());
        }
        // Load-bearing: the allowed embedded $ref target must actually be fetched (proves the guard does not
        // fail-closed for every ref).
        wireMockServer.verify(moreThanOrExactly(1), getRequestedFor(urlEqualTo(INTERNAL_PATH)));
    }

    private String loopbackRefUrl() {
        return "http://127.0.0.1:" + wireMockPort + INTERNAL_PATH;
    }

    private String buildOAS30WithLoopbackRef() {
        return "openapi: 3.0.1\n"
                + "info:\n  title: Embedded Ref Allow API 30\n  version: 1.0.0\n"
                + "paths:\n  /items:\n    get:\n      responses:\n        '200':\n"
                + "          description: OK\n          content:\n            application/json:\n"
                + "              schema:\n                $ref: '" + loopbackRefUrl() + "'\n";
    }

    private File tempFileWithContent(String content) throws Exception {
        File temp = File.createTempFile("embedded-ref-allow-openapi", ".yaml");
        temp.deleteOnExit();
        try (BufferedWriter out = new BufferedWriter(new FileWriter(temp))) {
            out.write(content);
        }
        return temp;
    }

    /**
     * Starts a WireMock server on a dynamic loopback port and stubs {@code /internal.yaml} with a valid small schema.
     * Under {@code bpna=false} this loopback target is allowed, so the embedded {@code $ref} crawl must fetch it; the
     * stub serves the referenced fragment so resolution can proceed.
     */
    private void startWireMockServer() {
        wireMockServer = new WireMockServer(options().dynamicPort());
        wireMockServer.start();
        wireMockPort = wireMockServer.port();
        String internalSchema = "type: object\nproperties:\n  id:\n    type: string\n";
        wireMockServer.stubFor(WireMock.get(urlEqualTo(INTERNAL_PATH)).willReturn(aResponse()
                .withStatus(200).withHeader("Content-Type", "application/yaml").withBody(internalSchema)));
        log.info("WireMock server for embedded-$ref allow SSRF test started on port " + wireMockPort);
    }

    @AfterClass(alwaysRun = true)
    public void destroy() throws Exception {
        try {
            if (wireMockServer != null) {
                wireMockServer.stop();
            }
        } finally {
            super.cleanUp();
        }
    }
}
