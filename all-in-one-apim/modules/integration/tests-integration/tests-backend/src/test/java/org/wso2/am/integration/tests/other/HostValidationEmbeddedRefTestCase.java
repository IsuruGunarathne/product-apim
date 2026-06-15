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
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.am.integration.test.utils.base.APIMIntegrationBaseTest;
import org.wso2.carbon.automation.engine.context.TestUserMode;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * Integration tests for SSRF protection of <em>embedded</em> OpenAPI/Swagger {@code $ref} URLs.
 *
 * <p>Runs in the same {@code <test>} as {@link HostValidationPrivateBlockTestSuite}, which applies the
 * {@code hostValidationPrivateBlock} configuration (deny mode, {@code block_private_network_access=true}).
 * Each definition is built in memory and submitted <em>inline (by file)</em> — i.e. with {@code url == null} —
 * so there is no top-level URL for the server to gate; the only outbound URL is the embedded {@code $ref}, which
 * points at a loopback (127.0.0.1) URL served by a WireMock server on a dynamic loopback port. Loopback is a
 * blocked (private) target under {@code bpna=true}, so the embedded-ref guard (the recursive remote-$ref crawl)
 * must reject validation with HTTP 400 "The provided URL is not trusted." and never fetch the referenced document.</p>
 *
 * <p>The load-bearing assertion is that the blocked {@code $ref} target receives ZERO requests — proving the guard
 * short-circuits resolution before any outbound fetch. The matrix covers OpenAPI 3.0, OpenAPI 3.1, and Swagger 2.0,
 * because the crawl runs on the raw document before the version-specific parser is chosen and so guards all three.</p>
 */
public class HostValidationEmbeddedRefTestCase extends APIMIntegrationBaseTest {

    private static final Log log = LogFactory.getLog(HostValidationEmbeddedRefTestCase.class);

    private static final String INTERNAL_PATH = "/internal.yaml";

    private WireMockServer wireMockServer;
    private int wireMockPort;

    @BeforeClass(alwaysRun = true)
    public void setEnvironment() throws Exception {
        super.init(TestUserMode.SUPER_TENANT_ADMIN);
        startWireMockServer();
    }

    @DataProvider(name = "specVersions")
    public Object[][] specVersions() {
        return new Object[][] {
                {"OpenAPI 3.0", buildOAS30WithLoopbackRef()},
                {"OpenAPI 3.1", buildOAS31WithLoopbackRef()},
                {"Swagger 2.0", buildSwagger20WithLoopbackRef()},
        };
    }

    @Test(groups = {"wso2.am"}, dataProvider = "specVersions",
            description = "SSRF [bpna=true]: an embedded $ref to a loopback URL is blocked and never fetched")
    public void testEmbeddedLoopbackRefBlocked(String label, String definition) throws Exception {
        wireMockServer.resetRequests();
        File definitionFile = tempFileWithContent(definition);
        try {
            restAPIPublisher.validateOASDefinition(definitionFile);
            Assert.fail(label + ": expected ApiException for a definition embedding an SSRF-blocked $ref");
        } catch (org.wso2.am.integration.clients.publisher.api.ApiException e) {
            Assert.assertEquals(e.getCode(), HttpStatus.SC_BAD_REQUEST,
                    label + ": expected HTTP 400 when the embedded $ref targets a blocked (loopback) host");
            Assert.assertTrue(e.getResponseBody() != null && e.getResponseBody().contains("not trusted"),
                    label + ": expected SSRF block error in the validate response body, got: " + e.getResponseBody());
        }
        // Load-bearing: the blocked embedded $ref target must never be fetched.
        wireMockServer.verify(0, getRequestedFor(urlEqualTo(INTERNAL_PATH)));
    }

    @Test(groups = {"wso2.am"},
            description = "SSRF [bpna=true]: an embedded $ref to a loopback URL inside a .zip archive is "
                    + "blocked and never fetched")
    public void testEmbeddedLoopbackRefInArchiveBlocked() throws Exception {
        wireMockServer.resetRequests();
        // The archive master (api/swagger.yaml) embeds the only outbound URL — a loopback $ref. Under bpna=true the
        // archive entry-point + the archive crawl must reject this before any fetch, proving the zip path is guarded.
        File archiveFile = buildArchiveWithLoopbackRef();
        try {
            restAPIPublisher.validateOASDefinition(archiveFile);
            Assert.fail("Archive: expected ApiException for an archive embedding an SSRF-blocked $ref");
        } catch (org.wso2.am.integration.clients.publisher.api.ApiException e) {
            Assert.assertEquals(e.getCode(), HttpStatus.SC_BAD_REQUEST,
                    "Archive: expected HTTP 400 when the embedded $ref targets a blocked (loopback) host");
            Assert.assertTrue(e.getResponseBody() != null && e.getResponseBody().contains("not trusted"),
                    "Archive: expected SSRF block error in the validate response body, got: " + e.getResponseBody());
        }
        // Load-bearing: the blocked embedded $ref target must never be fetched, even via the archive crawl.
        wireMockServer.verify(0, getRequestedFor(urlEqualTo(INTERNAL_PATH)));
    }

    private String loopbackRefUrl() {
        return "http://127.0.0.1:" + wireMockPort + INTERNAL_PATH;
    }

    private String buildOAS30WithLoopbackRef() {
        return "openapi: 3.0.1\n"
                + "info:\n  title: Embedded Ref API 30\n  version: 1.0.0\n"
                + "paths:\n  /items:\n    get:\n      responses:\n        '200':\n"
                + "          description: OK\n          content:\n            application/json:\n"
                + "              schema:\n                $ref: '" + loopbackRefUrl() + "'\n";
    }

    private String buildOAS31WithLoopbackRef() {
        return "openapi: 3.1.0\n"
                + "info:\n  title: Embedded Ref API 31\n  version: 1.0.0\n"
                + "paths:\n  /items:\n    get:\n      responses:\n        '200':\n"
                + "          description: OK\n          content:\n            application/json:\n"
                + "              schema:\n                $ref: '" + loopbackRefUrl() + "'\n";
    }

    private String buildSwagger20WithLoopbackRef() {
        return "swagger: \"2.0\"\n"
                + "info:\n  title: Embedded Ref API 20\n  version: 1.0.0\n"
                + "basePath: /v1\n"
                + "paths:\n  /items:\n    get:\n      produces:\n        - application/json\n"
                + "      responses:\n        '200':\n          description: OK\n"
                + "          schema:\n            $ref: '" + loopbackRefUrl() + "'\n";
    }

    private File tempFileWithContent(String content) throws Exception {
        File temp = File.createTempFile("embedded-ref-openapi", ".yaml");
        temp.deleteOnExit();
        try (BufferedWriter out = new BufferedWriter(new FileWriter(temp))) {
            out.write(content);
        }
        return temp;
    }

    /**
     * Builds a .zip archive whose single root folder ({@code api/}) contains the master {@code swagger.yaml} embedding
     * the loopback {@code $ref}. The {@code validate-openapi} endpoint accepts an archive (master {@code swagger.yaml}
     * or {@code swagger.json} inside one root folder); this exercises the archive entry-point + the archive crawl.
     */
    private File buildArchiveWithLoopbackRef() throws Exception {
        File temp = File.createTempFile("embedded-ref-archive", ".zip");
        temp.deleteOnExit();
        String master = buildOAS30WithLoopbackRef();
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(temp))) {
            zos.putNextEntry(new ZipEntry("api/swagger.yaml"));
            zos.write(master.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return temp;
    }

    /**
     * Starts a WireMock server on a dynamic loopback port and stubs {@code /internal.yaml} (the schema fragment the
     * embedded {@code $ref} points at). Under {@code bpna=true} this loopback target is blocked, so the stub must
     * never be fetched; it exists only so the zero-request assertion is meaningful.
     */
    private void startWireMockServer() {
        wireMockServer = new WireMockServer(options().dynamicPort());
        wireMockServer.start();
        wireMockPort = wireMockServer.port();
        String internalSchema = "type: object\nproperties:\n  id:\n    type: string\n";
        wireMockServer.stubFor(WireMock.get(urlEqualTo(INTERNAL_PATH)).willReturn(aResponse()
                .withStatus(200).withHeader("Content-Type", "application/yaml").withBody(internalSchema)));
        log.info("WireMock server for embedded-$ref SSRF tests started on port " + wireMockPort);
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
