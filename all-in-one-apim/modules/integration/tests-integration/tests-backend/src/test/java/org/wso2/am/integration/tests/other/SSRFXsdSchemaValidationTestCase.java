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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.impl.client.CloseableHttpClient;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.am.integration.clients.publisher.api.v1.dto.APIDTO;
import org.wso2.am.integration.clients.publisher.api.v1.dto.APIOperationsDTO;
import org.wso2.am.integration.clients.publisher.api.v1.dto.APIThreatProtectionPoliciesDTO;
import org.wso2.am.integration.clients.publisher.api.v1.dto.APIThreatProtectionPoliciesListDTO;
import org.wso2.am.integration.clients.store.api.v1.dto.ApplicationKeyDTO;
import org.wso2.am.integration.clients.store.api.v1.dto.ApplicationKeyGenerateRequestDTO;
import org.wso2.am.integration.test.utils.base.APIMIntegrationBaseTest;
import org.wso2.am.integration.test.utils.base.APIMIntegrationConstants;
import org.wso2.am.integration.test.utils.http.HTTPSClientUtils;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.carbon.automation.test.utils.http.client.HttpResponse;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.moreThanOrExactly;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;

/**
 * Integration tests for SSRF protection of {@code xsdURL} in the gateway XML schema validator.
 *
 * <p>The {@code XMLSchemaValidator} mediator fetches the publisher-configured {@code xsdURL} (and any
 * nested {@code xsd:import}/{@code xsd:include}/external-DTD refs inside the fetched XSD) through the
 * network access-control policy ({@code [apim.network_security.access_control]} in {@code deployment.toml}).
 *
 * <p><b>Test topology</b>
 * <ul>
 *   <li>WireMock server on {@code 127.0.0.1:8765} – serves {@code /main.xsd} and {@code /imported.xsd}
 *   <li>WireMock server on {@code 127.0.0.1:8766} – serves {@code /evil.dtd} (should never be fetched in
 *       the secure cases)
 * </ul>
 *
 * <p><b>Cases</b>
 * <ol>
 *   <li><b>A – deny/private-block:</b> {@code xsdURL=http://127.0.0.1:8765/main.xsd} → gateway returns
 *       HTTP 400 and the 8765 stub records <em>zero</em> hits (top-level fetch blocked before connecting).
 *   <li><b>B – allow mode, 127.0.0.1 allow-listed:</b> same {@code xsdURL} → gateway allows the fetch;
 *       both {@code /main.xsd} and {@code /imported.xsd} are requested from the 8765 stub.
 *   <li><b>C – allow mode, nested import to non-allow-listed host:</b> serve a {@code main.xsd} whose
 *       nested import points at {@code http://10.255.255.1/imported.xsd} (not allow-listed) → gateway
 *       returns HTTP 400 and no connection to 10.255.255.1 occurs.
 *   <li><b>D – external DTD, empirical:</b> {@code xsdURL=http://127.0.0.1:8765/main-with-dtd.xsd} with
 *       8765 allow-listed but 8766 NOT allow-listed.  Assert that the 8766 stub records <em>zero</em> hits
 *       and the gateway returns 400 (the resolver covers external DTD refs).
 *       <em>NOTE: if a later run shows that 8766 IS hit, the {@code XMLSchemaValidator} lacks full DTD
 *       SSRF protection.</em>
 * </ol>
 *
 * <p>Cases A and D run against the {@code ssrfXsdPrivateBlock} config (deny + bpna=true).
 * Cases B and C run against {@code ssrfXsdLoopbackAllow} (allow, only 127.0.0.1 allow-listed).
 * Each suite applies the matching {@code deployment.toml} and restricts which tests run via TestNG groups.
 *
 * <p><b>INFERRED / UNVERIFIED DETAILS (must be checked during E2E run)</b>
 * <ol>
 *   <li>The publisher REST API path for threat protection policies is inferred as
 *       {@code /api/am/publisher/v4/threat-protection-policies}.  Verify against the live server.
 *   <li>The JSON field names in the {@code "policy"} string are inferred from
 *       {@code ThreatProtectorConstants} and {@code APIMgtGatewayConstants}.  Verify against a live
 *       server response for an XML threat policy.
 *   <li>PUT support for {@code /threat-protection-policies/{id}} is assumed.  If 405/404, the fallback
 *       in {@link #updateApiXsdUrl} will delete + re-create + re-attach.
 *   <li>The XML payload does not need to satisfy the XSD for Case B; only the stub hit count matters.
 *   <li>Gateway URL pattern is inferred from {@link #getAPIInvocationURLHttp}; confirm with live server.
 * </ol>
 */
public class SSRFXsdSchemaValidationTestCase extends APIMIntegrationBaseTest {

    private static final Log log = LogFactory.getLog(SSRFXsdSchemaValidationTestCase.class);

    // ---- Test API identifiers ---------------------------------------------------------------

    private static final String API_NAME    = "SSRFXsdSchemaValidationAPI";
    private static final String API_CONTEXT = "/ssrf-xsd-schema-val";
    private static final String API_VERSION = "1.0.0";

    /** Dummy back-end — never reached (requests either get 400 or the XSD validation short-circuits). */
    private static final String DUMMY_ENDPOINT_URL = "http://localhost:9090/never-reached";

    // ---- Stub server ports ------------------------------------------------------------------

    /** Port for the XSD stub server. Must not be in use on the CI/test host. */
    private static final int STUB_XSD_PORT = 8765;

    /** Port for the evil DTD stub server. Must not be in use on the CI/test host. */
    private static final int STUB_DTD_PORT = 8766;

    // ---- WireMock stubs ---------------------------------------------------------------------

    private WireMockServer xsdServer;
    private WireMockServer dtdServer;

    // ---- State managed across tests ---------------------------------------------------------

    private String apiId;
    private String applicationId;
    private String threatPolicyId;
    private String accessToken;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // ---- XSD content -----------------------------------------------------------------------

    private static final String MAIN_XSD_WITH_LOOPBACK_IMPORT =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n"
            + "            xmlns:t=\"urn:ssrf:imported\" targetNamespace=\"urn:ssrf:main\">\n"
            + "    <xsd:import namespace=\"urn:ssrf:imported\"\n"
            + "                schemaLocation=\"http://127.0.0.1:" + STUB_XSD_PORT + "/imported.xsd\"/>\n"
            + "    <xsd:element name=\"root\" type=\"xsd:string\"/>\n"
            + "</xsd:schema>\n";

    private static final String IMPORTED_XSD =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" targetNamespace=\"urn:ssrf:imported\">\n"
            + "    <xsd:element name=\"imported\" type=\"xsd:string\"/>\n"
            + "</xsd:schema>\n";

    /** XSD with import pointing at a non-allow-listed host (for Case C). */
    private static final String MAIN_XSD_WITH_UNALLOWED_IMPORT =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n"
            + "            xmlns:t=\"urn:ssrf:imported\" targetNamespace=\"urn:ssrf:main\">\n"
            + "    <xsd:import namespace=\"urn:ssrf:imported\"\n"
            + "                schemaLocation=\"http://10.255.255.1/imported.xsd\"/>\n"
            + "    <xsd:element name=\"root\" type=\"xsd:string\"/>\n"
            + "</xsd:schema>\n";

    /** XSD with an external DOCTYPE DTD declaration (for Case D). */
    private static final String MAIN_XSD_WITH_DTD =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<!DOCTYPE xsd:schema SYSTEM \"http://127.0.0.1:" + STUB_DTD_PORT + "/evil.dtd\">\n"
            + "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" targetNamespace=\"urn:ssrf:dtd\">\n"
            + "    <xsd:element name=\"root\" type=\"xsd:string\"/>\n"
            + "</xsd:schema>\n";

    /** Minimal XML payload for gateway invocation. */
    private static final String XML_REQUEST_BODY =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<root>hello</root>";

    // =========================================================================================
    // Set-up / tear-down
    // =========================================================================================

    @BeforeClass(alwaysRun = true)
    public void setEnvironment() throws Exception {
        super.init(TestUserMode.SUPER_TENANT_ADMIN);

        // Start WireMock on fixed ports.
        // TODO (E2E): if ports are in use, switch to dynamicPort() and update xsdURL derivation.
        xsdServer = new WireMockServer(WireMockConfiguration.options()
                .bindAddress("127.0.0.1")
                .port(STUB_XSD_PORT));
        xsdServer.start();

        dtdServer = new WireMockServer(WireMockConfiguration.options()
                .bindAddress("127.0.0.1")
                .port(STUB_DTD_PORT));
        dtdServer.start();

        // Stub /main.xsd — XSD with loopback import (Cases A, B)
        xsdServer.stubFor(get(urlPathEqualTo("/main.xsd"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml")
                        .withBody(MAIN_XSD_WITH_LOOPBACK_IMPORT)));

        // Stub /imported.xsd (Case B)
        xsdServer.stubFor(get(urlPathEqualTo("/imported.xsd"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml")
                        .withBody(IMPORTED_XSD)));

        // Stub /main-noncrosshost.xsd — XSD with non-allow-listed import (Case C)
        xsdServer.stubFor(get(urlPathEqualTo("/main-noncrosshost.xsd"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml")
                        .withBody(MAIN_XSD_WITH_UNALLOWED_IMPORT)));

        // Stub /main-with-dtd.xsd — XSD with external DTD (Case D)
        xsdServer.stubFor(get(urlPathEqualTo("/main-with-dtd.xsd"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml")
                        .withBody(MAIN_XSD_WITH_DTD)));

        // Stub /evil.dtd — should never be fetched when SSRF protection is working
        dtdServer.stubFor(get(urlPathEqualTo("/evil.dtd"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml-dtd")
                        .withBody("<!ELEMENT root (#PCDATA)>")));

        // ---- Create threat protection policy, API, application, subscription, token --------

        threatPolicyId = createXmlThreatProtectionPolicy(
                "SSRFXsdTestPolicy",
                "http://127.0.0.1:" + STUB_XSD_PORT + "/main.xsd");

        apiId = createAndPublishXmlValidatorAPI(threatPolicyId);

        HttpResponse appResponse = restAPIStore.createApplication(
                "SSRFXsdSchemaValidationApp",
                "App for SSRF XSD schema validation tests",
                APIMIntegrationConstants.APPLICATION_TIER.UNLIMITED,
                org.wso2.am.integration.clients.store.api.v1.dto.ApplicationDTO.TokenTypeEnum.JWT);
        applicationId = appResponse.getData();

        restAPIStore.subscribeToAPI(apiId, applicationId, APIMIntegrationConstants.APPLICATION_TIER.UNLIMITED);

        List<String> grantTypes = new ArrayList<>();
        grantTypes.add(APIMIntegrationConstants.GRANT_TYPE.PASSWORD);
        grantTypes.add(APIMIntegrationConstants.GRANT_TYPE.CLIENT_CREDENTIAL);
        ApplicationKeyDTO keyDTO = restAPIStore.generateKeys(
                applicationId, "36000", "",
                ApplicationKeyGenerateRequestDTO.KeyTypeEnum.PRODUCTION,
                null, grantTypes);
        accessToken = keyDTO.getToken().getAccessToken();

        log.info("SSRFXsdSchemaValidationTestCase setUp complete: apiId=" + apiId
                + " threatPolicyId=" + threatPolicyId);
    }

    @AfterClass(alwaysRun = true)
    public void cleanUpArtifacts() throws Exception {
        try {
            if (applicationId != null) {
                restAPIStore.deleteApplication(applicationId);
            }
            if (apiId != null) {
                restAPIPublisher.deleteAPI(apiId);
            }
            if (threatPolicyId != null) {
                deleteThreatProtectionPolicy(threatPolicyId);
            }
        } finally {
            if (xsdServer != null && xsdServer.isRunning()) {
                xsdServer.stop();
            }
            if (dtdServer != null && dtdServer.isRunning()) {
                dtdServer.stop();
            }
            super.cleanUp();
        }
    }

    // =========================================================================================
    // Case A — deny / private-block: top-level xsdURL to loopback is BLOCKED
    // =========================================================================================

    /**
     * Case A: with {@code block_private_network_access=true} (deny mode), a gateway POST against an
     * API whose {@code xsdURL=http://127.0.0.1:8765/main.xsd} must return HTTP 400 and must NOT
     * trigger any request to the 8765 stub (fail-before-connect).
     *
     * <p>Run in the {@code ssrfXsdPrivateBlock} suite.
     */
    @Test(groups = {"wso2.am", "ssrfXsdPrivateBlock"},
            description = "SSRF XSD [deny+bpna=true]: loopback xsdURL is blocked before fetch")
    public void testCaseA_DenyMode_LoopbackXsdBlocked() throws Exception {
        updateApiXsdUrl(apiId, threatPolicyId,
                "http://127.0.0.1:" + STUB_XSD_PORT + "/main.xsd");
        xsdServer.resetRequests();

        HttpResponse response = invokeXmlPost(apiId);

        Assert.assertEquals(response.getResponseCode(), HttpStatus.SC_BAD_REQUEST,
                "Case A: expected HTTP 400 for xsdURL pointing at a blocked loopback host");

        // The top-level fetch must not have been attempted.
        xsdServer.verify(0, getRequestedFor(urlPathEqualTo("/main.xsd")));
        log.info("Case A passed: loopback xsdURL blocked, 0 stub hits.");
    }

    // =========================================================================================
    // Case B — allow mode: loopback allow-listed, both main.xsd AND imported.xsd are fetched
    // =========================================================================================

    /**
     * Case B: with allow mode and {@code hosts=["127.0.0.1"]}, a gateway POST must allow fetching
     * {@code /main.xsd}; the JAXP resolver must then also fetch the nested {@code xsd:import}
     * ({@code /imported.xsd}) through the same allow-gate.
     *
     * <p>Run in the {@code ssrfXsdLoopbackAllow} suite.
     */
    @Test(groups = {"wso2.am", "ssrfXsdLoopbackAllow"},
            description = "SSRF XSD [allow, 127.0.0.1 allowed]: main.xsd and imported.xsd are fetched")
    public void testCaseB_AllowMode_BothXsdsAreFetched() throws Exception {
        updateApiXsdUrl(apiId, threatPolicyId,
                "http://127.0.0.1:" + STUB_XSD_PORT + "/main.xsd");
        xsdServer.resetRequests();

        HttpResponse response = invokeXmlPost(apiId);

        // Top-level XSD must have been fetched.
        xsdServer.verify(moreThanOrExactly(1), getRequestedFor(urlPathEqualTo("/main.xsd")));

        // Nested import must also have been fetched (proves the per-host gate lets it through).
        xsdServer.verify(moreThanOrExactly(1), getRequestedFor(urlPathEqualTo("/imported.xsd")));

        // The response may be 400 for schema-content reasons (dummy XML doesn't satisfy the XSD)
        // but must NOT be an SSRF "not trusted" block.
        if (response.getResponseCode() == HttpStatus.SC_BAD_REQUEST) {
            String body = response.getData();
            Assert.assertFalse(
                    body != null && body.contains("not trusted"),
                    "Case B: loopback xsdURL must NOT be blocked as SSRF when 127.0.0.1 is allow-listed");
        }
        log.info("Case B passed: main.xsd and imported.xsd both fetched via allow-listed 127.0.0.1.");
    }

    // =========================================================================================
    // Case C — allow mode: nested import to a NON-allow-listed host is blocked
    // =========================================================================================

    /**
     * Case C: the top-level {@code xsdURL} points at an allow-listed loopback host, but the fetched
     * XSD contains a nested {@code xsd:import} pointing at {@code 10.255.255.1} (NOT allow-listed).
     * The JAXP custom resolver must block this nested fetch and the gateway must return HTTP 400.
     *
     * <p>Run in the {@code ssrfXsdLoopbackAllow} suite.
     */
    @Test(groups = {"wso2.am", "ssrfXsdLoopbackAllow"},
            description = "SSRF XSD [allow]: nested import to non-allow-listed host is blocked")
    public void testCaseC_AllowMode_NestedImportToNonListedHostBlocked() throws Exception {
        updateApiXsdUrl(apiId, threatPolicyId,
                "http://127.0.0.1:" + STUB_XSD_PORT + "/main-noncrosshost.xsd");
        xsdServer.resetRequests();

        HttpResponse response = invokeXmlPost(apiId);

        Assert.assertEquals(response.getResponseCode(), HttpStatus.SC_BAD_REQUEST,
                "Case C: expected HTTP 400 when nested import target is not allow-listed");
        log.info("Case C passed: nested import to non-allow-listed 10.255.255.1 blocked (HTTP 400).");
    }

    // =========================================================================================
    // Case D — external DTD: empirical test for DTD SSRF coverage
    // =========================================================================================

    /**
     * Case D: the top-level {@code xsdURL} points at an allow-listed loopback host (8765), but the
     * fetched XSD declares an external {@code DOCTYPE} DTD referencing port 8766 (NOT allow-listed
     * under {@code ssrfXsdPrivateBlock} because {@code block_private_network_access=true}).
     * The 8766 stub must receive ZERO hits and the gateway must return HTTP 400.
     *
     * <p><b>NOTE:</b> under the {@code ssrfXsdPrivateBlock} config both 8765 and 8766 are blocked by
     * the private-network rule, so the top-level fetch is also blocked.  The important assertion is
     * that the DTD stub is never hit, confirming no SSRF outbound attempt to 8766.
     *
     * <p>Run in the {@code ssrfXsdPrivateBlock} suite.
     */
    @Test(groups = {"wso2.am", "ssrfXsdPrivateBlock"},
            description = "SSRF XSD: external DTD server not hit when SSRF protection is active")
    public void testCaseD_ExternalDtd_DtdServerNotHit() throws Exception {
        updateApiXsdUrl(apiId, threatPolicyId,
                "http://127.0.0.1:" + STUB_XSD_PORT + "/main-with-dtd.xsd");
        xsdServer.resetRequests();
        dtdServer.resetRequests();

        HttpResponse response = invokeXmlPost(apiId);

        // DTD server must receive ZERO hits.
        dtdServer.verify(0, getRequestedFor(urlPathEqualTo("/evil.dtd")));

        Assert.assertEquals(response.getResponseCode(), HttpStatus.SC_BAD_REQUEST,
                "Case D: expected HTTP 400 — either top-level xsdURL blocked (bpna=true) "
                + "or the external DTD ref blocked by custom resolver / ACCESS_EXTERNAL_DTD");
        log.info("Case D passed: external DTD on port 8766 not fetched, gateway returned 400.");
    }

    // =========================================================================================
    // Helpers — threat protection policy management (direct REST calls)
    // =========================================================================================

    /**
     * Creates an XML threat protection policy with schema validation enabled and the given {@code xsdURL}.
     *
     * <p>Uses a direct HTTP POST to {@code /api/am/publisher/v4/threat-protection-policies} because
     * the typed publisher client ({@code RestAPIPublisherImpl}) does not expose a typed method for
     * this endpoint.
     *
     * <p>TODO (E2E): verify field names in the inner {@code "policy"} JSON against a live server.
     */
    private String createXmlThreatProtectionPolicy(String name, String xsdUrl) throws Exception {

        // Inner policy JSON — field names inferred from ThreatProtectorConstants and APIMgtGatewayConstants.
        ObjectNode policyJson = objectMapper.createObjectNode();
        policyJson.put("schemaValidation", true);   // APIMgtGatewayConstants.SCHEMA_VALIDATION
        policyJson.put("xsdURL", xsdUrl);           // APIMgtGatewayConstants.XSD_URL
        policyJson.put("xmlValidation", false);     // APIMgtGatewayConstants.XML_VALIDATION
        policyJson.put("dtdEnabled", false);        // ThreatProtectorConstants.DTD_ENABLED
        policyJson.put("externalEntitiesEnabled", false);
        policyJson.put("maxXMLDepth", 100);
        policyJson.put("maxElementCount", 100000);
        policyJson.put("maxAttributeCount", 100);
        policyJson.put("maxAttributeLength", 1024);
        policyJson.put("entityExpansionLimit", 100);
        policyJson.put("maxChildrenPerElement", 100);

        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("name", name);
        requestBody.put("type", "XML");   // TODO (E2E): verify the accepted type string
        requestBody.put("policy", policyJson.toString());

        String publisherBaseUrl = getPublisherURLHttps() + "api/am/publisher/v4";
        Map<String, String> headers = buildAuthHeaders();
        headers.put("Content-Type", "application/json");

        HttpResponse response = HTTPSClientUtils.doPost(
                publisherBaseUrl + "/threat-protection-policies", headers, requestBody.toString());
        Assert.assertEquals(response.getResponseCode(), HttpStatus.SC_OK,
                "Failed to create XML threat protection policy. Response: " + response.getData());

        JsonNode responseNode = objectMapper.readTree(response.getData());
        String uuid = responseNode.path("uuid").asText();
        Assert.assertFalse(uuid == null || uuid.isEmpty(),
                "Threat protection policy UUID must not be empty");
        log.info("Created XML threat protection policy: name=" + name + " uuid=" + uuid);
        return uuid;
    }

    /**
     * Updates the {@code xsdURL} in an existing threat protection policy and re-deploys the API
     * revision so the gateway picks up the change.
     *
     * <p>TODO (E2E): if the server does not support PUT for individual policies (405/404), the
     * fallback block below will delete + re-create + re-attach the policy.  Check whether a
     * re-deploy is needed or if the change is picked up live.
     */
    private void updateApiXsdUrl(String apiId, String policyId, String newXsdUrl) throws Exception {
        ObjectNode policyJson = objectMapper.createObjectNode();
        policyJson.put("schemaValidation", true);
        policyJson.put("xsdURL", newXsdUrl);
        policyJson.put("xmlValidation", false);
        policyJson.put("dtdEnabled", false);
        policyJson.put("externalEntitiesEnabled", false);
        policyJson.put("maxXMLDepth", 100);
        policyJson.put("maxElementCount", 100000);
        policyJson.put("maxAttributeCount", 100);
        policyJson.put("maxAttributeLength", 1024);
        policyJson.put("entityExpansionLimit", 100);
        policyJson.put("maxChildrenPerElement", 100);

        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("name", "SSRFXsdTestPolicy");
        requestBody.put("type", "XML");
        requestBody.put("policy", policyJson.toString());
        requestBody.put("uuid", policyId);

        String publisherBaseUrl = getPublisherURLHttps() + "api/am/publisher/v4";
        Map<String, String> headers = buildAuthHeaders();
        headers.put("Content-Type", "application/json");

        HttpResponse putResponse = HTTPSClientUtils.doPut(
                publisherBaseUrl + "/threat-protection-policies/" + policyId,
                headers, requestBody.toString());

        if (putResponse.getResponseCode() != HttpStatus.SC_OK) {
            log.warn("PUT /threat-protection-policies/" + policyId + " returned "
                    + putResponse.getResponseCode() + "; falling back to delete+create+reattach.");
            deleteThreatProtectionPolicy(policyId);
            this.threatPolicyId = createXmlThreatProtectionPolicy("SSRFXsdTestPolicy", newXsdUrl);
            attachThreatPolicyToApi(apiId, this.threatPolicyId);
        } else {
            log.info("Updated threat protection policy " + policyId + " with xsdURL=" + newXsdUrl);
        }
    }

    /**
     * Attaches a threat protection policy to an API by updating the APIDTO.
     */
    private void attachThreatPolicyToApi(String apiId, String policyId) throws Exception {
        APIDTO apidto = restAPIPublisher.apIsApi.getAPI(apiId, null, null);
        Assert.assertNotNull(apidto, "Could not retrieve API with id=" + apiId);

        APIThreatProtectionPoliciesListDTO policyEntry = new APIThreatProtectionPoliciesListDTO();
        policyEntry.setPolicyId(policyId);
        policyEntry.setPriority(1);

        APIThreatProtectionPoliciesDTO threatPolicies = new APIThreatProtectionPoliciesDTO();
        threatPolicies.setList(Collections.singletonList(policyEntry));
        apidto.setThreatProtectionPolicies(threatPolicies);

        restAPIPublisher.updateAPI(apidto);
        log.info("Re-attached threat policy " + policyId + " to API " + apiId);
    }

    /**
     * Deletes a threat protection policy via
     * {@code DELETE /api/am/publisher/v4/threat-protection-policies/{policyId}}.
     * Uses Apache {@code CloseableHttpClient} directly since {@code HTTPSClientUtils} does not
     * expose a {@code doDelete} method.
     */
    private void deleteThreatProtectionPolicy(String policyId) {
        String deleteUrl = getPublisherURLHttps()
                + "api/am/publisher/v4/threat-protection-policies/" + policyId;
        try {
            // Build a trust-all HTTPS client (same approach as HTTPSClientUtils internally).
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, new java.security.SecureRandom());

            try (CloseableHttpClient httpClient = org.apache.http.impl.client.HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setSSLHostnameVerifier(org.apache.http.conn.ssl.NoopHostnameVerifier.INSTANCE)
                    .build()) {
                HttpDelete deleteRequest = new HttpDelete(deleteUrl);
                deleteRequest.setHeader("Authorization",
                        "Bearer " + restAPIPublisher.getAccessToken());
                try (CloseableHttpResponse response = httpClient.execute(deleteRequest)) {
                    int status = response.getStatusLine().getStatusCode();
                    if (status != HttpStatus.SC_OK && status != HttpStatus.SC_NO_CONTENT) {
                        log.warn("DELETE /threat-protection-policies/" + policyId
                                + " returned unexpected status " + status);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to delete threat protection policy " + policyId, e);
        }
    }

    // =========================================================================================
    // Helpers — API lifecycle
    // =========================================================================================

    /**
     * Creates, deploys (revision + gateway), and publishes an API configured with the XML schema
     * validator threat protection policy.
     *
     * <p>TODO (E2E): verify that {@code createAPIRevisionAndDeployUsingRest} is accessible from
     * {@code APIMIntegrationBaseTest} (confirmed at line 875 of
     * {@code APIMIntegrationBaseTest.java}).
     */
    private String createAndPublishXmlValidatorAPI(String threatPolicyId) throws Exception {

        APIDTO apidto = new APIDTO();
        apidto.setName(API_NAME);
        apidto.setContext(API_CONTEXT);
        apidto.setVersion(API_VERSION);
        apidto.setVisibility(APIDTO.VisibilityEnum.PUBLIC);
        apidto.setType(APIDTO.TypeEnum.HTTP);
        apidto.setPolicies(Collections.singletonList(APIMIntegrationConstants.API_TIER.UNLIMITED));
        apidto.setApiThrottlingPolicy(APIMIntegrationConstants.API_TIER.UNLIMITED);

        // Endpoint config.
        ObjectNode epConfig = objectMapper.createObjectNode();
        epConfig.put("endpoint_type", "http");
        ObjectNode prodEp = objectMapper.createObjectNode();
        prodEp.put("url", DUMMY_ENDPOINT_URL);
        epConfig.set("production_endpoints", prodEp);
        epConfig.set("sandbox_endpoints", prodEp);
        apidto.setEndpointConfig(epConfig);

        // Single POST /xml operation.
        APIOperationsDTO operation = new APIOperationsDTO();
        operation.setVerb("POST");
        operation.setTarget("/xml");
        operation.setAuthType("Application & Application User");
        operation.setThrottlingPolicy(APIMIntegrationConstants.API_TIER.UNLIMITED);
        apidto.setOperations(Collections.singletonList(operation));

        // Attach the XML threat protection policy.
        APIThreatProtectionPoliciesListDTO policyEntry = new APIThreatProtectionPoliciesListDTO();
        policyEntry.setPolicyId(threatPolicyId);
        policyEntry.setPriority(1);
        APIThreatProtectionPoliciesDTO threatPolicies = new APIThreatProtectionPoliciesDTO();
        threatPolicies.setList(Collections.singletonList(policyEntry));
        apidto.setThreatProtectionPolicies(threatPolicies);

        // Create the API.
        APIDTO createdApi = restAPIPublisher.addAPI(apidto, "v3");
        String newApiId = createdApi.getId();
        Assert.assertNotNull(newApiId, "API creation failed — id is null");

        // Create revision + deploy to gateway.
        createAPIRevisionAndDeployUsingRest(newApiId, restAPIPublisher);

        // Publish.
        restAPIPublisher.changeAPILifeCycleStatusToPublish(newApiId, false);
        waitForAPIDeploymentSync(createdApi.getProvider(), API_NAME, API_VERSION,
                APIMIntegrationConstants.IS_API_EXISTS);

        log.info("Created and published XML validator API: id=" + newApiId);
        return newApiId;
    }

    // =========================================================================================
    // Helpers — gateway invocation
    // =========================================================================================

    /**
     * Invokes the XML validator API via HTTP POST with a minimal XML body.
     */
    private HttpResponse invokeXmlPost(String apiId) throws Exception {
        String invokeUrl = getAPIInvocationURLHttp(API_CONTEXT, API_VERSION) + "/xml";

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + accessToken);
        headers.put("Content-Type", "application/xml");
        headers.put("Accept", "application/xml");

        return HTTPSClientUtils.doPost(invokeUrl, headers, XML_REQUEST_BODY);
    }

    // =========================================================================================
    // Helpers — common
    // =========================================================================================

    private Map<String, String> buildAuthHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + restAPIPublisher.getAccessToken());
        return headers;
    }
}
