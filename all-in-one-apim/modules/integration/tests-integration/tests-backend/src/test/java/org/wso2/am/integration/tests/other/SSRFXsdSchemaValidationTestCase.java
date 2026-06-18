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
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.am.integration.clients.publisher.api.v1.dto.APIDTO;
import org.wso2.am.integration.clients.publisher.api.v1.dto.APIInfoDTO;
import org.wso2.am.integration.clients.publisher.api.v1.dto.APIListDTO;
import org.wso2.am.integration.clients.publisher.api.v1.dto.APIOperationPoliciesDTO;
import org.wso2.am.integration.clients.publisher.api.v1.dto.APIOperationsDTO;
import org.wso2.am.integration.clients.publisher.api.v1.dto.OperationPolicyDTO;
import org.wso2.am.integration.clients.store.api.v1.dto.ApplicationDTO;
import org.wso2.am.integration.clients.store.api.v1.dto.ApplicationKeyDTO;
import org.wso2.am.integration.clients.store.api.v1.dto.ApplicationKeyGenerateRequestDTO;
import org.wso2.am.integration.test.utils.base.APIMIntegrationConstants;
import org.wso2.am.integration.test.utils.base.APIManagerLifecycleBaseTest;
import org.wso2.am.integration.test.utils.http.HTTPSClientUtils;
import org.wso2.carbon.automation.test.utils.http.client.HttpResponse;

import java.io.File;
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
 * nested {@code xsd:import}/{@code xsd:include}/external-DTD refs inside the fetched XSD) at request time.
 * Every such fetch is routed through {@code APIUtil.validateRemoteURL}, governed by the
 * {@code [apim.network_security.access_control]} policy in {@code deployment.toml}. This suite proves the
 * gate is applied to the top-level {@code xsdURL} <em>and</em> to nested imports and external DTDs, per host.
 *
 * <p><b>How the API is wired (the real mechanism):</b> the feature is exercised through a custom
 * <em>common operation policy</em> named {@code xsdValidator} (spec {@code operationPolicy/xsdValidator.json}
 * + Synapse definition {@code operationPolicy/xsdValidator.j2}). The policy exposes an {@code xsdURL}
 * parameter and places the {@code XMLSchemaValidator} mediator in the request flow. The policy is attached to
 * a POST operation; changing {@code xsdURL} per case means updating the operation policy parameter and
 * deploying a new revision.
 *
 * <p><b>Dummy backend:</b> {@code http://203.0.113.10:9090/never-reached}. {@code 203.0.113.10} is an
 * RFC&nbsp;5737 TEST-NET-3 address: a literal IP (no DNS lookup), non-private (so it passes the
 * deny+block-private config) and explicitly allow-listed in the loopback-allow config — so the API
 * create/update endpoint validation passes under both configs. The backend is never actually reached: XSD
 * validation short-circuits (400) before the request is forwarded.
 *
 * <p><b>Test topology (WireMock, in the test JVM):</b>
 * <ul>
 *   <li>{@code 127.0.0.1:8765} — serves {@code /main.xsd}, {@code /imported.xsd},
 *       {@code /main-noncrosshost.xsd}, {@code /main-with-dtd.xsd}</li>
 *   <li>{@code 127.0.0.1:8766} — serves {@code /evil.dtd}</li>
 * </ul>
 *
 * <p><b>Cases</b> (matching the manually-verified scenario matrix):
 * <ol>
 *   <li><b>A — deny/private-block:</b> {@code xsdURL=http://127.0.0.1:8765/main.xsd} → gateway returns HTTP
 *       400 and the 8765 stub records <em>zero</em> hits (top-level fetch blocked before connecting).</li>
 *   <li><b>B — allow, 127.0.0.1 allow-listed:</b> same {@code xsdURL} → the gateway fetches {@code /main.xsd}
 *       <em>and</em> its nested {@code xsd:import} {@code /imported.xsd} through the per-host gate (two hits).</li>
 *   <li><b>C — allow, nested import to a non-allow-listed host:</b> {@code main-noncrosshost.xsd}'s import
 *       points at {@code http://10.255.255.1/imported.xsd} → gateway returns HTTP 400; only the top-level
 *       {@code /main-noncrosshost.xsd} is fetched and {@code 10.255.255.1} is never contacted.</li>
 *   <li><b>D — allow, external DTD:</b> {@code main-with-dtd.xsd} (on the allowed host) declares an external
 *       DTD on {@code 127.0.0.1:8766} → the resolver routes the DTD through the gate; since the host is
 *       allow-listed both {@code /main-with-dtd.xsd} and {@code /evil.dtd} are fetched. (Were the DTD host
 *       not allow-listed it would be blocked, exactly as Case C shows for a nested import.)</li>
 * </ol>
 *
 * <p>Case A runs under the {@code ssrfXsdPrivateBlock} config (applied by
 * {@link SSRFXsdSchemaValidationPrivateBlockTestSuite}); Cases B, C and D run under
 * {@code ssrfXsdLoopbackAllow} (applied by {@link SSRFXsdSchemaValidationLoopbackAllowTestSuite}). The TestNG
 * group on each {@code @Test} selects which cases run under which config.
 */
public class SSRFXsdSchemaValidationTestCase extends APIManagerLifecycleBaseTest {

    private static final Log log = LogFactory.getLog(SSRFXsdSchemaValidationTestCase.class);

    // ---- Test API identifiers ---------------------------------------------------------------

    private static final String API_NAME = "SSRFXsdSchemaValidationAPI";
    private static final String API_CONTEXT = "/ssrf-xsd-schema-val";
    private static final String API_VERSION = "1.0.0";
    private static final String APP_NAME = "SSRFXsdSchemaValidationApp";

    /** Common operation policy that exposes {@code xsdURL} and runs the XMLSchemaValidator mediator. */
    private static final String POLICY_NAME = "xsdValidator";
    private static final String POLICY_VERSION = "v1";
    private static final String POLICY_TYPE_COMMON = "common";

    /**
     * Dummy back-end — never reached (XSD validation returns 400 first). {@code 203.0.113.10} is an
     * RFC 5737 TEST-NET-3 literal IP: no DNS lookup, non-private (passes deny+block-private), and
     * allow-listed in the loopback-allow config (passes allow mode) — so endpoint validation on
     * API create/update succeeds under both deployment configs.
     */
    private static final String DUMMY_ENDPOINT_URL = "http://203.0.113.10:9090/never-reached";

    // ---- Stub server ports ------------------------------------------------------------------

    private static final int STUB_XSD_PORT = 8765;
    private static final int STUB_DTD_PORT = 8766;
    private static final String XSD_BASE = "http://127.0.0.1:" + STUB_XSD_PORT;

    // ---- WireMock stubs ---------------------------------------------------------------------

    private WireMockServer xsdServer;
    private WireMockServer dtdServer;

    // ---- State managed across tests ---------------------------------------------------------

    private String apiId;
    private String applicationId;
    private String xsdPolicyId;
    private String accessToken;

    // ---- XSD content -----------------------------------------------------------------------

    private static final String MAIN_XSD_WITH_LOOPBACK_IMPORT =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n"
            + "            xmlns:t=\"urn:ssrf:imported\" targetNamespace=\"urn:ssrf:main\">\n"
            + "    <xsd:import namespace=\"urn:ssrf:imported\"\n"
            + "                schemaLocation=\"" + XSD_BASE + "/imported.xsd\"/>\n"
            + "    <xsd:element name=\"root\" type=\"xsd:string\"/>\n"
            + "</xsd:schema>\n";

    private static final String IMPORTED_XSD =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" targetNamespace=\"urn:ssrf:imported\">\n"
            + "    <xsd:element name=\"imported\" type=\"xsd:string\"/>\n"
            + "</xsd:schema>\n";

    /** XSD whose nested import points at a non-allow-listed host (Case C). */
    private static final String MAIN_XSD_WITH_UNALLOWED_IMPORT =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n"
            + "            xmlns:t=\"urn:ssrf:imported\" targetNamespace=\"urn:ssrf:main\">\n"
            + "    <xsd:import namespace=\"urn:ssrf:imported\"\n"
            + "                schemaLocation=\"http://10.255.255.1/imported.xsd\"/>\n"
            + "    <xsd:element name=\"root\" type=\"xsd:string\"/>\n"
            + "</xsd:schema>\n";

    /** XSD with an external DOCTYPE DTD declaration (Case D). */
    private static final String MAIN_XSD_WITH_DTD =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<!DOCTYPE xsd:schema SYSTEM \"http://127.0.0.1:" + STUB_DTD_PORT + "/evil.dtd\">\n"
            + "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" targetNamespace=\"urn:ssrf:dtd\">\n"
            + "    <xsd:element name=\"root\" type=\"xsd:string\"/>\n"
            + "</xsd:schema>\n";

    /** Minimal XML payload for gateway invocation. */
    private static final String XML_REQUEST_BODY =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>hello</root>";

    // =========================================================================================
    // Set-up / tear-down
    // =========================================================================================

    @BeforeClass(alwaysRun = true)
    public void setEnvironment() throws Exception {
        super.init();

        startStubs();

        // Import (or reuse) the xsdValidator common operation policy.
        xsdPolicyId = ensureXsdValidatorPolicy();

        // Remove any leftover API from a previous (crashed) run so create is collision-free.
        deleteExistingApiByName();

        // Create the API with a single POST /xml operation, attach the xsdValidator policy
        // (initial xsdURL = main.xsd), publish and deploy.
        apiId = createApi();
        updateApiXsdUrl(XSD_BASE + "/main.xsd");
        restAPIPublisher.changeAPILifeCycleStatusToPublish(apiId, false);

        // Application -> subscribe -> keys.
        HttpResponse appResponse = restAPIStore.createApplication(APP_NAME,
                "Application for SSRF XSD schema validation tests",
                APIMIntegrationConstants.APPLICATION_TIER.UNLIMITED,
                ApplicationDTO.TokenTypeEnum.JWT);
        applicationId = appResponse.getData();
        restAPIStore.subscribeToAPI(apiId, applicationId, APIMIntegrationConstants.APPLICATION_TIER.UNLIMITED);

        ArrayList<String> grantTypes = new ArrayList<>();
        grantTypes.add(APIMIntegrationConstants.GRANT_TYPE.CLIENT_CREDENTIAL);
        ApplicationKeyDTO keyDTO = restAPIStore.generateKeys(applicationId, "36000", null,
                ApplicationKeyGenerateRequestDTO.KeyTypeEnum.PRODUCTION, null, grantTypes);
        accessToken = keyDTO.getToken().getAccessToken();

        log.info("SSRFXsdSchemaValidationTestCase setUp complete: apiId=" + apiId
                + " xsdPolicyId=" + xsdPolicyId);
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
        } finally {
            stopStubs();
            super.cleanUp();
        }
    }

    // =========================================================================================
    // Case A — deny / private-block: top-level xsdURL to loopback is BLOCKED before fetch
    // =========================================================================================

    @Test(groups = {"wso2.am", "ssrfXsdPrivateBlock"},
            description = "SSRF XSD [deny+bpna=true]: loopback xsdURL is blocked before any fetch")
    public void testCaseA_DenyMode_LoopbackXsdBlocked() throws Exception {
        updateApiXsdUrl(XSD_BASE + "/main.xsd");
        xsdServer.resetRequests();

        HttpResponse response = invokeXmlPost();

        Assert.assertEquals(response.getResponseCode(), HttpStatus.SC_BAD_REQUEST,
                "Case A: expected HTTP 400 for xsdURL pointing at a blocked loopback host. Body: "
                        + response.getData());
        xsdServer.verify(0, getRequestedFor(urlPathEqualTo("/main.xsd")));
        log.info("Case A passed: loopback xsdURL blocked, 0 stub hits.");
    }

    // =========================================================================================
    // Case B — allow mode: loopback allow-listed, both main.xsd AND imported.xsd are fetched
    // =========================================================================================

    @Test(groups = {"wso2.am", "ssrfXsdLoopbackAllow"},
            description = "SSRF XSD [allow, 127.0.0.1 allowed]: main.xsd and nested imported.xsd are fetched")
    public void testCaseB_AllowMode_BothXsdsAreFetched() throws Exception {
        updateApiXsdUrl(XSD_BASE + "/main.xsd");
        xsdServer.resetRequests();

        HttpResponse response = invokeXmlPost();

        // Top-level XSD and its nested import must both have been fetched through the per-host gate.
        xsdServer.verify(moreThanOrExactly(1), getRequestedFor(urlPathEqualTo("/main.xsd")));
        xsdServer.verify(moreThanOrExactly(1), getRequestedFor(urlPathEqualTo("/imported.xsd")));

        // The response may be 400 because the payload does not satisfy the schema, but it must NOT be an
        // SSRF "not trusted" block when 127.0.0.1 is allow-listed.
        if (response.getResponseCode() == HttpStatus.SC_BAD_REQUEST) {
            String body = response.getData();
            Assert.assertFalse(body != null && body.contains("not trusted"),
                    "Case B: loopback xsdURL must NOT be SSRF-blocked when 127.0.0.1 is allow-listed. Body: "
                            + body);
        }
        log.info("Case B passed: main.xsd and nested imported.xsd both fetched via allow-listed 127.0.0.1.");
    }

    // =========================================================================================
    // Case C — allow mode: nested import to a NON-allow-listed host is blocked
    // =========================================================================================

    @Test(groups = {"wso2.am", "ssrfXsdLoopbackAllow"},
            description = "SSRF XSD [allow]: nested import to a non-allow-listed host is blocked")
    public void testCaseC_AllowMode_NestedImportToNonListedHostBlocked() throws Exception {
        updateApiXsdUrl(XSD_BASE + "/main-noncrosshost.xsd");
        xsdServer.resetRequests();

        HttpResponse response = invokeXmlPost();

        Assert.assertEquals(response.getResponseCode(), HttpStatus.SC_BAD_REQUEST,
                "Case C: expected HTTP 400 when a nested import target is not allow-listed. Body: "
                        + response.getData());
        // The top-level XSD (allow-listed) was fetched; the nested non-allow-listed host was never contacted.
        xsdServer.verify(moreThanOrExactly(1), getRequestedFor(urlPathEqualTo("/main-noncrosshost.xsd")));
        log.info("Case C passed: nested import to non-allow-listed 10.255.255.1 blocked (HTTP 400), "
                + "top-level fetched, 10.255.255.1 never contacted.");
    }

    // =========================================================================================
    // Case D — allow mode: external DTD is resolved through the per-host gate
    // =========================================================================================

    @Test(groups = {"wso2.am", "ssrfXsdLoopbackAllow"},
            description = "SSRF XSD [allow]: external DTD is routed through the per-host gate and fetched")
    public void testCaseD_AllowMode_ExternalDtdResolvedThroughGate() throws Exception {
        updateApiXsdUrl(XSD_BASE + "/main-with-dtd.xsd");
        xsdServer.resetRequests();
        dtdServer.resetRequests();

        invokeXmlPost();

        // The XSD and its external DTD (both on the allow-listed host) are fetched via the resolver,
        // proving external DTD refs are routed through the SSRF gate (and would be blocked if not allowed).
        xsdServer.verify(moreThanOrExactly(1), getRequestedFor(urlPathEqualTo("/main-with-dtd.xsd")));
        dtdServer.verify(moreThanOrExactly(1), getRequestedFor(urlPathEqualTo("/evil.dtd")));
        log.info("Case D passed: external DTD resolved through the per-host gate (main-with-dtd.xsd + evil.dtd "
                + "both fetched on the allow-listed host).");
    }

    // =========================================================================================
    // Case E — allow mode: an xsdURL that 302-redirects to a non-allow-listed host is refused
    // =========================================================================================

    @Test(groups = {"wso2.am", "ssrfXsdLoopbackAllow"},
            description = "SSRF XSD [allow]: an xsdURL that 302-redirects to a non-allow-listed host is refused")
    public void testCaseE_RedirectToNonAllowedHostBlocked() throws Exception {
        updateApiXsdUrl(XSD_BASE + "/redirect-edge.xsd");
        xsdServer.resetRequests();

        HttpResponse response = invokeXmlPost();

        Assert.assertEquals(response.getResponseCode(), HttpStatus.SC_BAD_REQUEST,
                "Case E: a redirect from an allow-listed edge to a non-allow-listed host must be blocked. Body: "
                        + response.getData());
        // The allow-listed edge is fetched; the redirect target (10.255.255.1, not allow-listed) is refused.
        xsdServer.verify(moreThanOrExactly(1), getRequestedFor(urlPathEqualTo("/redirect-edge.xsd")));
        String body = response.getData();
        Assert.assertTrue(body != null && (body.contains("not trusted") || body.contains("not permitted")),
                "Case E: the 400 must indicate a policy block of the redirect target (not a generic fetch error), "
                        + "confirming the redirect Location was re-validated. Body: " + body);
        log.info("Case E passed: 302 from the allow-listed edge to a non-allow-listed host blocked (HTTP 400); "
                + "the redirect target was re-validated, not followed.");
    }

    // =========================================================================================
    // Helpers — operation policy + API lifecycle
    // =========================================================================================

    /** Imports the {@code xsdValidator} common operation policy if absent; returns its id. */
    private String ensureXsdValidatorPolicy() throws Exception {
        Map<String, String> policyMap = restAPIPublisher.getAllCommonOperationPolicies();
        if (policyMap != null && policyMap.get(POLICY_NAME) != null) {
            return policyMap.get(POLICY_NAME);
        }
        String policyDir = getAMResourceLocation() + File.separator + "operationPolicy" + File.separator;
        File spec = new File(policyDir + "xsdValidator.json");
        File synapse = new File(policyDir + "xsdValidator.j2");
        Assert.assertTrue(spec.exists(), "Policy spec file missing: " + spec.getAbsolutePath());
        Assert.assertTrue(synapse.exists(), "Policy definition file missing: " + synapse.getAbsolutePath());

        HttpResponse response = restAPIPublisher.addCommonOperationPolicy(spec, synapse, null);
        Assert.assertEquals(response.getResponseCode(), HttpStatus.SC_CREATED,
                "Failed to import xsdValidator common operation policy: " + response.getData());

        Map<String, String> refreshed = restAPIPublisher.getAllCommonOperationPolicies();
        String id = refreshed != null ? refreshed.get(POLICY_NAME) : null;
        Assert.assertNotNull(id, "xsdValidator policy id not found after import");
        return id;
    }

    /** Endpoint config as a plain map so it serialises flat ({@code "endpoint_type":"http",...}). */
    private static Map<String, Object> endpointConfig() {
        Map<String, Object> production = new HashMap<>();
        production.put("url", DUMMY_ENDPOINT_URL);
        Map<String, Object> config = new HashMap<>();
        config.put("endpoint_type", "http");
        config.put("production_endpoints", production);
        config.put("sandbox_endpoints", production);
        return config;
    }

    /** Creates the API with a single POST {@code /xml} operation (no policy yet). Returns the API id. */
    private String createApi() throws Exception {
        APIDTO apidto = new APIDTO();
        apidto.setName(API_NAME);
        apidto.setContext(API_CONTEXT);
        apidto.setVersion(API_VERSION);
        apidto.setVisibility(APIDTO.VisibilityEnum.PUBLIC);
        apidto.setType(APIDTO.TypeEnum.HTTP);
        apidto.setPolicies(Collections.singletonList(APIMIntegrationConstants.API_TIER.UNLIMITED));
        apidto.setApiThrottlingPolicy(APIMIntegrationConstants.API_TIER.UNLIMITED);

        apidto.setEndpointConfig(endpointConfig());

        APIOperationsDTO operation = new APIOperationsDTO();
        operation.setVerb("POST");
        operation.setTarget("/xml");
        operation.setAuthType("Application & Application User");
        operation.setThrottlingPolicy(APIMIntegrationConstants.API_TIER.UNLIMITED);
        apidto.setOperations(Collections.singletonList(operation));

        APIDTO created = restAPIPublisher.addAPI(apidto, "v3");
        String newApiId = created.getId();
        Assert.assertNotNull(newApiId, "API creation failed — id is null");
        return newApiId;
    }

    /**
     * Sets the POST operation's request flow to the {@code xsdValidator} policy with the given
     * {@code xsdURL}, updates the API, then creates and deploys a new revision (the gateway caches the
     * deployed revision, so an xsdURL change requires a redeploy).
     */
    private void updateApiXsdUrl(String xsdUrl) throws Exception {
        // Fetch the TYPED APIDTO directly. Do NOT use restAPIPublisher.getAPI()+Gson: that serializes the
        // APIDTO to a JSON string with Gson, which mangles the Jackson endpointConfig node into
        // {"_children":...,"_nodeFactory":...}. Re-sending that on update makes the server's
        // PublisherCommonUtils.updateApi read endpointConfig.get("endpoint_type") == null -> NPE (HTTP 500).
        APIDTO apidto = restAPIPublisher.apIsApi.getAPI(apiId, null, null);
        // The typed client deserialises endpointConfig into a Jackson node; re-setting it as a plain map
        // guarantees it serialises flat ({"endpoint_type":"http",...}) on the PUT, so the server's
        // PublisherCommonUtils.updateApi finds "endpoint_type" (otherwise NPE -> HTTP 500).
        apidto.setEndpointConfig(endpointConfig());

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("xsdURL", xsdUrl);

        OperationPolicyDTO policy = new OperationPolicyDTO();
        policy.setPolicyName(POLICY_NAME);
        policy.setPolicyType(POLICY_TYPE_COMMON);
        policy.setPolicyId(xsdPolicyId);
        policy.setPolicyVersion(POLICY_VERSION);
        policy.setParameters(parameters);

        APIOperationPoliciesDTO operationPolicies = new APIOperationPoliciesDTO();
        operationPolicies.setRequest(Collections.singletonList(policy));
        operationPolicies.setResponse(new ArrayList<>());
        operationPolicies.setFault(new ArrayList<>());

        boolean attached = false;
        for (APIOperationsDTO op : apidto.getOperations()) {
            if ("POST".equalsIgnoreCase(op.getVerb())) {
                op.setOperationPolicies(operationPolicies);
                attached = true;
            }
        }
        Assert.assertTrue(attached, "No POST operation found to attach the xsdValidator policy");

        restAPIPublisher.updateAPI(apidto);
        createAPIRevisionAndDeployUsingRest(apiId, restAPIPublisher);
        waitForAPIDeployment();
    }

    /** Deletes any pre-existing API with our name (defensive — clears leftovers from a crashed run). */
    private void deleteExistingApiByName() {
        try {
            APIListDTO apiList = restAPIPublisher.getAllAPIs();
            if (apiList == null || apiList.getList() == null) {
                return;
            }
            for (APIInfoDTO info : apiList.getList()) {
                if (API_NAME.equals(info.getName())) {
                    restAPIPublisher.deleteAPI(info.getId());
                    log.info("Deleted leftover API " + info.getId() + " before set-up.");
                }
            }
        } catch (Exception e) {
            log.warn("Defensive pre-clean of existing API failed (continuing): " + e.getMessage());
        }
    }

    // =========================================================================================
    // Helpers — gateway invocation
    // =========================================================================================

    private HttpResponse invokeXmlPost() throws Exception {
        String invokeUrl = getAPIInvocationURLHttp(API_CONTEXT, API_VERSION) + "/xml";
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + accessToken);
        headers.put("Content-Type", "application/xml");
        headers.put("Accept", "application/xml");
        return HTTPSClientUtils.doPost(invokeUrl, headers, XML_REQUEST_BODY);
    }

    // =========================================================================================
    // Helpers — WireMock stubs
    // =========================================================================================

    private void startStubs() {
        xsdServer = new WireMockServer(WireMockConfiguration.options()
                .bindAddress("127.0.0.1").port(STUB_XSD_PORT));
        xsdServer.start();
        dtdServer = new WireMockServer(WireMockConfiguration.options()
                .bindAddress("127.0.0.1").port(STUB_DTD_PORT));
        dtdServer.start();

        xsdServer.stubFor(get(urlPathEqualTo("/main.xsd")).willReturn(xml(MAIN_XSD_WITH_LOOPBACK_IMPORT)));
        xsdServer.stubFor(get(urlPathEqualTo("/imported.xsd")).willReturn(xml(IMPORTED_XSD)));
        xsdServer.stubFor(get(urlPathEqualTo("/main-noncrosshost.xsd"))
                .willReturn(xml(MAIN_XSD_WITH_UNALLOWED_IMPORT)));
        xsdServer.stubFor(get(urlPathEqualTo("/main-with-dtd.xsd")).willReturn(xml(MAIN_XSD_WITH_DTD)));
        // Edge whose 302 redirect points at a NON-allow-listed host (the redirect-bypass case).
        xsdServer.stubFor(get(urlPathEqualTo("/redirect-edge.xsd")).willReturn(aResponse()
                .withStatus(302).withHeader("Location", "http://10.255.255.1/secret.xsd")));
        dtdServer.stubFor(get(urlPathEqualTo("/evil.dtd")).willReturn(aResponse()
                .withStatus(200).withHeader("Content-Type", "application/xml-dtd")
                .withBody("<!ELEMENT root (#PCDATA)>")));
    }

    private static com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder xml(String body) {
        return aResponse().withStatus(200).withHeader("Content-Type", "application/xml").withBody(body);
    }

    private void stopStubs() {
        if (xsdServer != null && xsdServer.isRunning()) {
            xsdServer.stop();
        }
        if (dtdServer != null && dtdServer.isRunning()) {
            dtdServer.stop();
        }
    }
}
