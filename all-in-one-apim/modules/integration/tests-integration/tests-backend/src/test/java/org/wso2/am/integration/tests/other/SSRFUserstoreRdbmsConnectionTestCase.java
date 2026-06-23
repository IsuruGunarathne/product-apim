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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.am.integration.test.utils.base.APIMIntegrationBaseTest;
import org.wso2.am.integration.test.utils.base.APIMIntegrationConstants;
import org.wso2.am.integration.test.utils.http.HTTPSClientUtils;
import org.wso2.carbon.automation.test.utils.http.client.HttpResponse;
import org.wso2.carbon.integration.common.admin.client.AuthenticatorClient;

import java.util.HashMap;
import java.util.Map;

/**
 * Integration tests for SSRF protection of the user-store "test RDBMS connection" admin service.
 *
 * <p>The WSO2 Carbon {@code UserStoreConfigAdminService#testRDBMSConnection} SOAP operation accepts
 * a caller-supplied {@code connectionURL} (a JDBC URL string) and internally calls
 * {@code APIUtil.validateRemoteURL} before attempting the JDBC connection. This is the SSRF
 * gate-entry point for user-store provisioning flows.
 *
 * <p>This test suite verifies two key behaviours under the {@code ssrfUserstoreAllow} config
 * ({@code mode=allow, hosts=["localhost","127.0.0.1"], block_private_network_access=false}):
 * <ol>
 *   <li><b>Blocked:</b> A JDBC URL pointing at a link-local / cloud-metadata address
 *       ({@code 169.254.169.254}) is rejected with a policy-block fault before any connection
 *       attempt — proving that the SSRF gate fires on every caller-supplied JDBC URL.</li>
 *   <li><b>Gate passes (allow-listed host):</b> A JDBC URL pointing at {@code localhost} is
 *       <em>not</em> blocked by the SSRF gate; the request proceeds to the JDBC driver level
 *       (where it fails with a driver/connection error — that error is unrelated to SSRF and
 *       is expected and acceptable).</li>
 * </ol>
 *
 * <p>The tests run under the {@code ssrfUserstoreAllow} deployment config, applied and restored
 * by {@link SSRFUserstoreRdbmsTestSuite}.
 *
 * <p>Transport: raw SOAP 1.1 over HTTPS to
 * {@code https://localhost:9443/services/UserStoreConfigAdminService}, using Basic auth
 * (admin/admin). This avoids session-cookie lifecycle complexity while still exercising the
 * full server-side SSRF gate path.
 */
public class SSRFUserstoreRdbmsConnectionTestCase extends APIMIntegrationBaseTest {

    private static final Log log = LogFactory.getLog(SSRFUserstoreRdbmsConnectionTestCase.class);

    /** Base64(admin:admin) — the only credential available in the integration-test environment. */
    private static final String BASIC_AUTH_HEADER = "Basic YWRtaW46YWRtaW4=";

    /**
     * SOAPAction for {@code UserStoreConfigAdminService#testRDBMSConnection}.
     * Must match the WSDL operation action exactly (urn: prefix + method name).
     */
    private static final String SOAP_ACTION = "urn:testRDBMSConnection";

    /**
     * Schema namespace for the testRDBMSConnection request element and its (qualified) parameters.
     * Per the UserStoreConfigAdminService WSDL the operation schema has
     * targetNamespace="http://org.apache.axis2/xsd" with elementFormDefault="qualified", so the
     * wrapper AND every parameter element live in this namespace.
     */
    private static final String SER_NS = "http://org.apache.axis2/xsd";

    /**
     * The full back-end URL of the management services endpoint, e.g.
     * {@code https://localhost:9443/services/}.
     */
    private String backendUrl;

    // =========================================================================================
    // Set-up / tear-down
    // =========================================================================================

    /**
     * Initialises the test: calls {@code super.init()} to populate the inherited context fields
     * (including {@code gatewayContextMgt}), then derives the back-end services URL and obtains
     * a session cookie via {@link AuthenticatorClient} for diagnostic purposes. The actual SOAP
     * calls use Basic auth to avoid session-token lifecycle issues.
     */
    @BeforeClass(alwaysRun = true)
    public void setEnvironment() throws Exception {
        super.init();

        // gatewayContextMgt is set by APIMIntegrationBaseTest.init() and points at the Key Manager
        // management endpoint (https://localhost:9443/services/).
        backendUrl = gatewayContextMgt.getContextUrls().getBackEndUrl();
        if (!backendUrl.endsWith("/")) {
            backendUrl = backendUrl + "/";
        }

        // Obtain a session cookie via AuthenticatorClient — used for logging/diagnostics.
        // The SOAP calls themselves use Basic auth (more reliable across restart cycles).
        AuthenticatorClient authenticatorClient = new AuthenticatorClient(backendUrl);
        String sessionCookie = authenticatorClient.login(
                APIMIntegrationConstants.ADMIN_USERNAME,
                APIMIntegrationConstants.ADMIN_PASSWORD,
                APIMIntegrationConstants.LOCAL_HOST_NAME);
        log.info("SSRFUserstoreRdbmsConnectionTestCase setUp complete: backendUrl=" + backendUrl
                + " sessionCookie=" + (sessionCookie != null ? "obtained" : "null"));
    }

    @AfterClass(alwaysRun = true)
    public void cleanUp() throws Exception {
        super.cleanUp();
    }

    // =========================================================================================
    // Test: blocked host (link-local / cloud metadata)
    // =========================================================================================

    /**
     * Verifies that a JDBC URL targeting the IMDS link-local address {@code 169.254.169.254}
     * is blocked by the SSRF gate before any outbound connection is made.
     *
     * <p>Expected: the SOAP response contains a fault message indicating the URL was blocked by
     * the network security access control policy (e.g. "blocked by network security access
     * control policy" or "not trusted"). This fault originates from
     * {@code APIUtil.validateRemoteURL} inside {@code UserStoreConfigAdminService}.
     */
    @Test(groups = {"wso2.am", "ssrfUserstoreAllow"},
            description = "SSRF Userstore [allow, 169.254.169.254 not listed]: JDBC URL to link-local "
                    + "IMDS address is blocked by the SSRF gate before connection attempt")
    public void testBlockedHost() throws Exception {
        String jdbcUrl = "jdbc:mysql://169.254.169.254:3306/db";
        String responseBody = callTestRdbms(jdbcUrl);

        log.info("testBlockedHost response: " + responseBody);

        // The SSRF gate must have fired: the fault must contain the block message from APIUtil.
        // Accept either the primary phrasing or the older "not trusted" phrasing.
        boolean blocked = responseBody != null
                && (responseBody.toLowerCase().contains("blocked by network security access control policy")
                || responseBody.toLowerCase().contains("not trusted"));
        Assert.assertTrue(blocked,
                "Expected the SSRF gate to block 169.254.169.254 with a policy-block fault, "
                        + "but the response did not contain the expected block message. "
                        + "Response body: " + responseBody);
        log.info("testBlockedHost passed: 169.254.169.254 blocked by SSRF gate as expected.");
    }

    // =========================================================================================
    // Test: allow-listed host passes the gate
    // =========================================================================================

    /**
     * Verifies that a JDBC URL targeting {@code localhost} (which is allow-listed in the
     * {@code ssrfUserstoreAllow} config) is <em>not</em> blocked by the SSRF gate.
     *
     * <p>The JDBC driver will fail to connect to {@code localhost:3306/nonexistentdb} (MySQL is
     * not running), so the response will contain a driver-level connection error — but it must
     * NOT contain the SSRF policy-block fault. This confirms the gate passes allow-listed hosts
     * through to the next processing stage.
     */
    @Test(groups = {"wso2.am", "ssrfUserstoreAllow"},
            description = "SSRF Userstore [allow, localhost listed]: JDBC URL to allow-listed host "
                    + "passes the SSRF gate (driver error is expected; SSRF block is not)")
    public void testAllowedHostPassesGate() throws Exception {
        String jdbcUrl = "jdbc:mysql://localhost:3306/nonexistentdb";
        String responseBody = callTestRdbms(jdbcUrl);

        log.info("testAllowedHostPassesGate response: " + responseBody);

        // The SSRF gate must NOT have fired for an allow-listed host.
        boolean ssrfBlocked = responseBody != null
                && (responseBody.toLowerCase().contains("blocked by network security access control policy")
                || responseBody.toLowerCase().contains("not trusted"));
        Assert.assertFalse(ssrfBlocked,
                "The SSRF gate must NOT block localhost (it is allow-listed), but the response "
                        + "contained an SSRF policy-block fault. Response body: " + responseBody);
        log.info("testAllowedHostPassesGate passed: localhost not SSRF-blocked; gate correctly "
                + "passed it through to the JDBC driver layer.");
    }

    // =========================================================================================
    // Helper — SOAP invocation
    // =========================================================================================

    /**
     * Posts a SOAP 1.1 {@code testRDBMSConnection} request to
     * {@code UserStoreConfigAdminService} and returns the raw response body as a String.
     *
     * <p>The request uses a fixed MySQL driver class name and dummy credentials; only the
     * {@code connectionURL} varies per call. Basic auth is used (admin/admin, Base64-encoded)
     * so that the call works across server restart cycles without needing a live session cookie.
     *
     * @param connectionURL the JDBC connection URL to test, e.g.
     *                      {@code jdbc:mysql://169.254.169.254:3306/db}
     * @return the HTTP response body (the raw SOAP envelope or fault XML), or {@code null} if
     *         the HTTP call itself failed at the transport level
     * @throws Exception if the HTTPS client encounters an unrecoverable error
     */
    private String callTestRdbms(String connectionURL) throws Exception {
        String serviceUrl = backendUrl + "UserStoreConfigAdminService";

        // Construct the SOAP 1.1 envelope.  The namespace matches the WSDL for
        // org.wso2.carbon.user.mgt.stub.UserStoreConfigAdminService (Identity Server WS API).
        String soapBody = "<soapenv:Envelope "
                + "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                + "xmlns:ser=\"" + SER_NS + "\">"
                + "<soapenv:Header/>"
                + "<soapenv:Body>"
                + "<ser:testRDBMSConnection>"
                + "<ser:domainName>TEST</ser:domainName>"
                + "<ser:driverName>com.mysql.cj.jdbc.Driver</ser:driverName>"
                + "<ser:connectionURL>" + connectionURL + "</ser:connectionURL>"
                + "<ser:username>root</ser:username>"
                + "<ser:connectionPassword>root</ser:connectionPassword>"
                + "<ser:messageID></ser:messageID>"
                + "</ser:testRDBMSConnection>"
                + "</soapenv:Body>"
                + "</soapenv:Envelope>";

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "text/xml; charset=UTF-8");
        headers.put("SOAPAction", "\"" + SOAP_ACTION + "\"");
        headers.put("Authorization", BASIC_AUTH_HEADER);

        HttpResponse httpResponse = HTTPSClientUtils.doPost(serviceUrl, headers, soapBody);
        if (httpResponse == null) {
            log.warn("callTestRdbms: HTTPSClientUtils.doPost returned null for URL: " + serviceUrl);
            return null;
        }
        log.debug("callTestRdbms: HTTP status=" + httpResponse.getResponseCode()
                + " body=" + httpResponse.getData());
        return httpResponse.getData();
    }
}
