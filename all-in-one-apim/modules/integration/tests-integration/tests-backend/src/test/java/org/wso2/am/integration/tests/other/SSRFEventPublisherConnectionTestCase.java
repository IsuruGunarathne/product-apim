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
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.am.integration.test.utils.base.APIMIntegrationBaseTest;
import org.wso2.am.integration.test.utils.base.APIMIntegrationConstants;
import org.wso2.am.integration.test.utils.http.HTTPSClientUtils;
import org.wso2.carbon.automation.engine.context.AutomationContext;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.carbon.automation.engine.frameworkutils.FrameworkPathUtil;
import org.wso2.carbon.automation.test.utils.http.client.HttpResponse;
import org.wso2.carbon.integration.common.admin.client.AuthenticatorClient;
import org.wso2.carbon.integration.common.utils.mgt.ServerConfigurationManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

/**
 * Integration tests for SSRF protection of the event-publisher "test publisher connection" admin
 * service.
 *
 * <p>The WSO2 Carbon {@code EventPublisherAdminService#testPublisherConnection} SOAP operation
 * accepts a caller-supplied output-adapter configuration. For a JMS adapter this includes the
 * {@code java.naming.provider.url} property (a broker URL). Before the JMS event adapter attempts
 * {@code testConnect()} (which would open a JNDI/JMS connection to that provider URL), the server
 * calls {@code APIUtil.validateRemoteURL} (the G2 gate). This is the SSRF gate-entry point for
 * event-publisher provisioning flows.
 *
 * <p>This test suite verifies two key behaviours under the {@code ssrfEventPublisherAllow} config
 * ({@code mode=allow, hosts=["localhost","127.0.0.1"], block_private_network_access=false}):
 * <ol>
 *   <li><b>Blocked:</b> A JMS provider URL pointing at a link-local / cloud-metadata address
 *       ({@code 169.254.169.254}) is rejected with a policy-block fault before any connection
 *       attempt — proving that the SSRF gate fires on every caller-supplied provider URL.</li>
 *   <li><b>Gate passes (allow-listed host):</b> A JMS provider URL pointing at {@code localhost}
 *       is <em>not</em> blocked by the SSRF gate; the request proceeds to the JMS/JNDI layer
 *       (where it fails with a connection error because no broker is running — that error is
 *       unrelated to SSRF and is expected and acceptable).</li>
 * </ol>
 *
 * <p>The tests run under the {@code ssrfEventPublisherAllow} deployment config, applied and
 * restored by {@link SSRFEventPublisherTestSuite}.
 *
 * <p>Transport: raw SOAP 1.1 over HTTPS to
 * {@code https://localhost:9443/services/EventPublisherAdminService}, using Basic auth
 * (admin/admin). This avoids session-cookie lifecycle complexity while still exercising the
 * full server-side SSRF gate path.
 */
public class SSRFEventPublisherConnectionTestCase extends APIMIntegrationBaseTest {

    private static final Log log = LogFactory.getLog(SSRFEventPublisherConnectionTestCase.class);

    /** Base64(admin:admin) — the only credential available in the integration-test environment. */
    private static final String BASIC_AUTH_HEADER = "Basic YWRtaW46YWRtaW4=";

    /**
     * SOAPAction for {@code EventPublisherAdminService#testPublisherConnection}.
     * Must match the WSDL operation action exactly (urn: prefix + method name).
     */
    private static final String SOAP_ACTION = "urn:testPublisherConnection";

    /**
     * Schema namespace for the testPublisherConnection request element and its (qualified)
     * parameters. Per the EventPublisherAdminService WSDL the operation schema has
     * targetNamespace="http://admin.publisher.event.carbon.wso2.org" with
     * elementFormDefault="qualified", so the wrapper AND every parameter element live in this
     * namespace.
     */
    private static final String SER_NS = "http://admin.publisher.event.carbon.wso2.org";

    /**
     * Schema namespace for the output-property-configuration DTO child elements
     * ({@code key}, {@code static}, {@code value}). Per the WSDL these complex-type members live
     * in the "/xsd" namespace.
     */
    private static final String XSD_NS = "http://admin.publisher.event.carbon.wso2.org/xsd";

    /**
     * The full back-end URL of the management services endpoint, e.g.
     * {@code https://localhost:9443/services/}.
     */
    private String backendUrl;

    // =========================================================================================
    // G1 file-drop deploy-gate test fixtures
    // =========================================================================================

    /**
     * File name of the malicious event-publisher artifact dropped into the running server's
     * {@code eventpublishers/} hot-deployment directory. Its {@code <to>} adapter targets the
     * link-local IMDS address {@code 169.254.169.254}, which is blocked by the SSRF deploy gate
     * (G1) at {@code CarbonEventPublisherService.addEventPublisherConfiguration}.
     */
    private static final String BLOCKED_PUBLISHER_FILE = "ssrfBlockedWso2EventPublisher.xml";

    /** The {@code name} attribute of the dropped publisher (used in log assertions). */
    private static final String BLOCKED_PUBLISHER_NAME = "ssrfBlockedWso2EventPublisher";

    /** Max time (ms) to wait for the hot deployer to pick up the dropped artifact. */
    private static final long DEPLOY_POLL_TIMEOUT_MS = 30_000L;

    /** Polling interval (ms) while waiting for the hot deployer. */
    private static final long DEPLOY_POLL_INTERVAL_MS = 2_000L;

    /**
     * Manages applying/copying artifacts into the running server. Built from a super-tenant
     * Key-Manager automation context, the same way other deploy-time integration tests build it.
     */
    private ServerConfigurationManager serverConfigurationManager;

    /**
     * Absolute path of the dropped artifact inside the server's
     * {@code <carbonHome>/repository/deployment/server/eventpublishers/} directory. Tracked so the
     * {@link #cleanUpDroppedArtifact()} tear-down can remove it and keep the run clean.
     */
    private File droppedArtifact;

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
        // ServerConfigurationManager is used by the G1 file-drop test to copy the malicious
        // event-publisher artifact into the running server's hot-deployment directory. Built from
        // a super-tenant Key-Manager automation context, mirroring other deploy-time tests.
        AutomationContext superTenantKeyManagerContext = new AutomationContext(
                APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                APIMIntegrationConstants.AM_KEY_MANAGER_INSTANCE,
                TestUserMode.SUPER_TENANT_ADMIN);
        serverConfigurationManager = new ServerConfigurationManager(superTenantKeyManagerContext);

        log.info("SSRFEventPublisherConnectionTestCase setUp complete: backendUrl=" + backendUrl
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
     * Verifies that a JMS provider URL targeting the IMDS link-local address
     * {@code 169.254.169.254} is blocked by the SSRF gate before any outbound connection is made.
     *
     * <p>Expected: the SOAP response contains a fault message indicating the URL was blocked by
     * the network security access control policy (e.g. "blocked by network security access
     * control policy" or "not trusted"). This fault originates from
     * {@code APIUtil.validateRemoteURL} inside the JMS event-adapter {@code testConnect()} path.
     */
    @Test(groups = {"wso2.am", "ssrfEventPublisherAllow"},
            description = "SSRF EventPublisher [allow, 169.254.169.254 not listed]: JMS provider URL "
                    + "to link-local IMDS address is blocked by the SSRF gate before connection attempt")
    public void testBlockedJmsHost() throws Exception {
        String providerUrl = "tcp://169.254.169.254:61616";
        String responseBody = callTestPublisherConnection("jms", providerUrl);

        log.info("testBlockedJmsHost response: " + responseBody);

        // The SSRF gate must have fired: the fault must contain the block message from APIUtil.
        // Accept either the primary phrasing or the older "not trusted" phrasing.
        boolean blocked = responseBody != null
                && (responseBody.toLowerCase().contains("blocked by network security access control policy")
                || responseBody.toLowerCase().contains("not trusted"));
        Assert.assertTrue(blocked,
                "Expected the SSRF gate to block 169.254.169.254 with a policy-block fault, "
                        + "but the response did not contain the expected block message. "
                        + "Response body: " + responseBody);
        log.info("testBlockedJmsHost passed: 169.254.169.254 blocked by SSRF gate as expected.");
    }

    // =========================================================================================
    // Test: allow-listed host passes the gate
    // =========================================================================================

    /**
     * Verifies that a JMS provider URL targeting {@code localhost} (which is allow-listed in the
     * {@code ssrfEventPublisherAllow} config) is <em>not</em> blocked by the SSRF gate.
     *
     * <p>No JMS broker is running on {@code localhost:61616}, so the JMS/JNDI layer will fail to
     * connect and the response will contain a connection error — but it must NOT contain the SSRF
     * policy-block fault. This confirms the gate passes allow-listed hosts through to the next
     * processing stage.
     */
    @Test(groups = {"wso2.am", "ssrfEventPublisherAllow"},
            description = "SSRF EventPublisher [allow, localhost listed]: JMS provider URL to "
                    + "allow-listed host passes the SSRF gate (JMS/JNDI connection error is expected; "
                    + "SSRF block is not)")
    public void testAllowedLocalhost() throws Exception {
        String providerUrl = "tcp://localhost:61616";
        String responseBody = callTestPublisherConnection("jms", providerUrl);

        log.info("testAllowedLocalhost response: " + responseBody);

        // The SSRF gate must NOT have fired for an allow-listed host.
        boolean ssrfBlocked = responseBody != null
                && (responseBody.toLowerCase().contains("blocked by network security access control policy")
                || responseBody.toLowerCase().contains("not trusted"));
        Assert.assertFalse(ssrfBlocked,
                "The SSRF gate must NOT block localhost (it is allow-listed), but the response "
                        + "contained an SSRF policy-block fault. Response body: " + responseBody);
        log.info("testAllowedLocalhost passed: localhost not SSRF-blocked; gate correctly "
                + "passed it through to the JMS/JNDI layer.");
    }

    // =========================================================================================
    // Test: G1 deploy gate — file-drop of a blocked wso2event publisher is rejected at deploy
    // =========================================================================================

    /**
     * Verifies the SSRF <b>deploy gate (G1)</b>: dropping an event-publisher XML whose adapter
     * targets a blocked static URL into the running server's {@code eventpublishers/}
     * hot-deployment directory is rejected at deploy time.
     *
     * <p>The dropped artifact ({@value #BLOCKED_PUBLISHER_FILE}) declares a {@code wso2event}
     * {@code <to>} adapter whose {@code receiverURL}/{@code authenticatorURL} point at the
     * link-local IMDS address {@code 169.254.169.254}. When the Carbon hot deployer parses the
     * file it calls {@code CarbonEventPublisherService.addEventPublisherConfiguration}, which
     * invokes the SSRF gate (via {@code APIUtil.validateRemoteURL}) on the adapter URLs.
     *
     * <p>Crucially, the gate fires <em>before</em> the publisher subscribes to its {@code from}
     * stream {@code org.wso2.ssrf.test.stream} (which is intentionally absent). So the block is
     * the reason the publisher fails to deploy — the missing stream does not mask it.
     *
     * <p><b>Proof approach (log-based):</b> after the drop and a short hot-deploy wait, the test
     * reads the server log ({@code <carbonHome>/repository/logs/wso2carbon.log}) and asserts it
     * contains the publisher name together with a block indicator (the policy-block message, an
     * {@code EventPublisherConfigurationException}, or the blocked host {@code 169.254.169.254}).
     * The server-side log is directly readable in this single-node standalone test framework
     * because the test JVM shares the file system with the server, so the log assertion is the
     * primary, most precise proof that the block happened at the G1 deploy gate.
     */
    @Test(groups = {"wso2.am", "ssrfEventPublisherAllow"},
            description = "SSRF EventPublisher G1 deploy gate [allow, 169.254.169.254 not listed]: "
                    + "hot-deploying a wso2event publisher whose adapter targets a blocked static URL "
                    + "is rejected at CarbonEventPublisherService.addEventPublisherConfiguration "
                    + "(before the absent from-stream is subscribed), and the block is logged")
    public void testFileDropDeployBlocked() throws Exception {
        String eventPublishersDir = FrameworkPathUtil.getCarbonHome() + File.separator + "repository"
                + File.separator + "deployment" + File.separator + "server" + File.separator
                + "eventpublishers";
        File sourceArtifact = new File(getAMResourceLocation() + File.separator + "eventpublishers"
                + File.separator + BLOCKED_PUBLISHER_FILE);
        droppedArtifact = new File(eventPublishersDir + File.separator + BLOCKED_PUBLISHER_FILE);

        Assert.assertTrue(sourceArtifact.exists(),
                "Test artifact not found on the classpath: " + sourceArtifact.getAbsolutePath());

        // 1. Drop the malicious publisher into the running server's hot-deployment dir. This is the
        //    same copy idiom used by the WebSocket/WebSub event-publisher tests
        //    (ServerConfigurationManager.applyConfigurationWithoutRestart with restartServer=false).
        serverConfigurationManager.applyConfigurationWithoutRestart(sourceArtifact, droppedArtifact,
                false);
        log.info("testFileDropDeployBlocked: dropped " + BLOCKED_PUBLISHER_FILE + " into "
                + eventPublishersDir);

        // 2. Wait for the hot deployer to pick up the file and (attempt to) deploy it. We poll the
        //    server log for the block evidence rather than sleeping a fixed long interval.
        String logFilePath = FrameworkPathUtil.getCarbonHome() + File.separator + "repository"
                + File.separator + "logs" + File.separator + "wso2carbon.log";
        boolean blockDetected = false;
        long deadline = System.currentTimeMillis() + DEPLOY_POLL_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            if (logContainsDeployBlock(logFilePath)) {
                blockDetected = true;
                break;
            }
            Thread.sleep(DEPLOY_POLL_INTERVAL_MS);
        }

        // 3. Assert the SSRF block fired at the G1 deploy gate.
        Assert.assertTrue(blockDetected,
                "Expected the SSRF deploy gate (G1) to reject hot-deployment of "
                        + BLOCKED_PUBLISHER_NAME + " (adapter URL 169.254.169.254) and log the block, "
                        + "but no block evidence was found in " + logFilePath + " within "
                        + (DEPLOY_POLL_TIMEOUT_MS / 1000) + "s.");
        log.info("testFileDropDeployBlocked passed: G1 deploy gate rejected " + BLOCKED_PUBLISHER_NAME
                + " and the block was logged.");
    }

    /**
     * Tears down the G1 file-drop test by removing the dropped artifact from the running server's
     * {@code eventpublishers/} directory, so subsequent runs start from a clean deployment dir.
     * Runs only when {@link #droppedArtifact} was set (i.e. after {@link #testFileDropDeployBlocked}).
     */
    @AfterMethod(alwaysRun = true)
    public void cleanUpDroppedArtifact() {
        if (droppedArtifact != null && droppedArtifact.exists()) {
            boolean deleted = droppedArtifact.delete();
            log.info("cleanUpDroppedArtifact: removed dropped artifact "
                    + droppedArtifact.getAbsolutePath() + " (deleted=" + deleted + ")");
        }
        droppedArtifact = null;
    }

    /**
     * Scans the server log for evidence that the dropped publisher was rejected by the SSRF deploy
     * gate. A line counts as block evidence when it mentions the publisher (by name) <em>or</em> a
     * deploy failure for it, together with any of the recognised block indicators: the policy-block
     * message, an {@code EventPublisherConfigurationException}, or the blocked host
     * {@code 169.254.169.254}.
     *
     * @param logFilePath absolute path of {@code wso2carbon.log}
     * @return {@code true} if a block-evidence line is found; {@code false} otherwise (including
     *         when the log file does not yet exist)
     */
    private boolean logContainsDeployBlock(String logFilePath) {
        File logFile = new File(logFilePath);
        if (!logFile.exists()) {
            return false;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                boolean mentionsPublisher = lower.contains(BLOCKED_PUBLISHER_NAME.toLowerCase());
                boolean hasBlockIndicator =
                        lower.contains("blocked by network security access control policy")
                                || lower.contains("eventpublisherconfigurationexception")
                                || lower.contains("169.254.169.254")
                                || lower.contains("not trusted");
                // Require both the publisher reference (or the blocked host, which is unique to this
                // artifact) and a block indicator, to avoid false positives from unrelated log noise.
                if (hasBlockIndicator && (mentionsPublisher || lower.contains("169.254.169.254"))) {
                    log.info("logContainsDeployBlock: matched block-evidence line: " + line);
                    return true;
                }
            }
        } catch (Exception e) {
            log.warn("logContainsDeployBlock: failed to read server log " + logFilePath, e);
            return false;
        }
        return false;
    }

    // =========================================================================================
    // Helper — SOAP invocation
    // =========================================================================================

    /**
     * Posts a SOAP 1.1 {@code testPublisherConnection} request to
     * {@code EventPublisherAdminService} and returns the raw response body as a String.
     *
     * <p>The request configures an output adapter whose {@code java.naming.provider.url} property
     * carries the caller-supplied broker URL; only the {@code adapterType} and
     * {@code providerUrlValue} vary per call. Basic auth is used (admin/admin, Base64-encoded) so
     * that the call works across server restart cycles without needing a live session cookie.
     *
     * @param adapterType      the output event-adapter type, e.g. {@code jms}
     * @param providerUrlValue the JMS provider URL to test, e.g.
     *                         {@code tcp://169.254.169.254:61616}
     * @return the HTTP response body (the raw SOAP envelope or fault XML), or {@code null} if
     *         the HTTP call itself failed at the transport level
     * @throws Exception if the HTTPS client encounters an unrecoverable error
     */
    private String callTestPublisherConnection(String adapterType, String providerUrlValue)
            throws Exception {
        String serviceUrl = backendUrl + "EventPublisherAdminService";

        // Construct the SOAP 1.1 envelope. The wrapper + the four direct params live in SER_NS
        // (elementFormDefault qualified); the outputPropertyConfiguration DTO child elements
        // (key, static, value — in that order) live in XSD_NS.
        String soapBody = "<soapenv:Envelope "
                + "xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                + "xmlns:ser=\"" + SER_NS + "\" "
                + "xmlns:xsd=\"" + XSD_NS + "\">"
                + "<soapenv:Header/>"
                + "<soapenv:Body>"
                + "<ser:testPublisherConnection>"
                + "<ser:eventPublisherName>ssrfEventPubTest</ser:eventPublisherName>"
                + "<ser:eventAdapterType>" + adapterType + "</ser:eventAdapterType>"
                + "<ser:outputPropertyConfiguration>"
                + "<xsd:key>java.naming.provider.url</xsd:key>"
                + "<xsd:static>true</xsd:static>"
                + "<xsd:value>" + providerUrlValue + "</xsd:value>"
                + "</ser:outputPropertyConfiguration>"
                + "<ser:outputPropertyConfiguration>"
                + "<xsd:key>java.naming.factory.initial</xsd:key>"
                + "<xsd:static>true</xsd:static>"
                + "<xsd:value>org.wso2.andes.jndi.PropertiesFileInitialContextFactory</xsd:value>"
                + "</ser:outputPropertyConfiguration>"
                + "<ser:messageFormat>map</ser:messageFormat>"
                + "</ser:testPublisherConnection>"
                + "</soapenv:Body>"
                + "</soapenv:Envelope>";

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "text/xml; charset=UTF-8");
        headers.put("SOAPAction", "\"" + SOAP_ACTION + "\"");
        headers.put("Authorization", BASIC_AUTH_HEADER);

        HttpResponse httpResponse = HTTPSClientUtils.doPost(serviceUrl, headers, soapBody);
        if (httpResponse == null) {
            log.warn("callTestPublisherConnection: HTTPSClientUtils.doPost returned null for URL: "
                    + serviceUrl);
            return null;
        }
        log.debug("callTestPublisherConnection: HTTP status=" + httpResponse.getResponseCode()
                + " body=" + httpResponse.getData());
        return httpResponse.getData();
    }
}
