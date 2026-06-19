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

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.am.integration.test.ClientAuthenticator;
import org.wso2.am.integration.test.impl.RestAPIAdminImpl;
import org.wso2.am.integration.test.impl.RestAPIPublisherImpl;
import org.wso2.am.integration.test.impl.RestAPIStoreImpl;
import org.wso2.am.integration.test.utils.base.APIMIntegrationBaseTest;
import org.wso2.am.integration.test.utils.base.APIMIntegrationConstants;
import org.wso2.am.integration.test.utils.bean.APIMURLBean;
import org.wso2.am.integration.test.utils.bean.DCRParamRequest;
import org.wso2.carbon.automation.engine.context.AutomationContext;
import org.wso2.carbon.automation.engine.context.TestUserMode;

/**
 * Warm-up for running the SSRF xsdURL suites in isolation (via {@code testng-ssrf-xsd.xml}).
 *
 * <p>The framework's {@link ClientAuthenticator} keeps the bootstrap DCR client (consumer key/secret)
 * in a <em>static</em> map that is populated <b>only</b> by an explicit
 * {@link ClientAuthenticator#makeDCRRequest} call. {@code super.init()} does NOT register a client — it
 * merely <em>reads</em> that map (via {@code RestAPIPublisherImpl -> ClientAuthenticator.getAccessToken}),
 * so if the map is empty the very first {@code init()} fails with an NPE in {@code getAccessToken}.
 *
 * <p>In the full {@code testng.xml} run, {@code APIManagerConfigurationChangeTest.configureEnvironment()}
 * performs that DCR registration before any config-restart suite. The focused {@code testng-ssrf-xsd.xml}
 * does not include it, so this warm-up takes its place: it registers the publisher/devportal/admin DCR
 * clients against the freshly-started server, then runs {@code super.init()}.
 *
 * <p>The registration is <b>retried</b> until the {@code client-registration} REST web app is actually
 * deployed — the server logs "Carbon started" a few seconds before the REST web apps finish deploying,
 * and a DCR call in that window returns non-200 (the historical cold-start flakiness). A successful
 * {@code makeDCRRequest} is therefore both the readiness signal and what warms the static cache, which
 * every later {@code super.init()} (including the post-restart suites) relies on.
 */
public class SSRFXsdScopedRunWarmupTestCase extends APIMIntegrationBaseTest {

    /** Up to ~2 min (30 x 4s) for the REST web apps to finish deploying after the server starts. */
    private static final int DCR_MAX_ATTEMPTS = 30;
    private static final long DCR_RETRY_INTERVAL_MS = 4000L;

    @BeforeClass(alwaysRun = true)
    public void setEnvironment() throws Exception {
        primeDcrClientCache();
        super.init();
    }

    /**
     * Registers the publisher/devportal/admin REST clients via DCR, retrying until the
     * client-registration endpoint is up. Populates {@link ClientAuthenticator}'s static client cache.
     */
    private void primeDcrClientCache() throws Exception {
        AutomationContext gatewayContextMgt = new AutomationContext(
                APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                APIMIntegrationConstants.AM_GATEWAY_MGT_INSTANCE, TestUserMode.SUPER_TENANT_ADMIN);
        String dcrURL = new APIMURLBean(gatewayContextMgt.getContextUrls()).getWebAppURLHttps()
                + "client-registration/v0.17/register";

        Exception lastError = null;
        for (int attempt = 1; attempt <= DCR_MAX_ATTEMPTS; attempt++) {
            try {
                ClientAuthenticator.makeDCRRequest(new DCRParamRequest(
                        RestAPIPublisherImpl.appName, RestAPIPublisherImpl.callBackURL,
                        RestAPIPublisherImpl.tokenScope, RestAPIPublisherImpl.appOwner,
                        RestAPIPublisherImpl.grantType, dcrURL,
                        RestAPIPublisherImpl.username, RestAPIPublisherImpl.password,
                        APIMIntegrationConstants.SUPER_TENANT_DOMAIN));
                ClientAuthenticator.makeDCRRequest(new DCRParamRequest(
                        RestAPIStoreImpl.appName, RestAPIStoreImpl.callBackURL,
                        RestAPIStoreImpl.tokenScope, RestAPIStoreImpl.appOwner,
                        RestAPIStoreImpl.grantType, dcrURL,
                        RestAPIStoreImpl.username, RestAPIStoreImpl.password,
                        APIMIntegrationConstants.SUPER_TENANT_DOMAIN));
                ClientAuthenticator.makeDCRRequest(new DCRParamRequest(
                        RestAPIAdminImpl.appName, RestAPIAdminImpl.callBackURL,
                        RestAPIAdminImpl.tokenScope, RestAPIAdminImpl.appOwner,
                        RestAPIAdminImpl.grantType, dcrURL,
                        RestAPIAdminImpl.username, RestAPIAdminImpl.password,
                        APIMIntegrationConstants.SUPER_TENANT_DOMAIN));
                return;   // all three registered -> static DCR cache warm
            } catch (Exception e) {   // client-registration web app not deployed yet -> wait and retry
                lastError = e;
                Thread.sleep(DCR_RETRY_INTERVAL_MS);
            }
        }
        throw new IllegalStateException(
                "DCR client-registration endpoint did not become ready for the SSRF XSD suite after "
                        + DCR_MAX_ATTEMPTS + " attempts", lastError);
    }

    @Test(groups = {"wso2.am", "ssrfXsdWarmup"},
            description = "Warm up the REST-client DCR/token bootstrap before the config-restart suites")
    public void warmUpRestClientBootstrap() {
        // primeDcrClientCache() + super.init() populated the static DCR client cache against the
        // stable, freshly-started server.
    }
}
