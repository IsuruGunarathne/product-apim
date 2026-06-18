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
import org.wso2.am.integration.test.utils.base.APIMIntegrationBaseTest;

/**
 * Warm-up for running the SSRF xsdURL suites in isolation (via {@code testng-ssrf-xsd.xml}).
 *
 * <p>The framework's {@code ClientAuthenticator} caches the bootstrap DCR client id/secret in a
 * <em>static</em> map and registers it (via the DCR endpoint) against the server while it is in its
 * stable, freshly-started state. In the full {@code testng.xml} run, hundreds of ordinary tests do
 * this before any {@link org.wso2.carbon.integration.common.utils.mgt.ServerConfigurationManager}
 * config-restart suite runs, so the cache is warm by then. When the SSRF suites are run on their own
 * the very first action would otherwise be a config-restart, leaving the DCR bootstrap to happen
 * against a just-restarted server — which intermittently fails.
 *
 * <p>This class simply runs {@code super.init()} once against the initial (pre-restart) server so the
 * static DCR cache is populated before the config-restart suites execute. It is only referenced from
 * the focused {@code testng-ssrf-xsd.xml}; the committed {@code testng.xml} does not need it because
 * the SSRF blocks there already run after the normal warm-up tests.
 */
public class SSRFXsdScopedRunWarmupTestCase extends APIMIntegrationBaseTest {

    @BeforeClass(alwaysRun = true)
    public void setEnvironment() throws Exception {
        super.init();
    }

    @Test(groups = {"wso2.am", "ssrfXsdWarmup"},
            description = "Warm up the REST-client DCR/token bootstrap before the config-restart suites")
    public void warmUpRestClientBootstrap() {
        // super.init() populated the static DCR client cache against the stable server.
    }
}
