package com.github.highcumontoa.springauthzguardrailsjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 令牌过期端到端测试：通过独立配置把 TTL 设为 1 秒，
 * 验证过期请求返回 401 TOKEN_EXPIRED（与篡改、撤销等原因区分）。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "guardrail.token.ttl-seconds=1",
        "guardrail.rate-limit.access-limit=100",
        "guardrail.rate-limit.window-seconds=60",
        "guardrail.rate-limit.login-failure-limit=100",
        "guardrail.rate-limit.login-window-seconds=60"
})
class TokenExpiryIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("令牌在 TTL 之后使用 -> 401 TOKEN_EXPIRED")
    void expiredTokenRejected() throws Exception {
        ResponseEntity<String> login = restTemplate.postForEntity(
                "http://localhost:" + port + "/api/auth/login",
                Map.of("username", "alice", "password", "password-alice"),
                String.class);
        String token = objectMapper.readTree(login.getBody()).get("accessToken").asText();

        // 未过期时可用
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        ResponseEntity<String> before = restTemplate.exchange(
                "http://localhost:" + port + "/api/profile/me",
                HttpMethod.GET, new HttpEntity<>(headers), String.class);
        assertThat(before.getStatusCode().value()).isEqualTo(200);

        Thread.sleep(1200);

        ResponseEntity<String> after = restTemplate.exchange(
                "http://localhost:" + port + "/api/profile/me",
                HttpMethod.GET, new HttpEntity<>(headers), String.class);
        assertThat(after.getStatusCode().value()).isEqualTo(401);
        assertThat(after.getBody()).contains("TOKEN_EXPIRED");
    }
}
