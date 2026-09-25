package com.github.highcumontoa.springauthzguardrailsjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "guardrail")
public class GuardrailProperties {

    private final Token token = new Token();
    private final RateLimit rateLimit = new RateLimit();

    public Token getToken() {
        return token;
    }

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public static class Token {
        private long ttlSeconds = 60L;
        private String hmacKey = "local-dev-only-hmac-key-please-change";

        public long getTtlSeconds() {
            return ttlSeconds;
        }

        public void setTtlSeconds(long ttlSeconds) {
            this.ttlSeconds = ttlSeconds;
        }

        public String getHmacKey() {
            return hmacKey;
        }

        public void setHmacKey(String hmacKey) {
            this.hmacKey = hmacKey;
        }
    }

    public static class RateLimit {
        private int accessLimit = 10;
        private long windowSeconds = 60L;
        private int loginFailureLimit = 5;
        private long loginWindowSeconds = 300L;

        public int getAccessLimit() {
            return accessLimit;
        }

        public void setAccessLimit(int accessLimit) {
            this.accessLimit = accessLimit;
        }

        public long getWindowSeconds() {
            return windowSeconds;
        }

        public void setWindowSeconds(long windowSeconds) {
            this.windowSeconds = windowSeconds;
        }

        public int getLoginFailureLimit() {
            return loginFailureLimit;
        }

        public void setLoginFailureLimit(int loginFailureLimit) {
            this.loginFailureLimit = loginFailureLimit;
        }

        public long getLoginWindowSeconds() {
            return loginWindowSeconds;
        }

        public void setLoginWindowSeconds(long loginWindowSeconds) {
            this.loginWindowSeconds = loginWindowSeconds;
        }
    }
}
