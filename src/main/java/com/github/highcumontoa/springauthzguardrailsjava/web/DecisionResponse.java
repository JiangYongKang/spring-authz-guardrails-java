package com.github.highcumontoa.springauthzguardrailsjava.web;

/**
 * 统一的判定响应体：放行或拒绝都必须给出可解释的结论。
 */
public record DecisionResponse(String decision, String reason, String detail) {

    public static DecisionResponse allowed(String detail) {
        return new DecisionResponse("ALLOWED", "NONE", detail);
    }

    public static DecisionResponse denied(String reason, String detail) {
        return new DecisionResponse("DENIED", reason, detail);
    }
}
