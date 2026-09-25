package com.github.highcumontoa.springauthzguardrailsjava.web;

public record ApiError(String reason, String message, int status) {
}
