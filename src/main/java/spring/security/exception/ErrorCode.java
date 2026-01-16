package spring.security.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    INVALID_TOKEN("AUTH_001", "Invalid token"),
    TOKEN_EXPIRED("AUTH_002", "Token expired"),
    TOKEN_REVOKED("AUTH_003", "Token revoked"),
    TOKEN_BLACKLISTED("AUTH_004", "Token blacklisted"),
    INVALID_CREDENTIALS("AUTH_005", "Invalid credentials"),
    USER_NOT_FOUND("AUTH_006", "User not found"),
    USERNAME_ALREADY_EXISTS("AUTH_007", "Username already exists"),
    REFRESH_TOKEN_NOT_FOUND("AUTH_008", "Refresh token not found"),
    RATE_LIMIT_EXCEEDED("AUTH_009", "Rate limit exceeded"),
    ACCOUNT_LOCKED("AUTH_010", "Account locked"),
    DEVICE_MISMATCH("AUTH_011", "Device mismatch detected"),
    IP_MISMATCH("AUTH_012", "IP address mismatch detected"),
    TOKEN_REUSE_DETECTED("AUTH_013", "Token reuse detected"),
    VERIFICATION_REQUIRED("AUTH_014", "Verification required"),

    VALIDATION_ERROR("VALID_001", "Validation error"),

    INTERNAL_ERROR("SYS_001", "Internal server error");

    private final String code;
    private final String message;
}
