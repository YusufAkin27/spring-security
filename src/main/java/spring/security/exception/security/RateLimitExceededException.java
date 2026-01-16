package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class RateLimitExceededException extends BaseException {
    public RateLimitExceededException(String message) {
        super(ErrorCode.RATE_LIMIT_EXCEEDED, message);
    }

    public RateLimitExceededException(String message, Throwable cause) {
        super(ErrorCode.RATE_LIMIT_EXCEEDED, message, cause);
    }
}
