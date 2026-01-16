package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class TokenReuseException extends BaseException {
    public TokenReuseException(String message) {
        super(ErrorCode.TOKEN_REUSE_DETECTED, message);
    }

    public TokenReuseException(String message, Throwable cause) {
        super(ErrorCode.TOKEN_REUSE_DETECTED, message, cause);
    }
}
