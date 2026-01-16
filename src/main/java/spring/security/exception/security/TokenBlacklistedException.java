package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class TokenBlacklistedException extends BaseException {

    public TokenBlacklistedException(String message) {
        super(ErrorCode.TOKEN_BLACKLISTED, message);
    }

    public TokenBlacklistedException(String message, Throwable cause) {
        super(ErrorCode.TOKEN_BLACKLISTED, message, cause);
    }
}
