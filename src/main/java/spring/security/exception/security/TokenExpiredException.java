package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class TokenExpiredException extends BaseException {

    public TokenExpiredException(String message) {
        super(ErrorCode.TOKEN_EXPIRED, message);
    }

    public TokenExpiredException(String message, Throwable cause) {
        super(ErrorCode.TOKEN_EXPIRED, message, cause);
    }
}
