package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class TokenRevokedException extends BaseException {

    public TokenRevokedException(String message) {
        super(ErrorCode.TOKEN_REVOKED, message);
    }

    public TokenRevokedException(String message, Throwable cause) {
        super(ErrorCode.TOKEN_REVOKED, message, cause);
    }
}
