package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class InvalidTokenException extends BaseException {

    public InvalidTokenException(String message) {
        super(ErrorCode.INVALID_TOKEN, message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(ErrorCode.INVALID_TOKEN, message, cause);
    }
}
