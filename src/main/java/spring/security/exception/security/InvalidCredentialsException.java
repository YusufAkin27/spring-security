package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class InvalidCredentialsException extends BaseException {

    public InvalidCredentialsException(String message) {
        super(ErrorCode.INVALID_CREDENTIALS, message);
    }

    public InvalidCredentialsException(String message, Throwable cause) {
        super(ErrorCode.INVALID_CREDENTIALS, message, cause);
    }
}
