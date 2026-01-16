package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class UserNotFoundException extends BaseException {

    public UserNotFoundException(String message) {
        super(ErrorCode.USER_NOT_FOUND, message);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(ErrorCode.USER_NOT_FOUND, message, cause);
    }
}
