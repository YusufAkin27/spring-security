package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class AccountLockedException extends BaseException {
    public AccountLockedException(String message) {
        super(ErrorCode.ACCOUNT_LOCKED, message);
    }

    public AccountLockedException(String message, Throwable cause) {
        super(ErrorCode.ACCOUNT_LOCKED, message, cause);
    }
}
