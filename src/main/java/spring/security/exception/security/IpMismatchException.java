package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class IpMismatchException extends BaseException {
    public IpMismatchException(String message) {
        super(ErrorCode.IP_MISMATCH, message);
    }

    public IpMismatchException(String message, Throwable cause) {
        super(ErrorCode.IP_MISMATCH, message, cause);
    }
}
