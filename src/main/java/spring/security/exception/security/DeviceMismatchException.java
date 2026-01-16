package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

public class DeviceMismatchException extends BaseException {
    public DeviceMismatchException(String message) {
        super(ErrorCode.DEVICE_MISMATCH, message);
    }

    public DeviceMismatchException(String message, Throwable cause) {
        super(ErrorCode.DEVICE_MISMATCH, message, cause);
    }
}
