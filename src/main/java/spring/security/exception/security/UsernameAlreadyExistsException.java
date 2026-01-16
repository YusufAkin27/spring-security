package spring.security.exception.security;

import spring.security.exception.BaseException;
import spring.security.exception.ErrorCode;

import java.util.Map;

public class UsernameAlreadyExistsException extends BaseException {

    public UsernameAlreadyExistsException(String email) {
        super(ErrorCode.USERNAME_ALREADY_EXISTS, 
              "Email already exists: " + email,
              Map.of("email", email));
    }

    public UsernameAlreadyExistsException(String email, Throwable cause) {
        super(ErrorCode.USERNAME_ALREADY_EXISTS, 
              "Email already exists: " + email,
              Map.of("email", email),
              cause);
    }
}
