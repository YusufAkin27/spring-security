package spring.security.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import spring.security.dto.ApiResponse;
import spring.security.exception.security.*;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * BaseException ve türevlerini handle eder.
     * Hata koduna göre uygun HTTP status code döner.
     * 
     * @param ex BaseException
     * @param request HTTP istek nesnesi
     * @return Hata yanıtı
     */
    @ExceptionHandler(BaseException.class)
    public ResponseEntity<ApiResponse<Object>> handleBaseException(
            BaseException ex,
            HttpServletRequest request
    ) {
        HttpStatus status = determineHttpStatus(ex);
        log.warn("Hata: {}: {} - {}", ex.getErrorCode().getCode(), ex.getMessage(), request.getRequestURI());
        
        ApiResponse<Object> response = ApiResponse.error(
                ex.getMessage(),
                ex.getErrorCode().getCode()
        );
        
        return ResponseEntity.status(status).body(response);
    }

    private HttpStatus determineHttpStatus(BaseException ex) {
        ErrorCode errorCode = ex.getErrorCode();
        
        return switch (errorCode) {
            case INVALID_TOKEN, TOKEN_EXPIRED, TOKEN_REVOKED, TOKEN_BLACKLISTED,
                 INVALID_CREDENTIALS, USER_NOT_FOUND, REFRESH_TOKEN_NOT_FOUND,
                 DEVICE_MISMATCH, IP_MISMATCH, TOKEN_REUSE_DETECTED, VERIFICATION_REQUIRED -> HttpStatus.UNAUTHORIZED;
            case USERNAME_ALREADY_EXISTS, VALIDATION_ERROR -> HttpStatus.BAD_REQUEST;
            case RATE_LIMIT_EXCEEDED -> HttpStatus.TOO_MANY_REQUESTS;
            case ACCOUNT_LOCKED -> HttpStatus.LOCKED;
            case INTERNAL_ERROR -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
    }

    /**
     * Authentication hatalarını handle eder.
     * 
     * @param ex Authentication exception
     * @param request HTTP istek nesnesi
     * @return 401 Unauthorized yanıtı
     */
    @ExceptionHandler({
            AuthenticationException.class,
            BadCredentialsException.class,
            UsernameNotFoundException.class
    })
    public ResponseEntity<ApiResponse<Object>> handleAuthenticationException(
            Exception ex,
            HttpServletRequest request
    ) {
        log.warn("Authentication hatası: {}", ex.getMessage());
        
        ApiResponse<Object> response = ApiResponse.error(
                ex.getMessage() != null ? ex.getMessage() : "Authentication failed",
                ErrorCode.INVALID_CREDENTIALS.getCode()
        );
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * Access denied hatalarını handle eder.
     * 
     * @param ex AccessDeniedException
     * @param request HTTP istek nesnesi
     * @return 403 Forbidden yanıtı
     */
    @ExceptionHandler({
            org.springframework.security.access.AccessDeniedException.class
    })
    public ResponseEntity<ApiResponse<Object>> handleAccessDeniedException(
            Exception ex,
            HttpServletRequest request
    ) {
        log.warn("Erişim reddedildi: {}", ex.getMessage());
        
        ApiResponse<Object> response = ApiResponse.error(
                "You don't have permission to access this resource",
                ErrorCode.INVALID_CREDENTIALS.getCode()
        );
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    /**
     * Validation hatalarını handle eder.
     * 
     * @param ex MethodArgumentNotValidException
     * @param request HTTP istek nesnesi
     * @return 400 Bad Request yanıtı (field hataları ile)
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationException(
            MethodArgumentNotValidException ex,
            HttpServletRequest request
    ) {
        log.warn("Validation hatası: {}", ex.getMessage());
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        
        ApiResponse<Map<String, String>> response = ApiResponse.<Map<String, String>>builder()
                .success(false)
                .message("Validation failed")
                .data(errors)
                .errorCode(ErrorCode.VALIDATION_ERROR.getCode())
                .timestamp(java.time.LocalDateTime.now())
                .traceId(java.util.UUID.randomUUID().toString())
                .build();
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    /**
     * Genel exception'ları handle eder.
     * 
     * @param ex Exception
     * @param request HTTP istek nesnesi
     * @return 500 Internal Server Error yanıtı
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleGenericException(
            Exception ex,
            HttpServletRequest request
    ) {
        if (ex instanceof BaseException) {
            return handleBaseException((BaseException) ex, request);
        }
        
        log.error("Beklenmeyen hata: ", ex);
        
        ApiResponse<Object> response = ApiResponse.error(
                "An unexpected error occurred",
                ErrorCode.INTERNAL_ERROR.getCode()
        );
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    /**
     * RuntimeException'ları handle eder.
     * 
     * @param ex RuntimeException
     * @param request HTTP istek nesnesi
     * @return 400 Bad Request yanıtı
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<Object>> handleRuntimeException(
            RuntimeException ex,
            HttpServletRequest request
    ) {
        if (ex instanceof BaseException) {
            return handleBaseException((BaseException) ex, request);
        }
        
        log.warn("Runtime hatası: {}", ex.getMessage());
        
        ApiResponse<Object> response = ApiResponse.error(
                ex.getMessage() != null ? ex.getMessage() : "An error occurred",
                ErrorCode.INTERNAL_ERROR.getCode()
        );
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
}
