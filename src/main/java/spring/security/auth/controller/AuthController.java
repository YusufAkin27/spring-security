package spring.security.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.security.auth.dto.AuthResponse;
import spring.security.auth.dto.EmailVerificationRequest;
import spring.security.auth.dto.LoginRequest;
import spring.security.auth.dto.LogoutRequest;
import spring.security.auth.dto.RegisterRequest;
import spring.security.auth.dto.RefreshTokenRequest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import spring.security.dto.ApiResponse;
import spring.security.auth.service.*;
import spring.security.auth.entity.EmailVerification;
import spring.security.security.jwt.JwtService;
import spring.security.user.entity.User;
import spring.security.user.repository.UserRepository;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final DeviceFingerprintService deviceFingerprintService;
    private final IpControlService ipControlService;
    private final CookieService cookieService;
    private final EmailVerificationService emailVerificationService;
    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final SecurityAuditService securityAuditService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        String deviceId = deviceFingerprintService.generateDeviceId(httpRequest);
        String ipAddress = ipControlService.extractIpAddress(httpRequest);
        String deviceInfo = deviceFingerprintService.extractDeviceInfo(httpRequest);

        AuthResponse authResponse = authService.register(request, deviceId, ipAddress, deviceInfo);

        if (authResponse.getRefreshToken() != null) {
            cookieService.setRefreshTokenCookie(httpResponse, authResponse.getRefreshToken());
        }

        ApiResponse<AuthResponse> response = ApiResponse.success(
                "Registration successful. Please verify your email.",
                authResponse
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        String deviceId = deviceFingerprintService.generateDeviceId(httpRequest);
        String ipAddress = ipControlService.extractIpAddress(httpRequest);
        String deviceInfo = deviceFingerprintService.extractDeviceInfo(httpRequest);

        AuthResponse authResponse = authService.login(request, deviceId, ipAddress, deviceInfo);

        if (authResponse.getRefreshToken() != null) {
            cookieService.setRefreshTokenCookie(httpResponse, authResponse.getRefreshToken());
        }

        if (authResponse.getAccessToken() == null) {
            ApiResponse<AuthResponse> response = ApiResponse.<AuthResponse>builder()
                    .success(false)
                    .message("Verification code sent to your email. Please verify to continue.")
                    .data(authResponse)
                    .errorCode(spring.security.exception.ErrorCode.VERIFICATION_REQUIRED.getCode())
                    .timestamp(java.time.LocalDateTime.now())
                    .traceId(java.util.UUID.randomUUID().toString())
                    .build();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        ApiResponse<AuthResponse> response = ApiResponse.success(
                "Login successful",
                authResponse
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        String refreshToken = cookieService.getRefreshTokenFromCookie(httpRequest);
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new spring.security.exception.security.InvalidTokenException("Refresh token not found in cookie");
        }

        String deviceId = deviceFingerprintService.generateDeviceId(httpRequest);
        String ipAddress = ipControlService.extractIpAddress(httpRequest);

        AuthResponse authResponse = authService.refreshToken(refreshToken, deviceId, ipAddress);

        if (authResponse.getRefreshToken() != null) {
            cookieService.setRefreshTokenCookie(httpResponse, authResponse.getRefreshToken());
        }

        ApiResponse<AuthResponse> response = ApiResponse.success(
                "Token refreshed successfully",
                authResponse
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Object>> logout(
            Authentication authentication,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new spring.security.exception.security.InvalidTokenException("Authentication required for logout");
        }
        
        String email = authentication.getName();
        
        String accessToken = null;
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.substring(7);
        }
        
        authService.logout(null, email, accessToken);
        
        cookieService.clearRefreshTokenCookie(httpResponse);
        
        ApiResponse<Object> response = ApiResponse.success("Logout successful", null);
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse<AuthResponse>> verifyEmail(
            @Valid @RequestBody EmailVerificationRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        String deviceId = deviceFingerprintService.generateDeviceId(httpRequest);
        String ipAddress = ipControlService.extractIpAddress(httpRequest);
        String deviceInfo = deviceFingerprintService.extractDeviceInfo(httpRequest);

        spring.security.auth.entity.EmailVerification verification = emailVerificationService
                .findByCodeAndUsedFalseAndExpiresAtAfter(request.getCode(), java.time.LocalDateTime.now())
                .orElseThrow(() -> new spring.security.exception.security.InvalidTokenException("Invalid or expired verification code"));

        User user = verification.getUser();

        if (!emailVerificationService.verifyCode(request.getCode(), user, verification.getType())) {
            throw new spring.security.exception.security.InvalidTokenException("Invalid verification code");
        }

        AuthResponse authResponse;

        if ("REGISTRATION".equals(verification.getType())) {
            user.setEmailVerified(true);
            user.setEnabled(true);
            userRepository.save(user);

            UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());
            String accessToken = jwtService.generateAccessToken(userDetails);
            String accessTokenJti = jwtService.extractJti(accessToken);
            
            String refreshToken = refreshTokenService.issueRefreshToken(user, deviceInfo, deviceId, ipAddress);
            String refreshTokenJti = jwtService.extractJti(refreshToken);
            
            refreshTokenService.updateAccessTokenJti(refreshTokenJti, accessTokenJti);

            if (refreshToken != null) {
                cookieService.setRefreshTokenCookie(httpResponse, refreshToken);
            }

            authResponse = AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .username(user.getEmail())
                    .build();

            ApiResponse<AuthResponse> response = ApiResponse.success(
                    "Email verified successfully",
                    authResponse
            );

            return ResponseEntity.ok(response);
        } else if ("LOGIN_VERIFICATION".equals(verification.getType())) {
            refreshTokenService.deleteByUser(user);
            
            UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());
            String accessToken = jwtService.generateAccessToken(userDetails);
            String accessTokenJti = jwtService.extractJti(accessToken);
            
            String refreshToken = refreshTokenService.issueRefreshToken(user, deviceInfo, deviceId, ipAddress);
            String refreshTokenJti = jwtService.extractJti(refreshToken);
            
            refreshTokenService.updateAccessTokenJti(refreshTokenJti, accessTokenJti);

            if (refreshToken != null) {
                cookieService.setRefreshTokenCookie(httpResponse, refreshToken);
            }

            securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                    .user(user)
                    .username(user.getEmail())
                    .eventType("LOGIN_SUCCESS_AFTER_VERIFICATION")
                    .ipAddress(ipAddress)
                    .deviceId(deviceId)
                    .deviceInfo(deviceInfo)
                    .success(true)
                    .details("Login completed after device/IP verification, old sessions revoked")
                    .build());

            authResponse = AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .username(user.getEmail())
                    .build();

            ApiResponse<AuthResponse> response = ApiResponse.success(
                    "Login verification successful",
                    authResponse
            );

            return ResponseEntity.ok(response);
        }

        throw new spring.security.exception.security.InvalidTokenException("Invalid verification type");
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<Object>> resendVerification(
            @RequestBody(required = false) java.util.Map<String, String> requestBody,
            HttpServletRequest httpRequest
    ) {
        String deviceId = deviceFingerprintService.generateDeviceId(httpRequest);
        String ipAddress = ipControlService.extractIpAddress(httpRequest);
        String deviceInfo = deviceFingerprintService.extractDeviceInfo(httpRequest);

        String email = null;
        if (requestBody != null && requestBody.containsKey("email")) {
            email = requestBody.get("email");
        }
        
        if (email == null || email.isEmpty()) {
            email = httpRequest.getParameter("email");
        }

        if (email == null || email.isEmpty()) {
            throw new spring.security.exception.security.InvalidCredentialsException("Email is required");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new spring.security.exception.security.UserNotFoundException("User not found"));

        if (user.isEmailVerified()) {
            throw new spring.security.exception.security.InvalidCredentialsException("Email already verified");
        }

        emailVerificationService.generateAndSendVerificationCode(user, "REGISTRATION", ipAddress, deviceId);

        ApiResponse<Object> response = ApiResponse.success(
                "Verification code sent to your email",
                null
        );

        return ResponseEntity.ok(response);
    }
}
