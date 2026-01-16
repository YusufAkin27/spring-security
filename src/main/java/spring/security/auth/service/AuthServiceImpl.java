package spring.security.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.security.auth.dto.AuthResponse;
import spring.security.auth.dto.LoginRequest;
import spring.security.auth.dto.LogoutRequest;
import spring.security.auth.dto.RegisterRequest;
import spring.security.auth.entity.RefreshToken;
import spring.security.auth.entity.TokenBlacklist;
import spring.security.auth.repository.TokenBlacklistRepository;
import spring.security.exception.security.InvalidCredentialsException;
import spring.security.exception.security.InvalidTokenException;
import spring.security.exception.security.UsernameAlreadyExistsException;
import spring.security.security.jwt.JwtService;
import spring.security.user.entity.Role;
import spring.security.user.entity.User;
import spring.security.user.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistRepository tokenBlacklistRepository;
    private final RateLimitService rateLimitService;
    private final BruteForceProtectionService bruteForceProtectionService;
    private final SecurityAuditService securityAuditService;
    private final EmailVerificationService emailVerificationService;
    private final IpControlService ipControlService;

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request, String deviceId, String ipAddress, String deviceInfo) {
        java.util.Optional<User> existingUserOpt = userRepository.findByEmail(request.getEmail());
        
        if (existingUserOpt.isPresent()) {
            User existingUser = existingUserOpt.get();
            
            if (existingUser.isEmailVerified()) {
                securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                        .user(existingUser)
                        .username(request.getEmail())
                        .eventType("REGISTER_FAILED")
                        .ipAddress(ipAddress)
                        .deviceId(deviceId)
                        .deviceInfo(deviceInfo)
                        .success(false)
                        .failureReason("Email already exists and verified")
                        .build());
                throw new UsernameAlreadyExistsException(request.getEmail());
            }
            
            existingUser.setPassword(passwordEncoder.encode(request.getPassword()));
            User savedUser = userRepository.save(existingUser);
            
            emailVerificationService.generateAndSendVerificationCode(savedUser, "REGISTRATION", ipAddress, deviceId);
            
            securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                    .user(savedUser)
                    .username(savedUser.getEmail())
                    .eventType("REGISTER_VERIFICATION_RESENT")
                    .ipAddress(ipAddress)
                    .deviceId(deviceId)
                    .deviceInfo(deviceInfo)
                    .success(true)
                    .details("Verification code resent for unverified email")
                    .build());
            
            log.info("Verification code resent for unverified user: {}", savedUser.getEmail());
            
            return AuthResponse.builder()
                    .accessToken(null)
                    .refreshToken(null)
                    .tokenType("Bearer")
                    .username(savedUser.getEmail())
                    .build();
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.getRoles().add(Role.USER);
        user.setEnabled(false);
        user.setEmailVerified(false);

        User savedUser = userRepository.save(user);
        log.info("User registered: {}", savedUser.getEmail());

        emailVerificationService.generateAndSendVerificationCode(savedUser, "REGISTRATION", ipAddress, deviceId);

        securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                .user(savedUser)
                .username(savedUser.getEmail())
                .eventType("REGISTER_SUCCESS")
                .ipAddress(ipAddress)
                .deviceId(deviceId)
                .deviceInfo(deviceInfo)
                .success(true)
                .build());

        return AuthResponse.builder()
                .accessToken(null)
                .refreshToken(null)
                .tokenType("Bearer")
                .username(savedUser.getEmail())
                .build();
    }

    @Override
    @Transactional
    public AuthResponse login(LoginRequest request, String deviceId, String ipAddress, String deviceInfo) {
        if (rateLimitService.isRateLimitExceeded(ipAddress, "login")) {
            securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                    .username(request.getEmail())
                    .eventType("RATE_LIMIT_EXCEEDED")
                    .ipAddress(ipAddress)
                    .deviceId(deviceId)
                    .deviceInfo(deviceInfo)
                    .success(false)
                    .failureReason("Rate limit exceeded")
                    .build());
            throw new spring.security.exception.security.RateLimitExceededException(
                    "Too many login attempts. Please try again later.");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new spring.security.exception.security.UserNotFoundException(
                        "User not found: " + request.getEmail()));

        if (bruteForceProtectionService.isAccountLocked(user.getEmail())) {
            securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                    .user(user)
                    .username(user.getEmail())
                    .eventType("LOGIN_FAILED")
                    .ipAddress(ipAddress)
                    .deviceId(deviceId)
                    .deviceInfo(deviceInfo)
                    .success(false)
                    .failureReason("Account locked")
                    .build());
            throw new spring.security.exception.security.AccountLockedException(
                    "Account is locked due to too many failed login attempts. Please contact administrator.");
        }

        if (!user.isEmailVerified()) {
            emailVerificationService.generateAndSendVerificationCode(user, "REGISTRATION", ipAddress, deviceId);
            
            securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                    .user(user)
                    .username(user.getEmail())
                    .eventType("LOGIN_VERIFICATION_REQUIRED")
                    .ipAddress(ipAddress)
                    .deviceId(deviceId)
                    .deviceInfo(deviceInfo)
                    .success(false)
                    .failureReason("Email not verified - verification code sent")
                    .build());
            
            throw new spring.security.exception.security.InvalidCredentialsException("Email not verified. Verification code sent to your email. Please verify to continue.");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
        } catch (org.springframework.security.core.AuthenticationException e) {
            rateLimitService.recordAttempt(ipAddress, "login");
            bruteForceProtectionService.recordFailedAttempt(user.getEmail());
            
            securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                    .user(user)
                    .username(user.getEmail())
                    .eventType("LOGIN_FAILED")
                    .ipAddress(ipAddress)
                    .deviceId(deviceId)
                    .deviceInfo(deviceInfo)
                    .success(false)
                    .failureReason("Invalid credentials")
                    .build());
            
            throw new InvalidCredentialsException("Invalid email or password");
        }

        boolean needsVerification = false;
        String oldDeviceId = null;
        String oldIpAddress = null;

        Optional<RefreshToken> existingToken = refreshTokenService.findByUser(user);
        if (existingToken.isPresent()) {
            spring.security.auth.entity.RefreshToken token = existingToken.get();
            oldDeviceId = token.getDeviceId();
            oldIpAddress = token.getIpAddress();

            boolean deviceChanged = !deviceId.equals(oldDeviceId);
            
            if (deviceChanged) {
                needsVerification = true;
                log.info("Device change detected for user: {}, oldDevice: {}, newDevice: {}", 
                        user.getEmail(), oldDeviceId, deviceId);
            } else {
                boolean ipChanged = !ipControlService.validateIpChange(oldIpAddress, ipAddress);
                if (ipChanged && !"Unknown".equals(oldIpAddress) && !"Unknown".equals(ipAddress)) {
                    needsVerification = true;
                    log.info("IP change detected for user: {}, oldIP: {}, newIP: {}", 
                            user.getEmail(), oldIpAddress, ipAddress);
                }
            }
        }

        if (needsVerification) {
            java.util.Optional<spring.security.auth.entity.RefreshToken> existingTokenOpt = refreshTokenService.findByUser(user);
            if (existingTokenOpt.isPresent()) {
                RefreshToken refreshToken = existingTokenOpt.get();
                
                if (refreshToken.getAccessTokenJti() != null && !refreshToken.getAccessTokenJti().isEmpty()) {
                    try {
                        java.util.Date accessTokenExpiration = new java.util.Date(
                                System.currentTimeMillis() + jwtService.getAccessTokenExpiration());
                        addToBlacklist(refreshToken.getAccessTokenJti(), accessTokenExpiration, "DEVICE_IP_CHANGE");
                        log.info("Old access token blacklisted due to device/IP change: {}", refreshToken.getAccessTokenJti());
                    } catch (Exception e) {
                        log.warn("Failed to blacklist old access token: {}", e.getMessage());
                    }
                }
                
                refreshTokenService.deleteByUser(user);
                log.info("Old refresh token deleted due to device/IP change for user: {}, old jti: {}", 
                        user.getEmail(), refreshToken.getJti());
            }
            
            emailVerificationService.generateAndSendVerificationCode(user, "LOGIN_VERIFICATION", ipAddress, deviceId);
            
            securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                    .user(user)
                    .username(user.getEmail())
                    .eventType("LOGIN_VERIFICATION_REQUIRED")
                    .ipAddress(ipAddress)
                    .deviceId(deviceId)
                    .deviceInfo(deviceInfo)
                    .success(false)
                    .failureReason("Device or IP change detected - old tokens revoked")
                    .details("Old device: " + oldDeviceId + ", New device: " + deviceId + ", Old IP: " + oldIpAddress + ", New IP: " + ipAddress)
                    .build());
            
            return AuthResponse.builder()
                    .accessToken(null)
                    .refreshToken(null)
                    .tokenType("Bearer")
                    .username(user.getEmail())
                    .build();
        }

        rateLimitService.clearAttempts(ipAddress, "login");
        bruteForceProtectionService.recordSuccessfulLogin(user.getEmail());

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());
        
        String accessToken = jwtService.generateAccessToken(userDetails);
        String accessTokenJti = jwtService.extractJti(accessToken);
        
        String refreshToken = refreshTokenService.issueRefreshToken(user, deviceInfo, deviceId, ipAddress);
        String refreshTokenJti = jwtService.extractJti(refreshToken);
        
        refreshTokenService.updateAccessTokenJti(refreshTokenJti, accessTokenJti);

        securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                .user(user)
                .username(user.getEmail())
                .eventType("LOGIN_SUCCESS")
                .ipAddress(ipAddress)
                .deviceId(deviceId)
                .deviceInfo(deviceInfo)
                .success(true)
                .build());

        log.info("User logged in: {}", user.getEmail());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .username(user.getEmail())
                .build();
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(String refreshToken, String deviceId, String ipAddress) {
        if (rateLimitService.isRateLimitExceeded(ipAddress, "refresh")) {
            securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                    .eventType("RATE_LIMIT_EXCEEDED")
                    .ipAddress(ipAddress)
                    .deviceId(deviceId)
                    .success(false)
                    .failureReason("Rate limit exceeded for refresh endpoint")
                    .build());
            throw new spring.security.exception.security.RateLimitExceededException(
                    "Too many refresh attempts. Please try again later.");
        }

        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        spring.security.auth.entity.RefreshToken oldRefreshTokenEntity;
        try {
            oldRefreshTokenEntity = refreshTokenService.validateRefreshToken(refreshToken, deviceId, ipAddress);
        } catch (spring.security.exception.security.DeviceMismatchException | 
                 spring.security.exception.security.IpMismatchException e) {
            rateLimitService.recordAttempt(ipAddress, "refresh");
            throw e;
        }
        
        User user = oldRefreshTokenEntity.getUser();
        String email = user.getEmail();

        if (oldRefreshTokenEntity.getAccessTokenJti() != null && !oldRefreshTokenEntity.getAccessTokenJti().isEmpty()) {
            try {
                java.util.Date oldAccessTokenExpiration = new java.util.Date(
                        System.currentTimeMillis() + jwtService.getAccessTokenExpiration());
                addToBlacklist(oldRefreshTokenEntity.getAccessTokenJti(), oldAccessTokenExpiration, "TOKEN_REFRESH");
                log.debug("Old access token blacklisted: {}", oldRefreshTokenEntity.getAccessTokenJti());
            } catch (Exception e) {
                log.warn("Failed to blacklist old access token: {}", e.getMessage());
            }
        }

        refreshTokenService.revokeRefreshToken(oldRefreshTokenEntity.getJti());

        String newRefreshToken = refreshTokenService.issueRefreshToken(
                user, 
                oldRefreshTokenEntity.getDeviceInfo(), 
                deviceId, 
                ipAddress
        );
        String newRefreshTokenJti = jwtService.extractJti(newRefreshToken);

        UserDetails userDetails = userDetailsService.loadUserByUsername(email);

        String newAccessToken = jwtService.generateAccessToken(userDetails);
        String newAccessTokenJti = jwtService.extractJti(newAccessToken);
        
        refreshTokenService.updateAccessTokenJti(newRefreshTokenJti, newAccessTokenJti);
        
        rateLimitService.clearAttempts(ipAddress, "refresh");

        securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                .user(user)
                .username(email)
                .eventType("TOKEN_REFRESH")
                .ipAddress(ipAddress)
                .deviceId(deviceId)
                .deviceInfo(oldRefreshTokenEntity.getDeviceInfo())
                .success(true)
                .details("Token rotated: old jti=" + oldRefreshTokenEntity.getJti() + ", new jti=" + newRefreshTokenJti)
                .build());
        
        log.info("Token refreshed and rotated for user: {}, old jti: {}, new jti: {}", 
                email, oldRefreshTokenEntity.getJti(), newRefreshTokenJti);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .username(email)
                .build();
    }

    @Override
    @Transactional
    public void logout(LogoutRequest request, String email, String accessToken) {
        if (email == null || email.isEmpty()) {
            throw new InvalidTokenException("Authentication required for logout");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new spring.security.exception.security.UserNotFoundException(
                        "User not found: " + email));

        spring.security.auth.entity.RefreshToken refreshTokenEntity = 
                refreshTokenService.findByUser(user)
                        .orElse(null);

        if (refreshTokenEntity != null && refreshTokenEntity.getAccessTokenJti() != null 
                && !refreshTokenEntity.getAccessTokenJti().isEmpty()) {
            try {
                java.util.Date accessTokenExpiration = new java.util.Date(
                        System.currentTimeMillis() + jwtService.getAccessTokenExpiration());
                addToBlacklist(refreshTokenEntity.getAccessTokenJti(), accessTokenExpiration, "LOGOUT");
                log.debug("Access token blacklisted: {}", refreshTokenEntity.getAccessTokenJti());
            } catch (Exception e) {
                log.warn("Failed to blacklist access token: {}", e.getMessage());
            }
        }

        if (accessToken != null && !accessToken.isEmpty()) {
            try {
                String accessTokenJti = jwtService.extractJti(accessToken);
                java.util.Date accessTokenExpiration = jwtService.extractExpiration(accessToken);
                addToBlacklist(accessTokenJti, accessTokenExpiration, "LOGOUT");
                log.debug("Request access token blacklisted: {}", accessTokenJti);
            } catch (Exception e) {
                log.warn("Failed to blacklist request access token: {}", e.getMessage());
            }
        }

        if (refreshTokenEntity != null) {
            refreshTokenService.deleteByUser(user);
            log.info("Logout completed for user: {}, refreshToken jti: {}", 
                    email, refreshTokenEntity.getJti());
        } else {
            log.warn("No refresh token found for user: {}", email);
        }

        securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                .user(user)
                .username(email)
                .eventType("LOGOUT")
                .ipAddress(accessToken != null ? "extracted from token" : "unknown")
                .success(true)
                .build());
    }

    private void addToBlacklist(String jti, java.util.Date expiresAt, String reason) {
        TokenBlacklist blacklistEntry = new TokenBlacklist();
        blacklistEntry.setJti(jti);
        blacklistEntry.setExpiresAt(LocalDateTime.ofInstant(
                expiresAt.toInstant(), 
                java.time.ZoneId.systemDefault()));
        blacklistEntry.setReason(reason);
        tokenBlacklistRepository.save(blacklistEntry);
    }
}
