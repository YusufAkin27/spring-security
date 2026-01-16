package spring.security.auth.service;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.security.auth.entity.RefreshToken;
import spring.security.auth.repository.RefreshTokenRepository;
import spring.security.exception.security.InvalidTokenException;
import spring.security.exception.security.TokenExpiredException;
import spring.security.exception.security.TokenRevokedException;
import spring.security.jwt.JwtService;
import spring.security.user.entity.User;

import java.time.LocalDateTime;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final TokenHashService tokenHashService;
    private final IpControlService ipControlService;
    private final SecurityAuditService securityAuditService;
    private final EntityManager entityManager;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    /**
     * Yeni refresh token oluşturur ve kaydeder.
     * Kullanıcının mevcut refresh token'ı varsa önce silinir.
     * 
     * @param user Kullanıcı
     * @param deviceInfo Cihaz bilgisi
     * @param deviceId Cihaz ID'si
     * @param ipAddress IP adresi
     * @return Oluşturulan refresh token
     */
    @Override
    @Transactional
    public String issueRefreshToken(User user, String deviceInfo, String deviceId, String ipAddress) {
        Optional<RefreshToken> existingToken = refreshTokenRepository.findByUser(user);
        if (existingToken.isPresent()) {
            refreshTokenRepository.delete(existingToken.get());
            entityManager.flush();
            log.debug("Eski refresh token silindi, kullanıcı: {}, eski jti: {}", 
                    user.getUsername(), existingToken.get().getJti());
        }

        String rawToken = jwtService.generateRefreshToken(
                org.springframework.security.core.userdetails.User.builder()
                        .username(user.getUsername())
                        .password(user.getPassword())
                        .authorities(user.getAuthorities())
                        .build()
        );

        String jti = jwtService.extractJti(rawToken);

        String tokenHash = tokenHashService.sha256Base64(rawToken);

        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(tokenHash);
        refreshToken.setJti(jti);
        refreshToken.setExpiresAt(expiresAt);
        refreshToken.setRevoked(false);
        refreshToken.setDeviceInfo(deviceInfo);
        refreshToken.setDeviceId(deviceId);
        refreshToken.setIpAddress(ipAddress);
        refreshToken.setLastIpAddress(ipAddress);
        refreshToken.setAccessTokenJti(null);

        refreshTokenRepository.save(refreshToken);
        log.debug("Refresh token oluşturuldu, kullanıcı: {}, jti: {}, deviceId: {}, ipAddress: {}", 
                user.getUsername(), jti, deviceId, ipAddress);

        return rawToken;
    }

    /**
     * Refresh token'ı doğrular.
     * Token'ın geçerliliğini, süresini, cihaz/IP uyumunu kontrol eder.
     * 
     * @param token Refresh token
     * @param currentDeviceId Mevcut cihaz ID'si
     * @param currentIpAddress Mevcut IP adresi
     * @return Doğrulanmış refresh token entity
     */
    @Override
    @Transactional
    public RefreshToken validateRefreshToken(String token, String currentDeviceId, String currentIpAddress) {
        try {
            String jti = jwtService.extractJti(token);

            RefreshToken refreshToken = refreshTokenRepository.findByJti(jti)
                    .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

            if (refreshToken.isRevoked()) {
                throw new TokenRevokedException("Refresh token has been revoked");
            }

            if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
                throw new TokenExpiredException("Refresh token has expired");
            }

            String incomingHash = tokenHashService.sha256Base64(token);
            if (!incomingHash.equals(refreshToken.getTokenHash())) {
                securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                        .user(refreshToken.getUser())
                        .username(refreshToken.getUser().getUsername())
                        .eventType("TOKEN_REUSE")
                        .ipAddress(currentIpAddress)
                        .deviceId(currentDeviceId)
                        .success(false)
                        .failureReason("Token hash mismatch - possible token reuse")
                        .build());
                throw new InvalidTokenException("Invalid refresh token");
            }

            if (!refreshToken.getDeviceId().equals(currentDeviceId)) {
                log.error("Cihaz uyuşmazlığı tespit edildi, kullanıcı: {}, beklenen: {}, gelen: {}", 
                        refreshToken.getUser().getUsername(), refreshToken.getDeviceId(), currentDeviceId);
                
                refreshToken.setRevoked(true);
                refreshTokenRepository.save(refreshToken);
                
                securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                        .user(refreshToken.getUser())
                        .username(refreshToken.getUser().getUsername())
                        .eventType("DEVICE_CHANGE")
                        .ipAddress(currentIpAddress)
                        .deviceId(currentDeviceId)
                        .deviceInfo("Device mismatch: " + refreshToken.getDeviceId() + " vs " + currentDeviceId)
                        .success(false)
                        .failureReason("Device mismatch detected")
                        .build());
                
                throw new spring.security.exception.security.DeviceMismatchException(
                        "Device mismatch detected. Token revoked for security.");
            }

            if (!ipControlService.validateIpChange(refreshToken.getIpAddress(), currentIpAddress)) {
                log.error("IP uyuşmazlığı tespit edildi, kullanıcı: {}, orijinal: {}, mevcut: {}", 
                        refreshToken.getUser().getUsername(), refreshToken.getIpAddress(), currentIpAddress);
                
                refreshToken.setRevoked(true);
                refreshTokenRepository.save(refreshToken);
                
                securityAuditService.logEvent(SecurityAuditService.SecurityEvent.builder()
                        .user(refreshToken.getUser())
                        .username(refreshToken.getUser().getUsername())
                        .eventType("IP_CHANGE")
                        .ipAddress(currentIpAddress)
                        .deviceId(currentDeviceId)
                        .success(false)
                        .failureReason("IP mismatch detected: " + refreshToken.getIpAddress() + " -> " + currentIpAddress)
                        .build());
                
                throw new spring.security.exception.security.IpMismatchException(
                        "IP address mismatch detected. Token revoked for security.");
            }

            refreshToken.setLastUsedAt(LocalDateTime.now());
            refreshToken.setLastIpAddress(currentIpAddress);
            refreshTokenRepository.save(refreshToken);

            return refreshToken;

        } catch (Exception e) {
            if (e instanceof TokenExpiredException || 
                e instanceof TokenRevokedException || 
                e instanceof InvalidTokenException) {
                throw e;
            }
            throw new InvalidTokenException("Invalid refresh token", e);
        }
    }

    /**
     * Refresh token'ı iptal eder (revoke).
     * 
     * @param jti Token JTI'si
     */
    @Override
    @Transactional
    public void revokeRefreshToken(String jti) {
        refreshTokenRepository.findByJti(jti).ifPresent(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
            log.debug("Refresh token iptal edildi: {}", jti);
        });
    }

    /**
     * Kullanıcının refresh token'ını siler.
     * 
     * @param user Kullanıcı
     */
    @Override
    @Transactional
    public void deleteByUser(User user) {
        refreshTokenRepository.findByUser(user).ifPresent(token -> {
            refreshTokenRepository.delete(token);
            log.info("Refresh token silindi, kullanıcı: {}, jti: {}", 
                    user.getUsername(), token.getJti());
        });
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<RefreshToken> findByUser(User user) {
        return refreshTokenRepository.findByUser(user);
    }

    /**
     * Refresh token'a bağlı access token JTI'sini günceller.
     * 
     * @param refreshTokenJti Refresh token JTI'si
     * @param accessTokenJti Access token JTI'si
     */
    @Override
    @Transactional
    public void updateAccessTokenJti(String refreshTokenJti, String accessTokenJti) {
        refreshTokenRepository.findByJti(refreshTokenJti).ifPresent(token -> {
            token.setAccessTokenJti(accessTokenJti);
            refreshTokenRepository.save(token);
            log.debug("Access token JTI güncellendi, refresh token: {}, accessTokenJti: {}", 
                    refreshTokenJti, accessTokenJti);
        });
    }

    /**
     * Süresi dolmuş refresh token'ları temizler.
     */
    @Override
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        long deletedCount = refreshTokenRepository.count();
        refreshTokenRepository.deleteByExpiresAtBefore(now);
        log.info("{} adet süresi dolmuş refresh token temizlendi", deletedCount);
    }
}
