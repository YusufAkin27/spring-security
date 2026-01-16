package spring.security.auth.scheduler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import spring.security.auth.repository.RefreshTokenRepository;
import spring.security.auth.repository.TokenBlacklistRepository;
import spring.security.auth.service.RefreshTokenService;

import java.time.LocalDateTime;

@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(
        value = "jwt.refresh-token-cleanup-enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class TokenCleanupScheduler {

    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistRepository tokenBlacklistRepository;

    /**
     * Süresi dolmuş token'ları temizler.
     * Refresh token'ları ve blacklist'teki token'ları siler.
     * Cron expression ile belirlenen zamanda otomatik çalışır (varsayılan: her gün saat 02:00).
     */
    @Scheduled(cron = "${jwt.token-cleanup-cron:0 0 2 * * ?}")
    public void cleanupExpiredTokens() {
        log.info("Token temizleme işi başlatılıyor...");
        
        LocalDateTime now = LocalDateTime.now();
        
        try {
            refreshTokenService.cleanupExpiredTokens();
            tokenBlacklistRepository.deleteByExpiresAtBefore(now);
        } catch (Exception e) {
            log.error("Token temizleme sırasında hata oluştu", e);
        }
    }
}
