package spring.security.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Service
public class RateLimitService {

    @Value("${security.rate-limit.login.max-attempts:5}")
    private int loginMaxAttempts;

    @Value("${security.rate-limit.login.window-minutes:1}")
    private int loginWindowMinutes;

    @Value("${security.rate-limit.refresh.max-attempts:10}")
    private int refreshMaxAttempts;

    @Value("${security.rate-limit.refresh.window-minutes:1}")
    private int refreshWindowMinutes;

    private final Map<String, AttemptRecord> loginAttempts = new ConcurrentHashMap<>();
    private final Map<String, AttemptRecord> refreshAttempts = new ConcurrentHashMap<>();

    /**
     * Rate limit aşılıp aşılmadığını kontrol eder.
     * 
     * @param identifier IP adresi veya kullanıcı tanımlayıcısı
     * @param endpoint Endpoint adı (login, refresh)
     * @return Rate limit aşıldıysa true
     */
    public boolean isRateLimitExceeded(String identifier, String endpoint) {
        Map<String, AttemptRecord> attemptsMap;
        int maxAttempts;
        int windowMinutes;

        if ("login".equals(endpoint)) {
            attemptsMap = loginAttempts;
            maxAttempts = loginMaxAttempts;
            windowMinutes = loginWindowMinutes;
        } else if ("refresh".equals(endpoint)) {
            attemptsMap = refreshAttempts;
            maxAttempts = refreshMaxAttempts;
            windowMinutes = refreshWindowMinutes;
        } else {
            log.warn("Rate limiting için bilinmeyen endpoint: {}", endpoint);
            return false;
        }

        AttemptRecord record = attemptsMap.get(identifier);
        if (record == null) {
            return false;
        }

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime windowStart = now.minusMinutes(windowMinutes);

        if (record.getLastAttempt().isBefore(windowStart)) {
            attemptsMap.remove(identifier);
            return false;
        }

        if (record.getAttemptCount() >= maxAttempts) {
            log.warn("Rate limit aşıldı, {}: {} deneme {} dakika içinde", 
                    identifier, record.getAttemptCount(), windowMinutes);
            return true;
        }

        return false;
    }

    /**
     * Deneme kaydı yapar.
     * 
     * @param identifier IP adresi veya kullanıcı tanımlayıcısı
     * @param endpoint Endpoint adı
     */
    public void recordAttempt(String identifier, String endpoint) {
        Map<String, AttemptRecord> attemptsMap;

        if ("login".equals(endpoint)) {
            attemptsMap = loginAttempts;
        } else if ("refresh".equals(endpoint)) {
            attemptsMap = refreshAttempts;
        } else {
            return;
        }

        AttemptRecord record = attemptsMap.get(identifier);
        LocalDateTime now = LocalDateTime.now();

        if (record == null) {
            record = new AttemptRecord(1, now);
            attemptsMap.put(identifier, record);
        } else {
            int loginWindowMinutes = "login".equals(endpoint) ? this.loginWindowMinutes : this.refreshWindowMinutes;
            LocalDateTime windowStart = now.minusMinutes(loginWindowMinutes);

            if (record.getLastAttempt().isBefore(windowStart)) {
                record = new AttemptRecord(1, now);
            } else {
                record = new AttemptRecord(record.getAttemptCount() + 1, now);
            }
            attemptsMap.put(identifier, record);
        }
    }

    /**
     * Deneme kayıtlarını temizler (başarılı işlem sonrası).
     * 
     * @param identifier IP adresi veya kullanıcı tanımlayıcısı
     * @param endpoint Endpoint adı
     */
    public void clearAttempts(String identifier, String endpoint) {
        Map<String, AttemptRecord> attemptsMap;

        if ("login".equals(endpoint)) {
            attemptsMap = loginAttempts;
        } else if ("refresh".equals(endpoint)) {
            attemptsMap = refreshAttempts;
        } else {
            return;
        }

        attemptsMap.remove(identifier);
        log.debug("Rate limit temizlendi, {}: {}", identifier, endpoint);
    }

    /**
     * Eski rate limit kayıtlarını temizler (1 saatten eski).
     * Her 5 dakikada bir otomatik çalışır.
     */
    @Scheduled(fixedRate = 300000)
    public void cleanupOldRecords() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(1);
        
        int loginCleaned = cleanupMap(loginAttempts, cutoff);
        int refreshCleaned = cleanupMap(refreshAttempts, cutoff);
        
        if (loginCleaned > 0 || refreshCleaned > 0) {
            log.debug("Rate limit temizliği: {} login kaydı, {} refresh kaydı silindi", 
                    loginCleaned, refreshCleaned);
        }
    }

    private int cleanupMap(Map<String, AttemptRecord> map, LocalDateTime cutoff) {
        AtomicInteger cleaned = new AtomicInteger();
        map.entrySet().removeIf(entry -> {
            if (entry.getValue().getLastAttempt().isBefore(cutoff)) {
                cleaned.getAndIncrement();
                return true;
            }
            return false;
        });
        return cleaned.get();
    }

    private static class AttemptRecord {
        private final int attemptCount;
        private final LocalDateTime lastAttempt;

        public AttemptRecord(int attemptCount, LocalDateTime lastAttempt) {
            this.attemptCount = attemptCount;
            this.lastAttempt = lastAttempt;
        }

        public int getAttemptCount() {
            return attemptCount;
        }

        public LocalDateTime getLastAttempt() {
            return lastAttempt;
        }
    }
}
