package spring.security.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.security.user.entity.User;
import spring.security.user.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class BruteForceProtectionService {

    private final UserRepository userRepository;

    @Value("${security.brute-force.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${security.brute-force.temporary-lock-minutes:15}")
    private int temporaryLockMinutes;

    @Value("${security.brute-force.permanent-lock-threshold:10}")
    private int permanentLockThreshold;

    private final Map<String, FailedAttemptRecord> failedAttempts = new ConcurrentHashMap<>();

    @Transactional
    public void recordFailedAttempt(String email) {
        FailedAttemptRecord record = failedAttempts.get(email);
        LocalDateTime now = LocalDateTime.now();

        if (record == null) {
            record = new FailedAttemptRecord(1, now, false);
            failedAttempts.put(email, record);
            log.warn("Failed login attempt #1 for user: {}", email);
        } else {
            int newCount = record.getAttemptCount() + 1;
            boolean isPermanentlyLocked = record.isPermanentlyLocked();

            if (isPermanentlyLocked) {
                log.warn("Permanently locked account login attempt: {}", email);
                return;
            }

            if (record.getLockedUntil() != null && record.getLockedUntil().isAfter(now)) {
                log.warn("Temporarily locked account login attempt: {} (locked until: {})", 
                        email, record.getLockedUntil());
                return;
            }

            if (record.getLockedUntil() != null && record.getLockedUntil().isBefore(now)) {
                log.info("Temporary lock expired for user: {}, resetting counter", email);
                record = new FailedAttemptRecord(1, now, false);
                failedAttempts.put(email, record);
            } else {
                record = new FailedAttemptRecord(newCount, now, false);
            }

            if (newCount >= maxFailedAttempts && newCount < permanentLockThreshold) {
                LocalDateTime lockedUntil = now.plusMinutes(temporaryLockMinutes);
                record = new FailedAttemptRecord(newCount, now, false, lockedUntil);
                log.warn("Account temporarily locked for user: {} ({} failed attempts, locked until: {})", 
                        email, newCount, lockedUntil);
            }

            if (newCount >= permanentLockThreshold) {
                record = new FailedAttemptRecord(newCount, now, true);
                userRepository.findByEmail(email).ifPresent(user -> {
                    user.setEnabled(false);
                    userRepository.save(user);
                    log.error("Account permanently locked for user: {} ({} failed attempts)", 
                            email, newCount);
                });
            }

            failedAttempts.put(email, record);
            log.warn("Failed login attempt #{} for user: {}", newCount, email);
        }
    }

    public boolean isAccountLocked(String email) {
        FailedAttemptRecord record = failedAttempts.get(email);
        if (record == null) {
            return false;
        }

        if (record.isPermanentlyLocked()) {
            log.warn("Account is permanently locked: {}", email);
            return true;
        }

        if (record.getLockedUntil() != null) {
            LocalDateTime now = LocalDateTime.now();
            if (record.getLockedUntil().isAfter(now)) {
                log.warn("Account is temporarily locked: {} (locked until: {})", 
                        email, record.getLockedUntil());
                return true;
            } else {
                failedAttempts.remove(email);
                log.info("Temporary lock expired for user: {}", email);
                return false;
            }
        }

        return false;
    }

    public void recordSuccessfulLogin(String email) {
        FailedAttemptRecord record = failedAttempts.remove(email);
        if (record != null) {
            log.info("Successful login for user: {}, failed attempts counter reset", email);
        }
    }

    @Scheduled(fixedRate = 3600000)
    public void cleanupOldRecords() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(24);
        
        int cleaned = 0;
        for (Map.Entry<String, FailedAttemptRecord> entry : failedAttempts.entrySet()) {
            FailedAttemptRecord record = entry.getValue();
            if (record.getLastAttempt().isBefore(cutoff) && 
                (record.getLockedUntil() == null || record.getLockedUntil().isBefore(cutoff))) {
                failedAttempts.remove(entry.getKey());
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            log.debug("Brute force protection cleanup: {} old records removed", cleaned);
        }
    }

    private static class FailedAttemptRecord {
        private final int attemptCount;
        private final LocalDateTime lastAttempt;
        private final boolean permanentlyLocked;
        private final LocalDateTime lockedUntil;

        public FailedAttemptRecord(int attemptCount, LocalDateTime lastAttempt, boolean permanentlyLocked) {
            this(attemptCount, lastAttempt, permanentlyLocked, null);
        }

        public FailedAttemptRecord(int attemptCount, LocalDateTime lastAttempt, boolean permanentlyLocked, LocalDateTime lockedUntil) {
            this.attemptCount = attemptCount;
            this.lastAttempt = lastAttempt;
            this.permanentlyLocked = permanentlyLocked;
            this.lockedUntil = lockedUntil;
        }

        public int getAttemptCount() {
            return attemptCount;
        }

        public LocalDateTime getLastAttempt() {
            return lastAttempt;
        }

        public boolean isPermanentlyLocked() {
            return permanentlyLocked;
        }

        public LocalDateTime getLockedUntil() {
            return lockedUntil;
        }
    }
}
