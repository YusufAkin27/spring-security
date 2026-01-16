package spring.security.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.security.auth.entity.EmailVerification;
import spring.security.auth.repository.EmailVerificationRepository;
import spring.security.user.entity.User;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailVerificationRepository emailVerificationRepository;
    private final EmailService emailService;

    @Value("${security.email.verification.code-length:6}")
    private int codeLength;

    @Value("${security.email.verification.expiration-minutes:10}")
    private int expirationMinutes;

    private static final SecureRandom random = new SecureRandom();

    /**
     * Email doğrulama kodu oluşturur ve gönderir.
     * 
     * @param user Kullanıcı
     * @param type Doğrulama tipi (REGISTRATION, LOGIN_VERIFICATION)
     * @param ipAddress IP adresi
     * @param deviceId Cihaz ID'si
     * @return Oluşturulan doğrulama kodu
     */
    @Transactional
    public String generateAndSendVerificationCode(User user, String type, String ipAddress, String deviceId) {
        String code = generateCode();

        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(expirationMinutes);

        EmailVerification verification = new EmailVerification();
        verification.setUser(user);
        verification.setCode(code);
        verification.setExpiresAt(expiresAt);
        verification.setType(type);
        verification.setIpAddress(ipAddress);
        verification.setDeviceId(deviceId);
        verification.setUsed(false);

        emailVerificationRepository.save(verification);

        emailService.sendVerificationCode(user.getEmail(), code, type);

        log.info("Doğrulama kodu oluşturuldu, kullanıcı: {}, tip: {}", user.getEmail(), type);
        return code;
    }

    public Optional<EmailVerification> findByCodeAndUsedFalseAndExpiresAtAfter(String code, LocalDateTime now) {
        return emailVerificationRepository.findByCodeAndUsedFalseAndExpiresAtAfter(code, now);
    }

    /**
     * Doğrulama kodunu kontrol eder ve doğrular.
     * 
     * @param code Doğrulama kodu
     * @param user Kullanıcı
     * @param type Doğrulama tipi
     * @return Doğrulama başarılı ise true
     */
    @Transactional
    public boolean verifyCode(String code, User user, String type) {
        LocalDateTime now = LocalDateTime.now();

        Optional<EmailVerification> verificationOpt = emailVerificationRepository
                .findByCodeAndUsedFalseAndExpiresAtAfter(code, now);

        if (verificationOpt.isEmpty()) {
            log.warn("Geçersiz veya süresi dolmuş doğrulama kodu: {}", code);
            return false;
        }

        EmailVerification verification = verificationOpt.get();

        if (!verification.getUser().getId().equals(user.getId())) {
            log.warn("Doğrulama kodu kullanıcı uyuşmazlığı: kod={}, kullanıcı={}", code, user.getEmail());
            return false;
        }

        if (!type.equals(verification.getType())) {
            log.warn("Doğrulama kodu tip uyuşmazlığı: kod={}, beklenen={}, gerçek={}", 
                    code, type, verification.getType());
            return false;
        }

        verification.setUsed(true);
        emailVerificationRepository.save(verification);

        log.info("Doğrulama kodu başarıyla doğrulandı, kullanıcı: {}, tip: {}", user.getEmail(), type);
        return true;
    }

    private String generateCode() {
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < codeLength; i++) {
            code.append(random.nextInt(10));
        }
        return code.toString();
    }

    /**
     * Süresi dolmuş doğrulama kodlarını temizler.
     */
    @Transactional
    public void cleanupExpiredVerifications() {
        LocalDateTime now = LocalDateTime.now();
        emailVerificationRepository.deleteByExpiresAtBefore(now);
        log.debug("Süresi dolmuş email doğrulamaları temizlendi");
    }
}
