package spring.security.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import spring.security.auth.entity.EmailVerification;
import spring.security.user.entity.User;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface EmailVerificationRepository extends JpaRepository<EmailVerification, Long> {

    Optional<EmailVerification> findByCodeAndUsedFalseAndExpiresAtAfter(String code, LocalDateTime now);

    Optional<EmailVerification> findByUserAndTypeAndUsedFalseAndExpiresAtAfter(User user, String type, LocalDateTime now);

    @Modifying
    @Query("DELETE FROM EmailVerification ev WHERE ev.expiresAt < :now")
    void deleteByExpiresAtBefore(@Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE EmailVerification ev SET ev.used = true WHERE ev.user = :user AND ev.type = :type AND ev.used = false")
    void markAsUsedByUserAndType(@Param("user") User user, @Param("type") String type);
}
