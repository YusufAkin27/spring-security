package spring.security.auth.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import spring.security.auth.entity.SecurityAuditLog;
import spring.security.user.entity.User;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityAuditRepository extends JpaRepository<SecurityAuditLog, Long> {

    Page<SecurityAuditLog> findByUserOrderByTimestampDesc(User user, Pageable pageable);

    Page<SecurityAuditLog> findByUsernameOrderByTimestampDesc(String username, Pageable pageable);

    Page<SecurityAuditLog> findByEventTypeOrderByTimestampDesc(String eventType, Pageable pageable);

    Page<SecurityAuditLog> findByIpAddressOrderByTimestampDesc(String ipAddress, Pageable pageable);

    @Query("SELECT sal FROM SecurityAuditLog sal WHERE sal.timestamp BETWEEN :start AND :end ORDER BY sal.timestamp DESC")
    Page<SecurityAuditLog> findByTimestampBetween(
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end,
            Pageable pageable
    );

    @Query("SELECT sal FROM SecurityAuditLog sal WHERE sal.eventType = 'LOGIN_FAILED' AND sal.timestamp >= :since ORDER BY sal.timestamp DESC")
    List<SecurityAuditLog> findRecentFailedLogins(@Param("since") LocalDateTime since);

    @Query("SELECT sal FROM SecurityAuditLog sal WHERE sal.username = :username AND sal.eventType = 'LOGIN_FAILED' AND sal.timestamp >= :since ORDER BY sal.timestamp DESC")
    List<SecurityAuditLog> findRecentFailedLoginsByUsername(
            @Param("username") String username,
            @Param("since") LocalDateTime since
    );
}
