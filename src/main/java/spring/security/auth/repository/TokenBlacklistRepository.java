package spring.security.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import spring.security.auth.entity.TokenBlacklist;

import java.time.LocalDateTime;

@Repository
public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Long> {

    boolean existsByJti(String jti);

    @Modifying
    @Query("DELETE FROM TokenBlacklist tb WHERE tb.expiresAt < :now")
    void deleteByExpiresAtBefore(@Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM TokenBlacklist tb WHERE tb.jti = :jti")
    void deleteByJti(@Param("jti") String jti);
}
