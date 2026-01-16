package spring.security.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "token_blacklist", indexes = {
    @Index(name = "idx_blacklist_jti", columnList = "jti"),
    @Index(name = "idx_blacklist_expires", columnList = "expires_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TokenBlacklist {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long id;

    @Column(unique = true, nullable = false, length = 100)
    private String jti;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false, updatable = false)
    private LocalDateTime blacklistedAt;

    @Column(length = 100)
    private String reason;

    @PrePersist
    public void onCreate() {
        this.blacklistedAt = LocalDateTime.now();
    }
}
