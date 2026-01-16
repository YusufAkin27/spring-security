package spring.security.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import spring.security.user.entity.User;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens", indexes = {
    @Index(name = "idx_refresh_token_jti", columnList = "jti"),
    @Index(name = "idx_refresh_token_user", columnList = "user_id", unique = true),
    @Index(name = "idx_refresh_token_expires", columnList = "expires_at"),
    @Index(name = "idx_refresh_token_device", columnList = "device_id"),
    @Index(name = "idx_refresh_token_ip", columnList = "ip_address")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(nullable = false, length = 255)
    private String tokenHash;

    @Column(unique = true, nullable = false, length = 100)
    private String jti;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(length = 200)
    private String deviceInfo;

    private LocalDateTime lastUsedAt;

    @Column(length = 100)
    private String accessTokenJti;

    @Column(name = "device_id", length = 100, nullable = false)
    private String deviceId;

    @Column(name = "ip_address", length = 45, nullable = false)
    private String ipAddress;

    @Column(name = "last_ip_address", length = 45)
    private String lastIpAddress;

    @PrePersist
    public void onCreate() {
        this.createdAt = LocalDateTime.now();
        if (this.lastUsedAt == null) {
            this.lastUsedAt = LocalDateTime.now();
        }
    }
}
