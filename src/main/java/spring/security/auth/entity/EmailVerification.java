package spring.security.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import spring.security.user.entity.User;

import java.time.LocalDateTime;

@Entity
@Table(name = "email_verifications", indexes = {
    @Index(name = "idx_email_verification_code", columnList = "code"),
    @Index(name = "idx_email_verification_user", columnList = "user_id"),
    @Index(name = "idx_email_verification_expires", columnList = "expires_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class EmailVerification {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 10)
    private String code;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private boolean used = false;

    @Column(length = 50)
    private String type;

    @Column(length = 50)
    private String ipAddress;

    @Column(length = 255)
    private String deviceId;

    @PrePersist
    public void onCreate() {
        this.createdAt = LocalDateTime.now();
    }
}
