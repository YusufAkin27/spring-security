package spring.security.auth.service;

import spring.security.auth.entity.RefreshToken;
import spring.security.user.entity.User;

import java.util.Optional;

public interface RefreshTokenService {

    String issueRefreshToken(User user, String deviceInfo, String deviceId, String ipAddress);

    RefreshToken validateRefreshToken(String token, String currentDeviceId, String currentIpAddress);

    void revokeRefreshToken(String jti);

    void deleteByUser(User user);

    Optional<RefreshToken> findByUser(User user);

    void updateAccessTokenJti(String refreshTokenJti, String accessTokenJti);

    void cleanupExpiredTokens();
}
