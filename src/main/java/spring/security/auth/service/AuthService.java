package spring.security.auth.service;

import spring.security.auth.dto.AuthResponse;
import spring.security.auth.dto.LoginRequest;
import spring.security.auth.dto.LogoutRequest;
import spring.security.auth.dto.RegisterRequest;
import spring.security.auth.dto.RefreshTokenRequest;

public interface AuthService {
    
    AuthResponse register(RegisterRequest request, String deviceId, String ipAddress, String deviceInfo);
    
    AuthResponse login(LoginRequest request, String deviceId, String ipAddress, String deviceInfo);
    
    AuthResponse refreshToken(String refreshToken, String deviceId, String ipAddress);
    
    void logout(LogoutRequest request, String email, String accessToken);
}
