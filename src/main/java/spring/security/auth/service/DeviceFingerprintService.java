package spring.security.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Slf4j
@Service
public class DeviceFingerprintService {

    /**
     * İstekten cihaz ID'si oluşturur.
     * User-Agent, IP adresi ve Accept-Language bilgilerini kullanır.
     * 
     * @param request HTTP istek nesnesi
     * @return Cihaz ID'si (SHA-256 hash)
     */
    public String generateDeviceId(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null || userAgent.isEmpty()) {
            userAgent = "Unknown";
        }

        String ipAddress = extractIpAddress(request);

        String acceptLanguage = request.getHeader("Accept-Language");
        if (acceptLanguage == null || acceptLanguage.isEmpty()) {
            acceptLanguage = "Unknown";
        }

        String fingerprint = String.format("%s|%s|%s", userAgent, ipAddress, acceptLanguage);

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(fingerprint.getBytes(StandardCharsets.UTF_8));
            String deviceId = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            
            log.debug("Cihaz fingerprint oluşturuldu: {} (UA: {}, IP: {})", 
                    deviceId.substring(0, Math.min(16, deviceId.length())), 
                    userAgent.substring(0, Math.min(50, userAgent.length())), 
                    ipAddress);
            
            return deviceId;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String extractIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            String[] ips = xForwardedFor.split(",");
            String clientIp = ips[0].trim();
            if (!clientIp.isEmpty()) {
                return clientIp;
            }
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp.trim();
        }

        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr != null && !remoteAddr.isEmpty()) {
            return remoteAddr;
        }

        return "Unknown";
    }

    /**
     * İstekten cihaz bilgisini çıkarır (tarayıcı ve işletim sistemi).
     * 
     * @param request HTTP istek nesnesi
     * @return Cihaz bilgisi string'i
     */
    public String extractDeviceInfo(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null || userAgent.isEmpty()) {
            return "Unknown Device";
        }

        StringBuilder deviceInfo = new StringBuilder();

        if (userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            deviceInfo.append("Chrome");
        } else if (userAgent.contains("Firefox")) {
            deviceInfo.append("Firefox");
        } else if (userAgent.contains("Safari") && !userAgent.contains("Chrome")) {
            deviceInfo.append("Safari");
        } else if (userAgent.contains("Edg")) {
            deviceInfo.append("Edge");
        } else {
            deviceInfo.append("Unknown Browser");
        }

        deviceInfo.append(" on ");

        if (userAgent.contains("Windows")) {
            deviceInfo.append("Windows");
        } else if (userAgent.contains("Mac")) {
            deviceInfo.append("macOS");
        } else if (userAgent.contains("Linux")) {
            deviceInfo.append("Linux");
        } else if (userAgent.contains("Android")) {
            deviceInfo.append("Android");
        } else if (userAgent.contains("iPhone") || userAgent.contains("iPad")) {
            deviceInfo.append("iOS");
        } else {
            deviceInfo.append("Unknown OS");
        }

        return deviceInfo.toString();
    }
}
