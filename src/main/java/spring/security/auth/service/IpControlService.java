package spring.security.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class IpControlService {

    @Value("${security.ip-control.enabled}")
    private boolean ipControlEnabled;

    @Value("${security.ip-control.subnet-check}")
    private boolean subnetCheckEnabled;

    /**
     * İstekten IP adresini çıkarır.
     * X-Forwarded-For, X-Real-IP ve RemoteAddr header'larını kontrol eder.
     * 
     * @param request HTTP istek nesnesi
     * @return IP adresi veya "Unknown"
     */
    public String extractIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            String[] ips = xForwardedFor.split(",");
            String clientIp = ips[0].trim();
            if (!clientIp.isEmpty() && isValidIp(clientIp)) {
                return clientIp;
            }
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && isValidIp(xRealIp)) {
            return xRealIp.trim();
        }

        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr != null && !remoteAddr.isEmpty() && isValidIp(remoteAddr)) {
            return remoteAddr;
        }

        log.warn("İstekten geçerli IP adresi çıkarılamadı");
        return "Unknown";
    }

    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }

        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }

        try {
            for (String part : parts) {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * İki IP adresinin aynı subnet'te olup olmadığını kontrol eder.
     * İlk 3 octet'i karşılaştırır.
     * 
     * @param ip1 İlk IP adresi
     * @param ip2 İkinci IP adresi
     * @return Aynı subnet'te ise true
     */
    public boolean isSameSubnet(String ip1, String ip2) {
        if (ip1 == null || ip2 == null || ip1.isEmpty() || ip2.isEmpty()) {
            return false;
        }

        if (ip1.equals(ip2)) {
            return true;
        }

        if (!subnetCheckEnabled) {
            log.debug("Subnet kontrolü devre dışı, IP'ler farklı kabul edildi: {} vs {}", ip1, ip2);
            return false;
        }

        try {
            String[] parts1 = ip1.split("\\.");
            String[] parts2 = ip2.split("\\.");

            if (parts1.length != 4 || parts2.length != 4) {
                return false;
            }

            for (int i = 0; i < 3; i++) {
                if (!parts1[i].equals(parts2[i])) {
                    log.debug("IP'ler farklı subnet'lerde: {} vs {}", ip1, ip2);
                    return false;
                }
            }

            log.debug("IP'ler aynı subnet'te: {} vs {}", ip1, ip2);
            return true;
        } catch (Exception e) {
            log.warn("IP karşılaştırma hatası: {} vs {}, hata: {}", ip1, ip2, e.getMessage());
            return false;
        }
    }

    /**
     * IP değişikliğini doğrular.
     * IP kontrolü aktifse, aynı IP veya aynı subnet kontrolü yapar.
     * 
     * @param originalIp Orijinal IP adresi
     * @param currentIp Mevcut IP adresi
     * @return IP değişikliği kabul edilebilirse true
     */
    public boolean validateIpChange(String originalIp, String currentIp) {
        if (!ipControlEnabled) {
            log.debug("IP kontrolü devre dışı, IP değişikliği izinli");
            return true;
        }

        if (originalIp == null || originalIp.isEmpty() || "Unknown".equals(originalIp)) {
            log.debug("Orijinal IP bilinmiyor, IP değişikliği izinli");
            return true;
        }

        if (currentIp == null || currentIp.isEmpty() || "Unknown".equals(currentIp)) {
            log.warn("Mevcut IP bilinmiyor, istek reddedildi");
            return false;
        }

        if (originalIp.equals(currentIp)) {
            log.debug("IP'ler tam olarak eşleşiyor: {}", currentIp);
            return true;
        }

        if (subnetCheckEnabled) {
            boolean sameSubnet = isSameSubnet(originalIp, currentIp);
            if (sameSubnet) {
                log.debug("IP'ler aynı subnet'te: {} vs {}", originalIp, currentIp);
                return true;
            } else {
                log.warn("IP değişikliği tespit edildi (farklı subnet): {} -> {}", originalIp, currentIp);
                return false;
            }
        } else {
            log.warn("IP değişikliği tespit edildi: {} -> {}", originalIp, currentIp);
            return false;
        }
    }
}
