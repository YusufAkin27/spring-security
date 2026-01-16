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

        log.warn("Could not extract valid IP address from request");
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

    public boolean isSameSubnet(String ip1, String ip2) {
        if (ip1 == null || ip2 == null || ip1.isEmpty() || ip2.isEmpty()) {
            return false;
        }

        if (ip1.equals(ip2)) {
            return true;
        }

        if (!subnetCheckEnabled) {
            log.debug("Subnet check disabled, IPs considered different: {} vs {}", ip1, ip2);
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
                    log.debug("IPs in different subnets: {} vs {}", ip1, ip2);
                    return false;
                }
            }

            log.debug("IPs in same subnet: {} vs {}", ip1, ip2);
            return true;
        } catch (Exception e) {
            log.warn("Error comparing IPs: {} vs {}, error: {}", ip1, ip2, e.getMessage());
            return false;
        }
    }

    public boolean validateIpChange(String originalIp, String currentIp) {
        if (!ipControlEnabled) {
            log.debug("IP control disabled, IP change allowed");
            return true;
        }

        if (originalIp == null || originalIp.isEmpty() || "Unknown".equals(originalIp)) {
            log.debug("Original IP unknown, allowing IP change");
            return true;
        }

        if (currentIp == null || currentIp.isEmpty() || "Unknown".equals(currentIp)) {
            log.warn("Current IP unknown, rejecting request");
            return false;
        }

        if (originalIp.equals(currentIp)) {
            log.debug("IPs match exactly: {}", currentIp);
            return true;
        }

        if (subnetCheckEnabled) {
            boolean sameSubnet = isSameSubnet(originalIp, currentIp);
            if (sameSubnet) {
                log.debug("IPs in same subnet: {} vs {}", originalIp, currentIp);
                return true;
            } else {
                log.warn("IP change detected (different subnet): {} -> {}", originalIp, currentIp);
                return false;
            }
        } else {
            log.warn("IP change detected: {} -> {}", originalIp, currentIp);
            return false;
        }
    }
}
