package spring.security.auth.service;

import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.security.auth.entity.SecurityAuditLog;
import spring.security.auth.repository.SecurityAuditRepository;
import spring.security.user.entity.User;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityAuditService {

    private final SecurityAuditRepository auditRepository;

    @Transactional
    public void logEvent(SecurityEvent event) {
        try {
            SecurityAuditLog auditLog = new SecurityAuditLog();
            auditLog.setUser(event.getUser());
            auditLog.setUsername(event.getUsername());
            auditLog.setEventType(event.getEventType());
            auditLog.setIpAddress(event.getIpAddress());
            auditLog.setDeviceId(event.getDeviceId());
            auditLog.setDeviceInfo(event.getDeviceInfo());
            auditLog.setSuccess(event.isSuccess());
            auditLog.setFailureReason(event.getFailureReason());
            auditLog.setDetails(event.getDetails());
            auditLog.setTimestamp(LocalDateTime.now());

            auditRepository.save(auditLog);

            if (event.isSuccess()) {
                log.info("Security event logged: {} for user: {} from IP: {}", 
                        event.getEventType(), event.getUsername(), event.getIpAddress());
            } else {
                log.warn("Security event logged (FAILED): {} for user: {} from IP: {}, reason: {}", 
                        event.getEventType(), event.getUsername(), event.getIpAddress(), event.getFailureReason());
            }
        } catch (Exception e) {
            log.error("Failed to log security event: {}", e.getMessage(), e);
        }
    }

    @Builder
    public static class SecurityEvent {
        private User user;
        private String username;
        private String eventType;
        private String ipAddress;
        private String deviceId;
        private String deviceInfo;
        private boolean success;
        private String failureReason;
        private String details;


        public SecurityEvent user(User user) {
            this.user = user;
            if (user != null) {
                this.username = user.getUsername();
            }
            return this;
        }

        public SecurityEvent username(String username) {
            this.username = username;
            return this;
        }

        public SecurityEvent eventType(String eventType) {
            this.eventType = eventType;
            return this;
        }

        public SecurityEvent ipAddress(String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }

        public SecurityEvent deviceId(String deviceId) {
            this.deviceId = deviceId;
            return this;
        }

        public SecurityEvent deviceInfo(String deviceInfo) {
            this.deviceInfo = deviceInfo;
            return this;
        }

        public SecurityEvent success(boolean success) {
            this.success = success;
            return this;
        }

        public SecurityEvent failureReason(String failureReason) {
            this.failureReason = failureReason;
            return this;
        }

        public SecurityEvent details(String details) {
            this.details = details;
            return this;
        }

        public User getUser() { return user; }
        public String getUsername() { return username; }
        public String getEventType() { return eventType; }
        public String getIpAddress() { return ipAddress; }
        public String getDeviceId() { return deviceId; }
        public String getDeviceInfo() { return deviceInfo; }
        public boolean isSuccess() { return success; }
        public String getFailureReason() { return failureReason; }
        public String getDetails() { return details; }
    }
}
