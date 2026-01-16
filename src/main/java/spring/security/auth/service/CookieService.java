package spring.security.auth.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CookieService {

    @Value("${security.cookie.refresh-token.name:refreshToken}")
    private String cookieName;

    @Value("${security.cookie.refresh-token.path:/api/auth/refresh}")
    private String cookiePath;

    @Value("${security.cookie.refresh-token.secure:true}")
    private boolean cookieSecure;

    @Value("${security.cookie.refresh-token.http-only:true}")
    private boolean cookieHttpOnly;

    @Value("${security.cookie.refresh-token.same-site:Strict}")
    private String cookieSameSite;

    @Value("${jwt.refresh-token-expiration:604800000}")
    private long refreshTokenExpiration;

    /**
     * Refresh token'ı HTTP-only cookie olarak ayarlar.
     * 
     * @param response HTTP yanıt nesnesi
     * @param token Refresh token
     */
    public void setRefreshTokenCookie(HttpServletResponse response, String token) {
        int maxAge = (int) (refreshTokenExpiration / 1000);

        ResponseCookie cookie = ResponseCookie.from(cookieName, token)
                .path(cookiePath)
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .maxAge(maxAge)
                .sameSite(cookieSameSite)
                .build();

        response.addHeader("Set-Cookie", cookie.toString());

        log.debug("Refresh token cookie ayarlandı: name={}, path={}, httpOnly={}, secure={}, sameSite={}, maxAge={}s", 
                cookieName, cookiePath, cookieHttpOnly, cookieSecure, cookieSameSite, maxAge);
    }

    /**
     * Cookie'den refresh token'ı okur.
     * 
     * @param request HTTP istek nesnesi
     * @return Refresh token veya null
     */
    public String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                String token = cookie.getValue();
                log.debug("Refresh token cookie'den okundu: {}", token != null ? "mevcut" : "null");
                return token;
            }
        }

        log.debug("Refresh token cookie bulunamadı: {}", cookieName);
        return null;
    }

    /**
     * Refresh token cookie'sini temizler (silir).
     * 
     * @param response HTTP yanıt nesnesi
     */
    public void clearRefreshTokenCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(cookieName, "")
                .path(cookiePath)
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .maxAge(0)
                .sameSite(cookieSameSite)
                .build();

        response.addHeader("Set-Cookie", cookie.toString());

        log.debug("Refresh token cookie temizlendi: name={}, path={}, sameSite={}", cookieName, cookiePath, cookieSameSite);
    }
}
