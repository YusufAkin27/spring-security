package spring.security.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.from:no-reply@yusufakin.online}")
    private String fromEmail;

    /**
     * Doğrulama kodunu email ile gönderir.
     * 
     * @param toEmail Alıcı email adresi
     * @param code Doğrulama kodu
     * @param type Email tipi (REGISTRATION, LOGIN_VERIFICATION)
     */
    public void sendVerificationCode(String toEmail, String code, String type) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            
            if ("REGISTRATION".equals(type)) {
                message.setSubject("Hesap Doğrulama Kodu");
                message.setText(String.format(
                    "Merhaba,\n\n" +
                    "Hesabınızı doğrulamak için aşağıdaki kodu kullanın:\n\n" +
                    "Doğrulama Kodu: %s\n\n" +
                    "Bu kod 10 dakika geçerlidir.\n\n" +
                    "Eğer bu işlemi siz yapmadıysanız, lütfen bu e-postayı görmezden gelin.\n\n" +
                    "Saygılarımızla,\n" +
                    "Güvenlik Ekibi",
                    code
                ));
            } else if ("LOGIN_VERIFICATION".equals(type)) {
                message.setSubject("Giriş Doğrulama Kodu");
                message.setText(String.format(
                    "Merhaba,\n\n" +
                    "Hesabınıza yeni bir cihaz veya IP adresinden giriş yapılmaya çalışılıyor.\n\n" +
                    "Giriş yapmak için aşağıdaki doğrulama kodunu kullanın:\n\n" +
                    "Doğrulama Kodu: %s\n\n" +
                    "Bu kod 10 dakika geçerlidir.\n\n" +
                    "Eğer bu giriş denemesi sizden değilse, lütfen hemen şifrenizi değiştirin ve bizimle iletişime geçin.\n\n" +
                    "Saygılarımızla,\n" +
                    "Güvenlik Ekibi",
                    code
                ));
            }

            mailSender.send(message);
            log.info("Doğrulama email'i gönderildi: {}", toEmail);
        } catch (Exception e) {
            log.error("Doğrulama email'i gönderilemedi: {}", toEmail, e);
            throw new RuntimeException("Email gönderilemedi", e);
        }
    }
}
