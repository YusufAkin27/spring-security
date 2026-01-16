    package spring.security.user.service;

    import spring.security.user.dto.UserResponse;

    public interface UserService {

        UserResponse getProfile(String email);
    }
