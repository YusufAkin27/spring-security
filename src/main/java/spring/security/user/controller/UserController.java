package spring.security.user.controller;

import org.springframework.ui.Model;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.security.dto.ApiResponse;
import spring.security.user.dto.UserResponse;
import spring.security.user.service.UserService;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;



    @GetMapping("/profile")
    public ResponseEntity<ApiResponse<UserResponse>> getProfile(Authentication authentication) {
        String email = authentication.getName();
        
        UserResponse profile = userService.getProfile(email);
        
        ApiResponse<UserResponse> response = ApiResponse.success(profile);
        
        return ResponseEntity.ok(response);
    }
}
