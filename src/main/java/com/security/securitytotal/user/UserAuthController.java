package com.security.securitytotal.user;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserAuthController {

    private final UserAuthService userAuthService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserAuthController(UserAuthRepository userAuthRepository, UserAuthService userAuthService, PasswordEncoder passwordEncoder) {
        this.userAuthService = userAuthService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody UserAuthEntity userAuthEntity) {


        userAuthEntity.setPassword(passwordEncoder.encode(userAuthEntity.getPassword()) );
        userAuthService.save(userAuthEntity);

        return ResponseEntity.ok("successfully registered");
    }
    @GetMapping("/users")
    public ResponseEntity<String> getUser() {
        return ResponseEntity.ok("successfully logged in");
    }


}
