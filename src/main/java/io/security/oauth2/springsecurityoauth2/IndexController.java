package io.security.oauth2.springsecurityoauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "index";
    }
}
