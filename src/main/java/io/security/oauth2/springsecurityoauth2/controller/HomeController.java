package io.security.oauth2.springsecurityoauth2.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @GetMapping("/home")
    public String home(OAuth2AuthenticationToken authentication, Model model) {
        OAuth2AuthorizedClient oAuth2AuthorizedClient = oAuth2AuthorizedClientService.loadAuthorizedClient("keycloak", authentication.getName());
        model.addAttribute("oAuth2AuthenticationToken", authentication);
        model.addAttribute("AccessToken", oAuth2AuthorizedClient.getAccessToken());
        model.addAttribute("RefreshToken", oAuth2AuthorizedClient.getRefreshToken());
        return "home";
    }
}
