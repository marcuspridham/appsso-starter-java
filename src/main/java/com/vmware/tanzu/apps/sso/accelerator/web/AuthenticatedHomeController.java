package com.vmware.tanzu.apps.sso.accelerator.web;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;
import java.util.Map;

@Controller
public class AuthenticatedHomeController {
    private final ObjectMapper objectMapper;
    // see: https://www.baeldung.com/spring-security-openid-connect#1-accessing-user-information

    public AuthenticatedHomeController(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @GetMapping("/authenticated/home")
    public String authenticatedHome(Model model, @AuthenticationPrincipal OidcUser authenticatedUser, @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) throws Exception {
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        if (accessToken != null) {
            String accessTokenValue = accessToken.getTokenValue();
            model.addAttribute("access_token", toPrettyJsonString(parseToken(accessTokenValue)));
        }

        model.addAttribute("username", authenticatedUser.getClaims().get("sub"));
        return "authenticated-home.html";
    }

    private Map<String, ?> parseToken(String base64Token) throws IOException {
        String token = base64Token.split("\\.")[1];
        return objectMapper.readValue(Base64.decodeBase64(token), new TypeReference<Map<String, ?>>() {
        });
    }

    private String toPrettyJsonString(Object object) throws Exception {
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(object);
    }
}
