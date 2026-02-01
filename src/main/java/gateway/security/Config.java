package gateway.security;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.websocket.Decoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;

@Configuration
@EnableWebSecurity
public class Config {

    @Value("${token.key}")
    private String jwtSecret;

    @Bean
    public SecurityFilterChain springSecurityFilterChain(HttpSecurity http) {
        http
                .csrf(c -> c.disable())
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/auth", "/help").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(){
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        SecretKey spec = Keys.hmacShaKeyFor(keyBytes);
        return NimbusJwtDecoder.withSecretKey(spec).build();
    }
}
