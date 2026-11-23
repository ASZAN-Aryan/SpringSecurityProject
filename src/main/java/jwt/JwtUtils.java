package jwt;

import com.securitydemo.security.secrets.SecretManager;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private final SecretManager secretManager;
    private final int jwtExpirationMs;

    private final LocatorAdapter<Key> keyLocator = new LocatorAdapter<>() {
        @Override
        protected Key locate(JwsHeader header) {
            return secretManager.keyForVerification(header.getKeyId());
        }
    };

    public JwtUtils(SecretManager secretManager,
                    @Value("${spring.app.jwtExpirationMs}") int jwtExpirationMs) {
        this.secretManager = secretManager;
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public String getJwtFromHeader(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    public String generateToken(String username) {
        return Jwts.builder()
                .header().keyId(secretManager.currentKid()).and()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(secretManager.currentSigningKey())
                .compact();
    }

    public Claims parse(String token) {
        return Jwts.parser()
                .keyLocator(keyLocator)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getUsernameFromToken(String token) {
        return parse(token).getSubject();
    }

    public boolean validateToken(String token) {
        try {
            parse(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("JWT rejected: {}", e.getClass().getSimpleName());
        }
        return false;
    }
}