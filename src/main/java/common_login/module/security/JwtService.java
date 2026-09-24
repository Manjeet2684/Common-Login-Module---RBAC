package common_login.module.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import common_login.module.config.JwtProperties;
import common_login.module.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	private final JwtProperties jwtProperties;
	private final SecretKey secretKey;

	public JwtService(JwtProperties jwtProperties) {
		this.jwtProperties = jwtProperties;
		this.secretKey = Keys.hmacShaKeyFor(resolveSecretBytes(jwtProperties.getSecret()));
	}

	public String generateToken(UserDetails userDetails) {
		List<String> roles = userDetails.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.toList();

		Date now = new Date();
		Date expiry = new Date(now.getTime() + jwtProperties.getExpirationMs());

		return Jwts.builder()
				.subject(userDetails.getUsername())
				.issuer(jwtProperties.getIssuer())
				.issuedAt(now)
				.expiration(expiry)
				.claim("roles", roles)
				.signWith(secretKey)
				.compact();
	}

	public String extractUsername(String token) {
		return parseClaims(token).getSubject();
	}

	public Set<Role> extractRoles(String token) {
		Claims claims = parseClaims(token);
		Object rolesClaim = claims.get("roles");
		if (!(rolesClaim instanceof List<?> roleList)) {
			return Set.of();
		}
		return roleList.stream()
				.map(Object::toString)
				.map(role -> role.startsWith("ROLE_") ? role.substring(5) : role)
				.map(Role::valueOf)
				.collect(Collectors.toSet());
	}

	public boolean isTokenValid(String token, UserDetails userDetails) {
		try {
			String username = extractUsername(token);
			return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
		}
		catch (JwtException | IllegalArgumentException ex) {
			return false;
		}
	}

	public boolean isTokenExpired(String token) {
		return parseClaims(token).getExpiration().before(new Date());
	}

	public long getExpirationMs() {
		return jwtProperties.getExpirationMs();
	}

	private Claims parseClaims(String token) {
		return Jwts.parser()
				.verifyWith(secretKey)
				.requireIssuer(jwtProperties.getIssuer())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}

	private static byte[] resolveSecretBytes(String secret) {
		try {
			byte[] decoded = Decoders.BASE64.decode(secret);
			if (decoded.length >= 32) {
				return decoded;
			}
		}
		catch (RuntimeException ignored) {
			// fall through to raw UTF-8 bytes
		}
		return secret.getBytes(StandardCharsets.UTF_8);
	}
}
