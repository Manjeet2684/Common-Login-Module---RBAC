package common_login.module.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.EnumSet;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import common_login.module.config.JwtProperties;
import common_login.module.domain.Role;
import common_login.module.domain.User;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;

class JwtServiceTest {

	private JwtService jwtService;
	private User sampleUser;

	@BeforeEach
	void setUp() {
		JwtProperties properties = new JwtProperties();
		properties.setSecret("dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItY29tbW9uLWxvZ2luLW1vZHVsZS10ZXN0cw==");
		properties.setExpirationMs(3_600_000L);
		properties.setIssuer("common-login-module-test");
		jwtService = new JwtService(properties);

		sampleUser = new User();
		sampleUser.setUsername("alice");
		sampleUser.setEmail("alice@example.com");
		sampleUser.setPassword("encoded");
		sampleUser.setRoles(EnumSet.of(Role.USER, Role.ADMIN));
	}

	@Test
	void generateToken_containsSubjectAndRoles() {
		String token = jwtService.generateToken(sampleUser);

		assertThat(token).isNotBlank();
		assertThat(jwtService.extractUsername(token)).isEqualTo("alice");
		assertThat(jwtService.extractRoles(token)).containsExactlyInAnyOrder(Role.USER, Role.ADMIN);
		assertThat(jwtService.isTokenValid(token, sampleUser)).isTrue();
		assertThat(jwtService.isTokenExpired(token)).isFalse();
	}

	@Test
	void isTokenValid_returnsFalseForDifferentUser() {
		String token = jwtService.generateToken(sampleUser);

		User other = new User();
		other.setUsername("bob");
		other.setEmail("bob@example.com");
		other.setPassword("encoded");
		other.setRoles(EnumSet.of(Role.USER));

		assertThat(jwtService.isTokenValid(token, other)).isFalse();
	}

	@Test
	void parseClaims_rejectsTamperedToken() {
		String token = jwtService.generateToken(sampleUser);
		String tampered = token.substring(0, token.length() - 4) + "xxxx";

		assertThatThrownBy(() -> jwtService.extractUsername(tampered))
				.isInstanceOf(SignatureException.class);
	}

	@Test
	void expiredToken_isRejected() {
		JwtProperties shortLived = new JwtProperties();
		shortLived.setSecret("dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItY29tbW9uLWxvZ2luLW1vZHVsZS10ZXN0cw==");
		shortLived.setExpirationMs(1L);
		shortLived.setIssuer("common-login-module-test");
		JwtService shortLivedService = new JwtService(shortLived);

		String token = shortLivedService.generateToken(sampleUser);

		assertThatThrownBy(() -> {
			Thread.sleep(20L);
			shortLivedService.extractUsername(token);
		}).isInstanceOf(ExpiredJwtException.class);
	}

	@Test
	void extractRoles_returnsEmptyWhenClaimMissing() {
		assertThat(jwtService.extractRoles(jwtService.generateToken(sampleUser))).isInstanceOf(Set.class);
	}
}
