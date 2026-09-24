package common_login.module.dto;

import java.util.Set;

import common_login.module.domain.Role;

public record AuthResponse(
		String accessToken,
		String tokenType,
		Long expiresInMs,
		Long userId,
		String username,
		String email,
		Set<Role> roles) {

	public static AuthResponse of(String token, Long expiresInMs, Long userId, String username, String email,
			Set<Role> roles) {
		return new AuthResponse(token, "Bearer", expiresInMs, userId, username, email, roles);
	}
}
