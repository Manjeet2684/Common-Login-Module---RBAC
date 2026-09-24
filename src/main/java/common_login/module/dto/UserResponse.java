package common_login.module.dto;

import java.time.Instant;
import java.util.Set;

import common_login.module.domain.Role;
import common_login.module.domain.User;

public record UserResponse(
		Long id,
		String username,
		String email,
		boolean enabled,
		Set<Role> roles,
		Instant createdAt) {

	public static UserResponse from(User user) {
		return new UserResponse(
				user.getId(),
				user.getUsername(),
				user.getEmail(),
				user.isEnabled(),
				user.getRoles(),
				user.getCreatedAt());
	}
}
