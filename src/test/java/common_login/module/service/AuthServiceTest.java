package common_login.module.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.EnumSet;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.transaction.annotation.Transactional;

import common_login.module.domain.Role;
import common_login.module.dto.AuthResponse;
import common_login.module.dto.LoginRequest;
import common_login.module.dto.RegisterRequest;
import common_login.module.dto.UserResponse;
import common_login.module.exception.BadRequestException;
import common_login.module.exception.ResourceNotFoundException;

@SpringBootTest
@Transactional
class AuthServiceTest {

	@Autowired
	private AuthService authService;

	@BeforeEach
	void registerBaselineUser() {
		authService.register(new RegisterRequest(
				"serviceuser",
				"serviceuser@example.com",
				"Password1!",
				EnumSet.of(Role.USER)));
	}

	@Test
	void register_createsUserWithDefaultRole() {
		AuthResponse response = authService.register(new RegisterRequest(
				"newbie",
				"newbie@example.com",
				"Password1!",
				null));

		assertThat(response.username()).isEqualTo("newbie");
		assertThat(response.roles()).containsExactly(Role.USER);
		assertThat(response.accessToken()).isNotBlank();
		assertThat(response.tokenType()).isEqualTo("Bearer");
	}

	@Test
	void register_rejectsDuplicateUsername() {
		assertThatThrownBy(() -> authService.register(new RegisterRequest(
				"serviceuser",
				"other@example.com",
				"Password1!",
				Set.of(Role.USER))))
				.isInstanceOf(BadRequestException.class)
				.hasMessageContaining("Username");
	}

	@Test
	void login_returnsTokenForValidCredentials() {
		AuthResponse response = authService.login(new LoginRequest("serviceuser", "Password1!"));

		assertThat(response.accessToken()).isNotBlank();
		assertThat(response.username()).isEqualTo("serviceuser");
	}

	@Test
	void login_rejectsInvalidPassword() {
		assertThatThrownBy(() -> authService.login(new LoginRequest("serviceuser", "wrong-password")))
				.isInstanceOf(BadCredentialsException.class);
	}

	@Test
	void getUserById_throwsWhenMissing() {
		assertThatThrownBy(() -> authService.getUserById(999_999L))
				.isInstanceOf(ResourceNotFoundException.class);
	}

	@Test
	void getCurrentUser_returnsProfile() {
		UserResponse profile = authService.getCurrentUser("serviceuser");

		assertThat(profile.email()).isEqualTo("serviceuser@example.com");
		assertThat(profile.roles()).contains(Role.USER);
	}
}
