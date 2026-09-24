package common_login.module.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import common_login.module.domain.User;
import common_login.module.dto.UserResponse;
import common_login.module.exception.BadRequestException;
import common_login.module.service.AuthService;

@RestController
@RequestMapping("/api")
public class UserController {

	private final AuthService authService;

	public UserController(AuthService authService) {
		this.authService = authService;
	}

	@GetMapping("/users")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<List<UserResponse>> listUsers() {
		return ResponseEntity.ok(authService.getAllUsers());
	}

	@GetMapping("/users/{id}")
	@PreAuthorize("hasRole('ADMIN') or #id == principal.id")
	public ResponseEntity<UserResponse> getUser(@PathVariable Long id, @AuthenticationPrincipal User principal) {
		if (principal == null) {
			throw new BadRequestException("Authenticated principal is required");
		}
		return ResponseEntity.ok(authService.getUserById(id));
	}

	@GetMapping("/admin/dashboard")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<Map<String, String>> adminDashboard() {
		return ResponseEntity.ok(Map.of(
				"message", "Welcome to the admin dashboard",
				"scope", "ADMIN"));
	}

	@GetMapping("/moderator/reports")
	@PreAuthorize("hasAnyRole('MODERATOR', 'ADMIN')")
	public ResponseEntity<Map<String, String>> moderatorReports() {
		return ResponseEntity.ok(Map.of(
				"message", "Moderator reports available",
				"scope", "MODERATOR_OR_ADMIN"));
	}
}
