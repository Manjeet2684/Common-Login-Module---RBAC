package common_login.module.service;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import common_login.module.domain.Role;
import common_login.module.domain.User;
import common_login.module.dto.AuthResponse;
import common_login.module.dto.LoginRequest;
import common_login.module.dto.RegisterRequest;
import common_login.module.dto.UserResponse;
import common_login.module.exception.BadRequestException;
import common_login.module.exception.ResourceNotFoundException;
import common_login.module.repository.UserRepository;
import common_login.module.security.JwtService;

@Service
public class AuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;

	public AuthService(
			UserRepository userRepository,
			PasswordEncoder passwordEncoder,
			JwtService jwtService,
			AuthenticationManager authenticationManager) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.authenticationManager = authenticationManager;
	}

	@Transactional
	public AuthResponse register(RegisterRequest request) {
		if (userRepository.existsByUsername(request.username())) {
			throw new BadRequestException("Username is already taken");
		}
		if (userRepository.existsByEmail(request.email())) {
			throw new BadRequestException("Email is already registered");
		}

		User user = new User();
		user.setUsername(request.username());
		user.setEmail(request.email());
		user.setPassword(passwordEncoder.encode(request.password()));
		user.setRoles(resolveRoles(request.roles()));

		User saved = userRepository.save(user);
		String token = jwtService.generateToken(saved);
		return AuthResponse.of(
				token,
				jwtService.getExpirationMs(),
				saved.getId(),
				saved.getUsername(),
				saved.getEmail(),
				saved.getRoles());
	}

	@Transactional(readOnly = true)
	public AuthResponse login(LoginRequest request) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.username(), request.password()));

		User user = (User) authentication.getPrincipal();
		String token = jwtService.generateToken(user);
		return AuthResponse.of(
				token,
				jwtService.getExpirationMs(),
				user.getId(),
				user.getUsername(),
				user.getEmail(),
				user.getRoles());
	}

	@Transactional(readOnly = true)
	public UserResponse getCurrentUser(String username) {
		return userRepository.findByUsername(username)
				.map(UserResponse::from)
				.orElseThrow(() -> new ResourceNotFoundException("User not found"));
	}

	@Transactional(readOnly = true)
	public List<UserResponse> getAllUsers() {
		return userRepository.findAll().stream().map(UserResponse::from).toList();
	}

	@Transactional(readOnly = true)
	public UserResponse getUserById(Long id) {
		return userRepository.findById(id)
				.map(UserResponse::from)
				.orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
	}

	private Set<Role> resolveRoles(Set<Role> requestedRoles) {
		if (requestedRoles == null || requestedRoles.isEmpty()) {
			return EnumSet.of(Role.USER);
		}
		return EnumSet.copyOf(requestedRoles);
	}
}
