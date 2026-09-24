package common_login.module.config;

import java.util.EnumSet;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import common_login.module.domain.Role;
import common_login.module.domain.User;
import common_login.module.repository.UserRepository;

@Component
public class DataInitializer implements ApplicationRunner {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public void run(ApplicationArguments args) {
		createIfAbsent("admin", "admin@common-login.local", "Admin@12345", EnumSet.of(Role.ADMIN, Role.USER));
		createIfAbsent("moderator", "moderator@common-login.local", "Mod@12345", EnumSet.of(Role.MODERATOR, Role.USER));
		createIfAbsent("user", "user@common-login.local", "User@12345", EnumSet.of(Role.USER));
	}

	private void createIfAbsent(String username, String email, String rawPassword, EnumSet<Role> roles) {
		if (userRepository.existsByUsername(username)) {
			return;
		}
		User user = new User();
		user.setUsername(username);
		user.setEmail(email);
		user.setPassword(passwordEncoder.encode(rawPassword));
		user.setRoles(roles);
		userRepository.save(user);
	}
}
