package common_login.module.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import common_login.module.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByUsername(String username);

	boolean existsByUsername(String username);

	boolean existsByEmail(String email);
}
