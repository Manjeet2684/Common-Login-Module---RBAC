package common_login.module.exception;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import common_login.module.dto.ApiError;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
		List<String> details = ex.getBindingResult().getFieldErrors().stream()
				.map(this::formatFieldError)
				.toList();
		return ResponseEntity.badRequest().body(
				ApiError.of(HttpStatus.BAD_REQUEST.value(), "Validation Failed", "Request validation failed",
						request.getRequestURI(), details));
	}

	@ExceptionHandler(BadRequestException.class)
	public ResponseEntity<ApiError> handleBadRequest(BadRequestException ex, HttpServletRequest request) {
		return ResponseEntity.badRequest().body(
				ApiError.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", ex.getMessage(),
						request.getRequestURI(), null));
	}

	@ExceptionHandler({ BadCredentialsException.class, UsernameNotFoundException.class })
	public ResponseEntity<ApiError> handleAuthFailures(RuntimeException ex, HttpServletRequest request) {
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
				ApiError.of(HttpStatus.UNAUTHORIZED.value(), "Unauthorized", "Invalid username or password",
						request.getRequestURI(), null));
	}

	@ExceptionHandler({ AccessDeniedException.class, AuthorizationDeniedException.class })
	public ResponseEntity<ApiError> handleAccessDenied(RuntimeException ex, HttpServletRequest request) {
		return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
				ApiError.of(HttpStatus.FORBIDDEN.value(), "Forbidden",
						"You do not have permission to access this resource",
						request.getRequestURI(), null));
	}

	@ExceptionHandler(ResourceNotFoundException.class)
	public ResponseEntity<ApiError> handleNotFound(ResourceNotFoundException ex, HttpServletRequest request) {
		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
				ApiError.of(HttpStatus.NOT_FOUND.value(), "Not Found", ex.getMessage(),
						request.getRequestURI(), null));
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiError> handleGeneric(Exception ex, HttpServletRequest request) {
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
				ApiError.of(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal Server Error",
						"An unexpected error occurred", request.getRequestURI(), null));
	}

	private String formatFieldError(FieldError error) {
		return error.getField() + ": " + error.getDefaultMessage();
	}
}
