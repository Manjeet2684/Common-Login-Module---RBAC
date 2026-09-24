package common_login.module.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import tools.jackson.databind.json.JsonMapper;

@SpringBootTest
@AutoConfigureMockMvc
class RoleBasedAccessIntegrationTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JsonMapper jsonMapper;

	@Test
	void admin_canAccessAdminAndModeratorEndpoints() throws Exception {
		String token = login("admin", "Admin@12345");

		mockMvc.perform(get("/api/admin/dashboard")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.scope").value("ADMIN"));

		mockMvc.perform(get("/api/moderator/reports")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.scope").value("MODERATOR_OR_ADMIN"));

		mockMvc.perform(get("/api/users")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isOk());
	}

	@Test
	void moderator_canAccessReportsButNotAdminDashboard() throws Exception {
		String token = login("moderator", "Mod@12345");

		mockMvc.perform(get("/api/moderator/reports")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isOk());

		mockMvc.perform(get("/api/admin/dashboard")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden());

		mockMvc.perform(get("/api/users")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden());
	}

	@Test
	void user_cannotAccessPrivilegedEndpoints() throws Exception {
		String token = login("user", "User@12345");

		mockMvc.perform(get("/api/admin/dashboard")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden());

		mockMvc.perform(get("/api/moderator/reports")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden());

		mockMvc.perform(get("/api/users")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden());
	}

	@Test
	void user_canReadOwnProfileById() throws Exception {
		String token = login("user", "User@12345");

		MvcResult meResult = mockMvc.perform(get("/api/auth/me")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isOk())
				.andReturn();

		long userId = jsonMapper.readTree(meResult.getResponse().getContentAsString()).get("id").asLong();

		mockMvc.perform(get("/api/users/" + userId)
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.username").value("user"));
	}

	@Test
	void user_cannotReadAnotherUsersProfile() throws Exception {
		String userToken = login("user", "User@12345");
		String adminToken = login("admin", "Admin@12345");

		MvcResult adminMe = mockMvc.perform(get("/api/auth/me")
						.header("Authorization", "Bearer " + adminToken))
				.andExpect(status().isOk())
				.andReturn();

		long adminId = jsonMapper.readTree(adminMe.getResponse().getContentAsString()).get("id").asLong();

		mockMvc.perform(get("/api/users/" + adminId)
						.header("Authorization", "Bearer " + userToken))
				.andExpect(status().isForbidden());
	}

	private String login(String username, String password) throws Exception {
		String body = """
				{
				  "username": "%s",
				  "password": "%s"
				}
				""".formatted(username, password);

		MvcResult result = mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body))
				.andExpect(status().isOk())
				.andReturn();

		return jsonMapper.readTree(result.getResponse().getContentAsString())
				.get("accessToken")
				.asString();
	}
}
