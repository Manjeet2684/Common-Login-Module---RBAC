package common_login.module.controller;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;
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

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerIntegrationTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JsonMapper jsonMapper;

	@Test
	void register_login_and_me_flow() throws Exception {
		String registerBody = """
				{
				  "username": "alice",
				  "email": "alice@example.com",
				  "password": "Password1!"
				}
				""";

		mockMvc.perform(post("/api/auth/register")
						.contentType(MediaType.APPLICATION_JSON)
						.content(registerBody))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.accessToken", notNullValue()))
				.andExpect(jsonPath("$.username").value("alice"))
				.andExpect(jsonPath("$.roles", hasItem("USER")));

		String loginBody = """
				{
				  "username": "alice",
				  "password": "Password1!"
				}
				""";

		MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content(loginBody))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.tokenType").value("Bearer"))
				.andReturn();

		String token = jsonMapper.readTree(loginResult.getResponse().getContentAsString())
				.get("accessToken")
				.asString();

		mockMvc.perform(get("/api/auth/me")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.username").value("alice"))
				.andExpect(jsonPath("$.email").value("alice@example.com"));
	}

	@Test
	void register_rejectsInvalidPayload() throws Exception {
		String body = """
				{
				  "username": "ab",
				  "email": "not-an-email",
				  "password": "short"
				}
				""";

		mockMvc.perform(post("/api/auth/register")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("Validation Failed"))
				.andExpect(jsonPath("$.details", notNullValue()));
	}

	@Test
	void login_rejectsBadCredentials() throws Exception {
		String body = """
				{
				  "username": "admin",
				  "password": "definitely-wrong"
				}
				""";

		mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.message", containsString("Invalid")));
	}

	@Test
	void me_requiresAuthentication() throws Exception {
		mockMvc.perform(get("/api/auth/me"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void seededAdmin_canLogin() throws Exception {
		String body = """
				{
				  "username": "admin",
				  "password": "Admin@12345"
				}
				""";

		MvcResult result = mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body))
				.andExpect(status().isOk())
				.andReturn();

		JsonNode json = jsonMapper.readTree(result.getResponse().getContentAsString());
		assert json.get("accessToken").asString().length() > 20;
	}
}
