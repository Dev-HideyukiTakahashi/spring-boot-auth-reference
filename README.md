# Spring Security Reference

---

### Adicionando Spring Security ao projeto

- Dependências Spring Security:

```
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
</dependency>
```

- Liberando provisoriamente os endpoints

```
  @Configuration
  public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
      http.csrf(csrf -> csrf.disable());
      http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
      return http.build();
    }
  }

```

---

#### Checklist do Spring Security

![](/resources/spring-security-model.png)

- UserDetailsProjection.java

```
public interface UserDetailsProjection {

	String getUsername();
	String getPassword();
	Long getRoleId();
	String getAuthority();
}

```

- Consulta no UserRepository
  - Para ser utilizado no userService no `loadUserByUsername(String username)`

```
@Query(nativeQuery = true, value = """
			SELECT tb_user.email AS username, tb_user.password, tb_role.id AS roleId, tb_role.authority
			FROM tb_user
			INNER JOIN tb_user_role ON tb_user.id = tb_user_role.user_id
			INNER JOIN tb_role ON tb_role.id = tb_user_role.role_id
			WHERE tb_user.email = :email
		""")
List<UserDetailsProjection> searchUserAndRolesByEmail(String email);
```

- Filtro do H2 para Spring Security

```
	@Bean
	@Profile("test")
	@Order(1)
	public SecurityFilterChain h2SecurityFilterChain(HttpSecurity http) throws Exception {

		http.securityMatcher(PathRequest.toH2Console()).csrf(csrf -> csrf.disable())
				.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
		return http.build();
	}
```

---

#### Checklist OAuth2 JWT password grant

- Valores de configuração

```
security.client-id=${CLIENT_ID:myclientid}
security.client-secret=${CLIENT_SECRET:myclientsecret}

security.jwt.duration=${JWT_DURATION:86400}

cors.origins=${CORS_ORIGINS:http://localhost:3000,http://localhost:5173}
```

- Dependências

```
<dependency>
	<groupId>org.springframework.security</groupId>
	<artifactId>spring-security-oauth2-authorization-server</artifactId>
</dependency>

<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

- Controle de acesso por perfil e rota exemplos

```
  @PreAuthorize("hasRole('ROLE_ADMIN')")

  @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_OPERATOR')")
```
