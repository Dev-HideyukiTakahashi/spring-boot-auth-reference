# 🛡️ **Referência Spring Security**

## 🚀 **Adicionando Spring Security ao Projeto**
## SPRING 3.1.0 ~ 3.2.5

### **Dependências necessárias**

Adicione as dependências no arquivo `pom.xml`:

```xml
<!-- Dependência principal do Spring Security -->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!-- Dependência para testes de segurança -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
</dependency>
```

### **Liberando Endpoints Provisoriamente**

Caso queira liberar provisoriamente todos os endpoints sem autenticação, configure a segurança com a seguinte classe:

```java
@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable());  // Desativa o CSRF
    http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());  // Permite todas as requisições
    return http.build();
  }
}
```

---

## 📋 **Checklist Spring Security**

![](/resources/spring-security-model.png)


### **loadUserByUsername**

```java
  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    List<UserDetailsProjection> list = userRepository.searchUserAndRolesByEmail(username);
    if (list.isEmpty())
      throw new UsernameNotFoundException("User not found!");

    User user = new User();
    user.setEmail(username);
    user.setPassword(list.get(0).getPassword());
    list.forEach(role -> user.addRole(new Role(role.getRoleId(), role.getAuthority())));

    return user;
  }
```

### **Alteração na entidade User para facilitar acesso**

```java
  public void addRole(Role role){
    roles.add(role);
  }

  public boolean hasRole(String roleName) {
    for (Role r : roles) {
      if (roleName.equals(r.getAuthority()))
        return true;
    }
    return false;
  }
```

### **UserDetailsProjection**

Interface para definir os dados de um usuário.

```java
public interface UserDetailsProjection {
  String getUsername();
  String getPassword();
  Long getRoleId();
  String getAuthority();
}
```

### **Consulta no `UserRepository`**

Consulta para ser utilizada no `userService` no método `loadUserByUsername(String username)`:
* Obs: dessa maneira evitamos o `Fetch.EAGER` para trazer os `Roles` na busca de `User`, mantendo mais controle
* Essa consulta substitui o `findByEmail` tradicional `Fetch.EAGER` no entidade `User`.

```java
@Query(nativeQuery = true, value = """
  SELECT tb_user.email AS username, tb_user.password, tb_role.id AS roleId, tb_role.authority
  FROM tb_user
  INNER JOIN tb_user_role ON tb_user.id = tb_user_role.user_id
  INNER JOIN tb_role ON tb_role.id = tb_user_role.role_id
  WHERE tb_user.email = :email
""")
List<UserDetailsProjection> searchUserAndRolesByEmail(String email);
```

### **Filtro de Segurança para o H2 (para testes)**

Para liberar o console H2 no perfil de teste, adicione o seguinte filtro:

```java
@Bean
@Profile("test")
@Order(1)
public SecurityFilterChain h2SecurityFilterChain(HttpSecurity http) throws Exception {
  http.securityMatcher(PathRequest.toH2Console())
      .csrf(csrf -> csrf.disable())
      .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
  return http.build();
}
```

### **Liberar todos endpoints para testes (Spring Boot 3.1+)**

```java
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

## 🔑 **Checklist OAuth2 JWT (Password Grant)**

- Oauth 2 com JWT
  - no repositório do bootcamp
  - copiar o arquivo AuthorizationServerConfig e ResourceServerConfig
  - copiar a pasta customgrant

### **Configuração de Valores**

No arquivo `application.properties` ou `application.yml`, adicione as configurações necessárias:

```properties
spring.profiles.active=${APP_PROFILE:test}

security.client-id=${CLIENT_ID:myclientid}
security.client-secret=${CLIENT_SECRET:myclientsecret}
security.jwt.duration=${JWT_DURATION:86400}

cors.origins=${CORS_ORIGINS:http://localhost:3000,http://localhost:5173}

spring.jpa.open-in-view=false
```

### **Dependências Necessárias**

Adicione as dependências para o OAuth2:

```xml
<!-- Dependência para o servidor de autorização OAuth2 -->
<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-oauth2-authorization-server</artifactId>
</dependency>

<!-- Dependência para o servidor de recursos OAuth2 -->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

### **Controle de Acesso por Perfil e Rota**

Use anotações como `@PreAuthorize` para restringir o acesso a determinadas rotas:

```java
// Exemplo de acesso restrito a usuários com a role 'ROLE_ADMIN'
@PreAuthorize("hasRole('ROLE_ADMIN')")

// Exemplo de acesso para usuários com roles 'ROLE_ADMIN' ou 'ROLE_OPERATOR'
@PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_OPERATOR')")
```

---

## 🔐 Métodos para Acessar o Usuário Autenticado

Código para acessar o usuário autenticado via JWT e retornar os dados do usuário logado:

* Service

```java

protected User authenticated() {
  try {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    Jwt jwtPrincipal = (Jwt) authentication.getPrincipal();

  // o getClaim() esta na classe AuthorizationServerConfig
  // no metodo tokenCustomizer() podemos incluir outros 'claims'
    String username = jwtPrincipal.getClaim("username");

    return userRepository.findByEmail(username).get();
  } catch (Exception e) {
    throw new UsernameNotFoundException("Invalid user");
  }
}

// para ser chamado no controller
@Transactional(readOnly = true)
public UserDTO getLoggedUser() {
  User user = authenticated();
  return new UserDTO(user);
}
```
---
## 🔒 Criptografar Senha ao Salvar um 'User'

* Na classe de configuração:

```java
@Bean
public BCryptPasswordEncoder passwordEncoder(){
  return new BCryptPasswordEncoder();
}
```

* Exemplo na classe service:

```java
public UserDTO save(UserInsertDTO dto) {
  User entity = new User();
  copyDtoToEntity(dto, entity);
  entity = userRepository.save(entity);
  return modelMapper.map(entity, UserDTO.class);
}

// método para reaproveitar código, já que podemos ter um UserUpdateDTO também.
private void copyDtoToEntity(UserDTO dto, User entity, String password) {
  entity.getRoles().clear();
  modelMapper.map(dto, entity);
  for (RoleDTO roleDTO : dto.getRoles()) {
    Role role = roleRepository.getReferenceById(roleDTO.getId());
    entity.getRoles().add(role);
  }
  // Criptografando a senha
  entity.setPassword(passwordEncoder.encode(password));
}
```
---
## 🔥 Script para automatizar token no Postman

```javascript
if (responseCode.code >= 200 && responseCode.code < 300) {
   var json = JSON.parse(responseBody);
   postman.setEnvironmentVariable('token', json.access_token);
} 
```
