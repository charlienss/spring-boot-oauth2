#### 1.OAuth 2.0简介

OAuth 2.0提供者机制负责公开OAuth 2.0受保护的资源。该配置包括建立可独立或代表用户访问其受保护资源的OAuth 2.0客户端。提供者通过管理和验证用于访问受保护资源的OAuth 2.0令牌来实现。在适用的情况下，提供商还必须提供用户界面，以确认客户端可以被授权访问受保护资源（即确认页面）。

#### 2.OAuth 2.0的四种授权模式

OAuth 2.0常见的有如下四种授权模式,(主要参考自 [阮一峰 OAuth 2.0 的四种方式](http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html)):

- 授权码（authorization code）方式，指的是第三方应用先申请一个授权码，然后再用该码获取令牌.
- 隐藏式,有些 Web 应用是纯前端应用，没有后端。这时就不能用上面的方式了，必须将令牌储存在前端。RFC 6749 就规定了第二种方式，允许直接向前端颁发令牌。这种方式没有授权码这个中间步骤，所以称为（授权码）"隐藏式"（implicit).
- 密码式,如果你高度信任某个应用，RFC 6749 也允许用户把用户名和密码，直接告诉该应用。该应用就使用你的密码，申请令牌，这种方式称为"密码式"（password).
- 凭证式,最后一种方式是凭证式（client credentials），适用于没有前端的命令行应用，即在命令行下请求令牌.

#### 3.使用授权码模式获得JWTtoken令牌Demo项目演示

```java
client_id: demo-client
client_secret: demo-secret (数据表中需要加密)
    
// 登录页访问地址
http://localhost:8080/login
用户名: admin
密码:   123456

// 资源页访问地址
http://localhost:8081/oauth2-server/login    
    
// 授权访问地址    
http://localhost:8080/oauth/authorize?client_id=demo-client&response_type=code&redirect_uri=http://localhost:8081/oauth2-server/login    
```

Html演示页面地址为:http://localhost:8081/oauth2-server/index,授权访问效果如下,授权后会返回相应的token:

![dSV8r8.gif](https://s1.ax1x.com/2020/08/13/dSV8r8.gif)

#### 4.项目结构以及相关代码配置

项目结构如下:

[![ax9FIK.png](https://s1.ax1x.com/2020/08/12/ax9FIK.png)](https://imgchr.com/i/ax9FIK)

**建表语句:**

```java
CREATE TABLE `oauth_client_details`  (
  `client_id` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `resource_ids` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `client_secret` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `scope` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `authorized_grant_types` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `web_server_redirect_uri` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `authorities` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `access_token_validity` int(11) NULL DEFAULT NULL,
  `refresh_token_validity` int(11) NULL DEFAULT NULL,
  `additional_information` varchar(4096) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `autoapprove` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  PRIMARY KEY (`client_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

INSERT INTO `oauth_client_details` VALUES ('demo-client', NULL, '$2a$10$jr6DMjq2pRS1pa8vGvgdUewJTLXyHazOIgG5OrotSVhqhTgoCx1m.', 'all', 'authorization_code,refresh_token', 'http://localhost:8081/oauth2-server/login', NULL, 3600, 36000, NULL, '1');
```

**pom依赖:**

```java
 <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
            <version>2.1.3.RELEASE</version>
        </dependency>

        <!-- ################## Lombok  ################## -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <version>1.18.0</version>
        </dependency>

        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-jdbc</artifactId>
        </dependency>

        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.49</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

```



**security-web:** 用于用户的认证,根据用户的用户名和密码进行认证并用于获得授权码和获取JWT token的服务,主要配置如下:

GetSecret (获取Header以及加密后的密码):

```java
public class GetSecret {

    private static final String APP_KEY = "demo-client";
    private static final String SECRET_KEY = "demo-secret";


    public static void main(String[] args){
        System.out.println("secret: "+new BCryptPasswordEncoder().encode("demo-secret"));

        System.out.println("getHeader: "+getHeader());

    }

    /**
     * 构造Basic Auth认证头信息
     *
     * @return
     */
    private static String getHeader() {
        String auth = APP_KEY + ":" + SECRET_KEY;
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(Charset.forName("US-ASCII")));
        String authHeader = "Basic " + new String(encodedAuth);
        return authHeader;
    }

}
```

WebSecurityConfig

```java
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * 允许匿名访问所有接口 主要是 oauth 接口
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .and()
                .authorizeRequests()
                .antMatchers("/**").permitAll();
    }
}
```

OAuth2Config

```java
@Configuration
@EnableAuthorizationServer
public class OAuth2Config extends AuthorizationServerConfigurerAdapter {


    @Autowired
    @Qualifier("demoUserDetailsService")
    public UserDetailsService demoUserDetailsService;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Autowired
    private TokenStore jwtTokenStore;

    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;

    @Autowired
    private TokenEnhancer jwtTokenEnhancer;

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        /**
         * jwt 增强模式
         */
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> enhancerList = new ArrayList<>();
        enhancerList.add(jwtTokenEnhancer);
        enhancerList.add(jwtAccessTokenConverter);
        enhancerChain.setTokenEnhancers(enhancerList);
        endpoints.tokenStore(jwtTokenStore)
                .userDetailsService(demoUserDetailsService)
                /**
                 * 支持 password 模式
                 */
                .authenticationManager(authenticationManager)
                .tokenEnhancer(enhancerChain)
                .accessTokenConverter(jwtAccessTokenConverter);


    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients();
    }
}
```

**oauth2-server:** 主要用于授权认证后的资源访问,使用的是授权码授权模式(这也是最常见的Oauth2.0的模式),主要资源配置如下:

```java
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {


    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
        accessTokenConverter.setSigningKey("demo");
        accessTokenConverter.setVerifierKey("demo");
        return accessTokenConverter;
    }

    @Autowired
    private TokenStore jwtTokenStore;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenStore(jwtTokenStore);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/login").permitAll();
    }
}

```

#### 5.GitHub项目地址:

```java
https://github.com/fengcharly/spring-boot-oauth2
```