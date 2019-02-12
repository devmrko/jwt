package jwt.hello;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

	@Autowired
	private JwtEntryPoint jwtEntryPoint;

	@Autowired
	private JwtUserDetailService jwtUserDetailService;

	@Autowired
	JwtProvider jwtProvider;
	
	@Value("${jwt.testuser.name}")
	private String username;
	
	@Value("${jwt.testuser.pass}")
	private String password;

	@Value("${jwt.testuser.role}")
	private String role;
	
	@Bean
	public JwtFilter authenticationTokenFilterBean() throws Exception {
		return new JwtFilter(jwtProvider);
	}
	
	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		
		JwtFilter customFilter = new JwtFilter(jwtProvider);
		httpSecurity.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);

		
		httpSecurity
        // we don't need CSRF because our token is invulnerable
        .csrf().disable()
        
        .exceptionHandling().authenticationEntryPoint(jwtEntryPoint).and()
        
        // don't create session
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        
        .authorizeRequests()
        // Un-secure specific requests(log-in, sign-up, and etc)
        .antMatchers("/rest/auth/getAccessKey").permitAll();
        
        //.anyRequest().authenticated();
        
		
		// 
		// httpSecurity.addFilterAfter(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

		// disable page caching
		/**
        httpSecurity
            .headers()
            .frameOptions().sameOrigin()  // required to set for H2 else H2 Console will be blank.
            .cacheControl();
		**/
		
//		httpSecurity.cors().and().csrf().disable().authorizeRequests().antMatchers("/rest/auth/**").permitAll().anyRequest()
//				.authenticated()
//				.and().exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and().sessionManagement()
//				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		
		// http.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
		
		// httpSecurity.add(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
		
		/**
		http.cors().and().csrf().disable().authorizeRequests().antMatchers("/rest/auth/**").permitAll().anyRequest()
				.hasAnyAuthority("ROLE_TOPAS_ADMIN", "ROLE_TOPAS_USER", "ROLE_AGENT_ADMIN", "ROLE_AGENT_USER",
						"HIST_ADMIN")
				.and().exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
		**/
		
		// 필요한지 체크
		// http.headers().cacheControl();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser(username).password(encoder().encode(password)).roles(role);
	}
	
	@Override
	 public void configure(WebSecurity web) throws Exception {
		 
		 String authenticationPath = "/rest/auth/getAccessKey";
		 
		 // AuthenticationTokenFilter will ignore the below paths
		 web
           .ignoring()
           .antMatchers(
           	HttpMethod.GET,
           	authenticationPath
           )

           // allow anonymous resource requests
           .and()
           .ignoring()
           .antMatchers(
           	HttpMethod.GET,
           	"/",
           	"/*.html",
           	"/favicon.ico",
           	"/**/*.html",
           	"/**/*.css",
           	"/**/*.js"
           );

	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		logger.info("### ### ### WebSecurityConfig - corsConfigurationSource");

		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "OPTIONS", "DELETE", "PUT", "PATCH"));
		configuration.setAllowedHeaders(
				Arrays.asList("X-Requested-With", "Origin", "Content-Type", "Accept", "X-XSRF-TOKEN", "x-access-token",
						"x-access-refresh", "Content-Type", "x-auth-token", "x-requested-with", "x-xsrf-token"));
		configuration.setAllowCredentials(true);
		configuration.setMaxAge(3600L);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	// to prevent Spring boot auto-configuration, and it has to be here
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Autowired
	public void configureUserDetails(AuthenticationManagerBuilder auth) throws Exception {
		// auth.userDetailsService(jwtUserDetailService).passwordEncoder(encoder());
		auth.userDetailsService(jwtUserDetailService);
	}

	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

}
