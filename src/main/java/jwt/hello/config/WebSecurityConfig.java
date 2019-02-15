package jwt.hello.config;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
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

import jwt.hello.exception.JwtEntryPoint;
import jwt.hello.service.JwtProvider;
import jwt.hello.service.JwtUserDetailService;

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
	
	@Bean
	public JwtFilter authenticationTokenFilterBean() throws Exception {
		return new JwtFilter(jwtProvider);
	}
	
	@Override
	@Order(1)
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		
		// add filter to verify JWT token
		httpSecurity.addFilterBefore(new JwtFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class);

		httpSecurity
				// we don't need CSRF because our token is invulnerable
				.csrf().disable()

				.exceptionHandling().authenticationEntryPoint(jwtEntryPoint).and()

				// don't create session
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

				.authorizeRequests()
				// Un-secure specific requests(log-in, sign-up, and etc)
				.antMatchers("/rest/auth/getAccessKey").permitAll();
        
	}

	@Override
	 public void configure(WebSecurity web) throws Exception {
		 
		String authenticationPath = "/rest/auth/getAccessKey";
		// AuthenticationTokenFilter will ignore the below paths
		web.ignoring().antMatchers(HttpMethod.OPTIONS, "/**").and().ignoring()
				.antMatchers(HttpMethod.GET, authenticationPath)

				// allow anonymous resource requests
				.and().ignoring()
				.antMatchers(HttpMethod.GET, "/", "/*.html", "/favicon.ico", "/**/*.html", "/**/*.css", "/**/*.js");

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
		// set to use authentication by jwtUserDetailService which is extended by Spring UserDetailsService
		auth.userDetailsService(jwtUserDetailService).passwordEncoder(encoder());
	}
	
	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

}
