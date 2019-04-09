package jwt.hello.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

import jwt.hello.exception.JwtEntryPoint;
import jwt.hello.service.JwtProvider;
import jwt.hello.service.JwtUserDetailService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

	@Value("${jwt.insecure.urlPattern}")
	private String INSECURE_URL_PATTERN;

	@Value("${jwt.accessToken.name}")
	private String ACCESS_TOKEN_NAME;	
	
	@Autowired
	private JwtEntryPoint jwtEntryPoint;

	@Autowired
	private JwtUserDetailService jwtUserDetailService;

	@Autowired
	JwtProvider jwtProvider;
	
	@Bean
	public JwtFilter authenticationTokenFilterBean() throws Exception {
		return new JwtFilter(jwtProvider, ACCESS_TOKEN_NAME, INSECURE_URL_PATTERN);
	}
	
	// to inject @Value annotation in custom filter class
	@Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }
	
	@Override
	@Order(1)
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		
		// add filter to verify JWT token
		httpSecurity.addFilterBefore(new JwtFilter(jwtProvider, ACCESS_TOKEN_NAME, INSECURE_URL_PATTERN), UsernamePasswordAuthenticationFilter.class);

		httpSecurity//.cors().and()
				// we don't need CSRF because our token is invulnerable, and cors
				.cors().and().csrf().disable()
				
				.exceptionHandling().authenticationEntryPoint(jwtEntryPoint).and()

				// don't create session
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

				.authorizeRequests()
				// Un-secure specific requests(log-in, sign-up, and etc)
				.antMatchers("/**").permitAll();
        
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
