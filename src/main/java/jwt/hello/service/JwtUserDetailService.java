package jwt.hello.service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import jwt.hello.mapper.JwtMapper;
import jwt.hello.vo.JwtUser;

@Service
public class JwtUserDetailService implements UserDetailsService {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtUserDetailService.class);
	
	@Autowired
	JwtProvider jwtProvider;
	
	@Autowired
	JwtMapper jwtMapper;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
	/**
     * <B>History</B>
     * <ul>
     * <li>Date : 2019. 2. 15.
     * <li>Developer : devmrko
     * <li>get user information from database, and create user object. this time input password is going to be encrypted(BCryptPasswordEncoder).
     * </ul>
     *  
     * @param username
     * @return
     */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		logger.debug("### ### ### loadUserByUsername");
		JwtUser jwtUser = jwtMapper.selectUser(username);
		User user = new User(jwtUser.getUsername(), encoder().encode(jwtUser.getPassword()), getAuthority(jwtUser.getUsername()));
		return user;
	}
	

	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>get user roles from database, and convert to SimpleGrantedAuthority set
	     * </ul>
	     *  
	     * @param username
	     * @return
	     */
	private Set<SimpleGrantedAuthority> getAuthority(String username) {
		logger.info("### ### ### getAuthority");
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		String jwtRoles = jwtMapper.selectRoles(username);
		String[] jwtRoleArray = jwtRoles.split(",");
		for(int i = 0; jwtRoleArray.length > i; i++) {
			authorities.add(new SimpleGrantedAuthority(jwtRoleArray[i]));
		}
		return authorities;
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>create UsernamePasswordAuthenticationToken by JwtUser
	     * </ul>
	     *  
	     * @param jwtUser
	     * @return
	     */
	public UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(JwtUser jwtUser) {
		return new UsernamePasswordAuthenticationToken(jwtUser.getUsername(), jwtUser.getPassword(), getAuthority(jwtUser.getUsername()));
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : Joungmin
	     * <li>create UsernamePasswordAuthenticationToken
	     * </ul>
	     *  
	     * @param user
	     * @param credential
	     * @param authorities
	     * @return
	     */
	public UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(User user, String credential, Collection<? extends GrantedAuthority> authorities) {
		return new UsernamePasswordAuthenticationToken(user, credential, authorities);
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>create UsernamePasswordAuthenticationToken without password when create JWT access token by refresh token 
	     * </ul>
	     *  
	     * @param username
	     * @return
	     */
	public UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(String username) {
		return new UsernamePasswordAuthenticationToken(username, "", getAuthority(username));
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>get authentication from JwtUser
	     * </ul>
	     *  
	     * @param jwtUser
	     * @return
	     */
	public Authentication getAuthentication(JwtUser jwtUser) {
		return authenticationManager.authenticate(getUsernamePasswordAuthenticationToken(jwtUser));
	}
	
}
