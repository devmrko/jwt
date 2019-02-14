package jwt.hello.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import jwt.hello.service.JwtProvider;
import jwt.hello.vo.JwtKeys;
import jwt.hello.vo.JwtTokenDetail;
import jwt.hello.vo.JwtUser;

@RestController
public class JwtController {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtController.class);

	@Autowired
	JwtProvider jwtProvider;

	@RequestMapping(method = RequestMethod.POST, path="/rest/auth/login")
	public JwtTokenDetail getAccessKeyByLoginRequest(@RequestBody JwtUser jwtUser) {
		logger.info("### ### ### JwtController - getAccessKeyByLoginRequest");
		JwtTokenDetail jwtTokenDetail = jwtProvider.getJwtTokens(jwtUser);
		return jwtTokenDetail;
	}

	@RequestMapping(method = RequestMethod.POST, path="/rest/auth/refresh")
	public JwtTokenDetail getAccessKeyByRefreshKey(@RequestBody JwtKeys jwtKeys) throws Exception {
		logger.info("### ### ### JwtController - getAccessKeyByRefreshKey");
		JwtTokenDetail jwtTokenDetail = jwtProvider.getJwtTokenByRefresh(jwtKeys);
		return jwtTokenDetail;
	}
	
}