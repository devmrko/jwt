package jwt.hello.controller;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import jwt.hello.service.JwtProvider;
import jwt.hello.vo.JwtKeys;
import jwt.hello.vo.JwtTokenDetail;
import jwt.hello.vo.JwtUser;

//@CrossOrigin
@RestController
public class JwtController {

	private static final Logger logger = LoggerFactory.getLogger(JwtController.class);

	@Autowired
	JwtProvider jwtProvider;

	@RequestMapping(method = RequestMethod.POST, path = "/rest/auth/login")
	public JwtTokenDetail getAccessKeyByLoginRequest(@RequestBody JwtUser jwtUser, HttpServletRequest request) {
		logger.debug("### ### ### getAccessKeyByLoginRequest");
		JwtTokenDetail jwtTokenDetail = jwtProvider.getJwtTokens(jwtUser, request);
		return jwtTokenDetail;
	}

	@RequestMapping(method = RequestMethod.POST, path = "/rest/auth/refresh")
	public JwtTokenDetail getAccessKeyByRefreshKey(@RequestBody JwtKeys jwtKeys, HttpServletRequest request) throws Exception {
		logger.debug("### ### ### getAccessKeyByRefreshKey");
		JwtTokenDetail jwtTokenDetail = jwtProvider.getJwtTokenByRefresh(jwtKeys, request);
		return jwtTokenDetail;
	}

}