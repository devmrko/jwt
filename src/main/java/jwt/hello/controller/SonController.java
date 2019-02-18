package jwt.hello.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;

import jwt.hello.mapper.JwtMapper;

@RestController
public class SonController {
	
	@Autowired
	JwtMapper jwtMapper;
	
	@RequestMapping(method=RequestMethod.GET, path="/menu")
	public String selectMenu() {
		Gson gson = new Gson();
		String result = gson.toJson(jwtMapper.selectMenu(), List.class);
		return result;
	}
	
}
